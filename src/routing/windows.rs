use super::RouteAdder;
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex, CreateIpForwardEntry2,
    DeleteIpForwardEntry2, FreeMibTable, GetAdaptersAddresses, GetBestInterface,
    GetBestInterfaceEx, GetIpForwardTable2, GAA_FLAG_INCLUDE_ALL_INTERFACES,
    IP_ADAPTER_ADDRESSES_LH, IP_ADDRESS_PREFIX, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows::Win32::NetworkManagement::Ndis::{IF_MAX_STRING_SIZE, NET_LUID_LH};
use windows::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0,
    MIB_IPPROTO_NETMGMT, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
};

/// Route adder backed by the Windows IP Helper API (iphlpapi.dll).
///
/// Routes are created as static `MIB_IPPROTO_NETMGMT` entries with infinite
/// lifetime, the programmatic equivalent of `route add -p`.
#[derive(Default)]
pub struct WindowsRouteAdder;

impl WindowsRouteAdder {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}

/// Convert an IPv4 address into the network-byte-order `S_addr` value the IP
/// Helper structures expect in memory.
fn ipv4_to_s_addr(addr: Ipv4Addr) -> u32 {
    addr.to_bits().to_be()
}

/// Inverse of [`ipv4_to_s_addr`].
fn s_addr_to_ipv4(s_addr: u32) -> Ipv4Addr {
    Ipv4Addr::from_bits(u32::from_be(s_addr))
}

/// Build a `SOCKADDR_INET` for a destination/prefix field (address zeroed).
fn prefix_sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    match ip {
        IpAddr::V4(_) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 { S_addr: 0 },
                },
                sin_zero: [0; 8],
            },
        },
        IpAddr::V6(_) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: [0; 16] },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            },
        },
    }
}

/// Build a `SOCKADDR_INET` holding a concrete address.
fn address_sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    match ip {
        IpAddr::V4(v4) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: ipv4_to_s_addr(v4),
                    },
                },
                sin_zero: [0; 8],
            },
        },
        IpAddr::V6(v6) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: v6.octets() },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            },
        },
    }
}

/// Extract the address from a `SOCKADDR_INET` returned by the IP Helper API.
fn sockaddr_to_ip(addr: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: si_family shares storage with the variants; reading it first is
    // always defined.
    let family = unsafe { addr.si_family };
    if family == AF_INET {
        // SAFETY: family confirms the IPv4 variant is active.
        let v4 = unsafe { &addr.Ipv4.sin_addr };
        // SAFETY: S_addr covers all four bytes of the S_un union.
        let s_addr = unsafe { v4.S_un.S_addr };
        Some(IpAddr::V4(s_addr_to_ipv4(s_addr)))
    } else if family == AF_INET6 {
        // SAFETY: family confirms the IPv6 variant is active.
        let v6 = unsafe { &addr.Ipv6.sin6_addr };
        // SAFETY: Byte covers all sixteen bytes of the u union.
        let octets = unsafe { v6.u.Byte };
        Some(IpAddr::V6(Ipv6Addr::from(octets)))
    } else {
        None
    }
}

/// Resolve a device name from a Leshy device file to a Windows interface index.
///
/// Accepted forms:
/// - the adapter alias / friendly name shown by `Get-NetAdapter` (for example
///   `AmneziaVPN` or `Wi-Fi 2`), matched case-insensitively;
/// - a bare interface index written as decimal digits.
fn resolve_interface_index(device: &str) -> Result<u32> {
    let trimmed = device.trim();
    if let Ok(index) = trimmed.parse::<u32>() {
        return Ok(index);
    }

    let wide = to_wide_null_terminated(trimmed);
    let mut luid = NET_LUID_LH::default();
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 buffer for the call.
    let err = unsafe { ConvertInterfaceAliasToLuid(PCWSTR(wide.as_ptr()), &mut luid) };
    if err.is_ok() {
        let mut index: u32 = 0;
        // SAFETY: luid was initialized by the successful conversion above.
        let conv = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
        if conv.is_ok() {
            return Ok(index);
        }
    }

    find_interface_index_case_insensitive(trimmed)
        .with_context(|| format!("Interface '{trimmed}' not found"))
}

fn to_wide_null_terminated(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Adapter aliases are case-insensitive on Windows; a direct LUID conversion
/// may still miss odd spellings, so fall back to scanning
/// `GetAdaptersAddresses` and comparing lowercased aliases.
fn find_interface_index_case_insensitive(name: &str) -> Result<u32> {
    let name_lower = name.to_lowercase();
    for (alias, index) in enumerate_adapters(AF_INET)? {
        if alias == name_lower {
            return Ok(index);
        }
    }
    anyhow::bail!("no interface matches '{name}' (case-insensitive)")
}

/// Scan `GetAdaptersAddresses` for (lowercased alias, ifIndex) pairs.
fn enumerate_adapters(family: ADDRESS_FAMILY) -> Result<Vec<(String, u32)>> {
    const FLAGS: u32 = GAA_FLAG_INCLUDE_ALL_INTERFACES.0;
    let flags = windows::Win32::NetworkManagement::IpHelper::GET_ADAPTERS_ADDRESSES_FLAGS(FLAGS);

    let mut size: u32 = 0;
    // SAFETY: passing a null buffer with an out-size is the documented probe.
    let _ = unsafe { GetAdaptersAddresses(family.0 as u32, flags, None, None, &mut size) };
    if size == 0 {
        anyhow::bail!("GetAdaptersAddresses probe failed");
    }

    let mut buffer = vec![0u8; size as usize];
    let head = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
    // SAFETY: `buffer` is at least `size` bytes as required by the API.
    let ret = unsafe { GetAdaptersAddresses(family.0 as u32, flags, None, Some(head), &mut size) };
    check_win32(WIN32_ERROR(ret), "GetAdaptersAddresses")?;

    let mut out = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: cursor points at a linked-list node inside `buffer`.
        let adapter = unsafe { &*cursor };
        if !adapter.FriendlyName.is_null() {
            // FriendlyName is a NUL-terminated UTF-16 string.
            let alias = wide_to_string(adapter.FriendlyName.0, IF_MAX_STRING_SIZE as usize);
            // SAFETY: Anonymous1 is a union; IfIndex is the documented layout
            // of its anonymous struct member.
            let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
            out.push((alias.to_lowercase(), index));
        }
        cursor = adapter.Next;
    }
    Ok(out)
}

fn wide_to_string(ptr: *const u16, max_len: usize) -> String {
    // SAFETY: ptr is NUL-terminated per the IP Helper contract.
    let mut len = 0usize;
    unsafe {
        while len < max_len && *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

fn check_win32(err: WIN32_ERROR, what: &str) -> Result<()> {
    err.ok().map_err(|e| anyhow::anyhow!("{what} failed: {e}"))
}

/// Build a ready-to-install `MIB_IPFORWARD_ROW2`.
fn build_route_row(
    ip: IpAddr,
    prefix_len: u8,
    interface_index: u32,
    next_hop: Option<IpAddr>,
) -> MIB_IPFORWARD_ROW2 {
    MIB_IPFORWARD_ROW2 {
        InterfaceLuid: NET_LUID_LH::default(),
        InterfaceIndex: interface_index,
        DestinationPrefix: IP_ADDRESS_PREFIX {
            Prefix: prefix_sockaddr(ip),
            PrefixLength: prefix_len,
        },
        NextHop: match next_hop {
            Some(gateway) => address_sockaddr(gateway),
            None => prefix_sockaddr(ip),
        },
        // 0xFFFFFFFF = infinite lifetime (`route add -p` semantics).
        ValidLifetime: 0xFFFF_FFFF,
        PreferredLifetime: 0xFFFF_FFFF,
        Metric: 0,
        Protocol: MIB_IPPROTO_NETMGMT,
        SitePrefixLength: 0,
        ..Default::default()
    }
}

/// Find the interface through which the given gateway is reachable.
fn interface_for_gateway(gateway: IpAddr) -> Result<u32> {
    let mut index: u32 = 0;
    match gateway {
        IpAddr::V4(v4) => {
            // GetBestInterface expects the address in network byte order and
            // returns a bare u32 status code.
            let addr = ipv4_to_s_addr(v4);
            // SAFETY: out-pointer is valid for the duration of the call.
            let ret = unsafe { GetBestInterface(addr, &mut index) };
            check_win32(WIN32_ERROR(ret), "GetBestInterface")?;
        }
        IpAddr::V6(v6) => {
            let mut sockaddr = address_sockaddr(IpAddr::V6(v6));
            let sockaddr_ptr = &mut sockaddr as *mut SOCKADDR_INET as *mut SOCKADDR;
            // SAFETY: SOCKADDR_INET and SOCKADDR share the leading
            // address-family layout; the API only reads family + address.
            let ret = unsafe { GetBestInterfaceEx(sockaddr_ptr, &mut index) };
            check_win32(WIN32_ERROR(ret), "GetBestInterfaceEx")?;
        }
    }
    Ok(index)
}

/// Enumerate all forwarding-table entries of `family` and keep the rows whose
/// destination prefix matches `(ip, prefix_len)`.
fn find_route_rows(
    family: ADDRESS_FAMILY,
    ip: IpAddr,
    prefix_len: u8,
) -> Result<Vec<MIB_IPFORWARD_ROW2>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: out-pointer contract of GetIpForwardTable2; the table is freed
    // with FreeMibTable below.
    let err = unsafe { GetIpForwardTable2(family, &mut table) };
    check_win32(err, "GetIpForwardTable2")?;

    let mut matches = Vec::new();
    // SAFETY: table is a valid heap table returned by the API; rows live until
    // FreeMibTable below.
    unsafe {
        let count = (*table).NumEntries as usize;
        let rows = (*table).Table.as_ptr();
        for i in 0..count {
            let row = &*rows.add(i);
            if row.DestinationPrefix.PrefixLength == prefix_len {
                if let Some(dest) = sockaddr_to_ip(&row.DestinationPrefix.Prefix) {
                    if dest == ip {
                        matches.push(*row);
                    }
                }
            }
        }
    }
    // SAFETY: table was allocated by the IP Helper API.
    unsafe { FreeMibTable(table as _) };
    Ok(matches)
}

fn delete_routes(family: ADDRESS_FAMILY, ip: IpAddr, prefix_len: u8) -> Result<()> {
    let rows = find_route_rows(family, ip, prefix_len)?;
    if rows.is_empty() {
        tracing::debug!(ip = %ip, prefix_len = prefix_len, "Route does not exist, nothing to remove");
        return Ok(());
    }
    for row in rows {
        // SAFETY: DeleteIpForwardEntry2 only reads the row.
        let err = unsafe { DeleteIpForwardEntry2(&row) };
        if err.is_ok() || err == ERROR_NOT_FOUND {
            continue;
        }
        anyhow::bail!("DeleteIpForwardEntry2 failed: {err:?}");
    }
    Ok(())
}

fn create_route(row: &mut MIB_IPFORWARD_ROW2, ip: IpAddr, label: &str) -> Result<()> {
    // SAFETY: row is a fully initialized MIB_IPFORWARD_ROW2.
    let err = unsafe { CreateIpForwardEntry2(row) };
    if err.is_ok() || err == ERROR_OBJECT_ALREADY_EXISTS {
        tracing::debug!(ip = %ip, kind = label, "Route added successfully");
        return Ok(());
    }
    tracing::error!(ip = %ip, kind = label, error = ?err, "Failed to add route");
    anyhow::bail!("CreateIpForwardEntry2 failed: {err:?}")
}

#[async_trait]
impl RouteAdder for WindowsRouteAdder {
    async fn add_via_route(&self, ip: IpAddr, prefix_len: u8, gateway: &str) -> Result<()> {
        tracing::info!(ip = %ip, prefix_len = prefix_len, gateway = gateway, "Adding route via gateway");
        let gateway_ip: IpAddr = gateway.parse().context("Failed to parse gateway IP")?;
        let interface_index = interface_for_gateway(gateway_ip)?;
        let mut row = build_route_row(ip, prefix_len, interface_index, Some(gateway_ip));
        create_route(&mut row, ip, "via")
    }

    async fn add_dev_route(&self, ip: IpAddr, prefix_len: u8, device: &str) -> Result<()> {
        tracing::info!(ip = %ip, prefix_len = prefix_len, device = device, "Adding route via device");
        let interface_index = resolve_interface_index(device)?;
        let mut row = build_route_row(ip, prefix_len, interface_index, None);
        create_route(&mut row, ip, "dev")
    }

    async fn remove_route(&self, ip: IpAddr, prefix_len: u8) -> Result<()> {
        tracing::info!(ip = %ip, prefix_len = prefix_len, "Removing route");
        match ip {
            IpAddr::V4(_) => delete_routes(AF_INET, ip, prefix_len),
            IpAddr::V6(_) => delete_routes(AF_INET6, ip, prefix_len),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_s_addr_roundtrip() {
        let addr = Ipv4Addr::new(127, 0, 0, 1);
        assert_eq!(ipv4_to_s_addr(addr), 0x0100_007F);
        assert_eq!(s_addr_to_ipv4(ipv4_to_s_addr(addr)), addr);
    }

    #[test]
    fn prefix_sockaddr_sets_family_only() {
        let v4 = prefix_sockaddr(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
        let family = unsafe { v4.si_family };
        assert_eq!(family, AF_INET);

        let v6 = prefix_sockaddr(IpAddr::V6(Ipv6Addr::LOCALHOST));
        let family = unsafe { v6.si_family };
        assert_eq!(family, AF_INET6);
    }

    #[test]
    fn sockaddr_roundtrip_v4() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 40, 7));
        let sockaddr = address_sockaddr(ip);
        assert_eq!(sockaddr_to_ip(&sockaddr), Some(ip));
    }

    #[test]
    fn sockaddr_roundtrip_v6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x1234));
        let sockaddr = address_sockaddr(ip);
        assert_eq!(sockaddr_to_ip(&sockaddr), Some(ip));
    }

    #[test]
    fn sockaddr_zero_prefix_has_no_address() {
        let sockaddr = prefix_sockaddr(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(
            sockaddr_to_ip(&sockaddr),
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        );
    }

    #[test]
    fn loopback_interface_resolves() {
        // The loopback interface always exists and needs no admin rights.
        let index = resolve_interface_index("Loopback Pseudo-Interface 1").unwrap();
        assert!(index > 0);
    }

    #[test]
    fn interface_index_is_case_insensitive() {
        let index = resolve_interface_index("LOOPBACK PSEUDO-INTERFACE 1").unwrap();
        assert!(index > 0);
    }

    #[test]
    fn missing_interface_is_reported() {
        assert!(resolve_interface_index("no-such-leshy-interface").is_err());
    }
}
