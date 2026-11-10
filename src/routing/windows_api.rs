//! Windows IP Helper route API seam (08D1 §41.3 production contract).
//!
//! `RealWindowsRouteApi` performs the actual IP Helper calls.
//! `FakeWindowsRouteApi` (test builds) provides a deterministic in-memory
//! forwarding table with scripted outcomes. `windows.rs` owns exactly one of
//! these behind `Arc<dyn WindowsRouteApi>` plus one coherent cache, so every
//! kernel read and write goes through this seam.

use super::backend::RouteInvalidation;
use super::model::{
    AddressFamily, ObservedRoute, RouteIntent, RouteKernelIdentity, RouteKey, RoutePrefix,
    RouteTarget,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, HANDLE, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, ConvertInterfaceAliasToLuid, ConvertInterfaceIndexToLuid,
    ConvertInterfaceLuidToAlias, ConvertInterfaceLuidToIndex, CreateIpForwardEntry2,
    DeleteIpForwardEntry2, FreeMibTable, GetAdaptersAddresses, GetBestInterface,
    GetBestInterfaceEx, GetIpForwardTable2, InitializeIpForwardEntry, NotifyRouteChange2,
    GAA_FLAG_INCLUDE_ALL_INTERFACES, IP_ADAPTER_ADDRESSES_LH, IP_ADDRESS_PREFIX,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_NOTIFICATION_TYPE,
};
use windows::Win32::NetworkManagement::Ndis::{IF_MAX_STRING_SIZE, NET_LUID_LH};
use windows::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0,
    MIB_IPPROTO_NETMGMT, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
};

/// The main routing table. Windows has no table selector in the IP Helper API;
/// every row lives in the system forwarding table.
pub(crate) const MAIN_TABLE: u32 = 254;

/// Static `MIB_IPPROTO_NETMGMT` protocol number, as recorded in the identity.
pub(crate) const WINDOWS_PROTOCOL_NETMGMT: u8 = 3;

/// Metric every Leshy-owned static row carries.
pub(crate) const WINDOWS_METRIC: u32 = 0;

/// Exact Windows interface identity. `index` alone is not enough: Windows may
/// reuse an ifIndex for a different adapter (different LUID).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WindowsInterfaceIdentity {
    pub index: u32,
    pub luid: u64,
}

/// A route intent resolved against the live interface state.
///
/// The identity is backend-private: it never enters the cross-platform
/// `RouteIntent`, but it is the exact Windows match proof.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedWindowsRoute {
    pub intent: RouteIntent,
    pub identity: RouteKernelIdentity,
}

/// Result of `WindowsRouteApi::create`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsCreateOutcome {
    /// The API created the row.
    Created,
    /// `CreateIpForwardEntry2` answered ERROR_OBJECT_ALREADY_EXISTS; the
    /// caller must re-read and prove the desired identity before accepting it.
    AlreadyExists,
}

/// Result of `WindowsRouteApi::delete_exact`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowsDeleteOutcome {
    /// The exact recorded row was deleted.
    Deleted,
    /// No live row carried the recorded identity; nothing was touched.
    Absent,
}

/// Injected IP Helper seam.
// async_trait's generated #[must_use] on boxed futures trips this lint on
// newer clippy versions; the futures are always awaited internally.
#[allow(clippy::double_must_use)]
#[async_trait]
pub(crate) trait WindowsRouteApi: Send + Sync {
    /// Resolve a device alias to its exact index + LUID.
    async fn resolve_device(&self, name: &str) -> Result<WindowsInterfaceIdentity>;

    /// Resolve the interface the given gateway is reachable through.
    async fn resolve_gateway_interface(&self, gateway: IpAddr) -> Result<WindowsInterfaceIdentity>;

    /// Enumerate one family of the forwarding table.
    async fn dump_family(&self, family: AddressFamily) -> Result<Vec<ObservedRoute>>;

    /// Create one desired row.
    async fn create(&self, desired: &ResolvedWindowsRoute) -> Result<WindowsCreateOutcome>;

    /// Delete exactly the row carrying `identity`; never a same-prefix sweep.
    async fn delete_exact(
        &self,
        key: &RouteKey,
        identity: &RouteKernelIdentity,
    ) -> Result<WindowsDeleteOutcome>;

    /// Register the route-change notification before the first snapshot.
    fn subscribe(
        &self,
        generation: Arc<AtomicU64>,
        tx: mpsc::UnboundedSender<RouteInvalidation>,
    ) -> Result<Box<dyn WindowsRouteSubscription>>;
}

/// Keeps the kernel notification registration alive for the backend lifetime.
pub(crate) trait WindowsRouteSubscription: Send + Sync {}

fn windows_family(family: AddressFamily) -> ADDRESS_FAMILY {
    match family {
        AddressFamily::V4 => AF_INET,
        AddressFamily::V6 => AF_INET6,
    }
}

pub(crate) fn family_of_key(key: &RouteKey) -> ADDRESS_FAMILY {
    if key.prefix.family() == AddressFamily::V6 {
        AF_INET6
    } else {
        AF_INET
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

/// Resolve an interface index back to its adapter alias.
fn interface_alias(index: u32) -> Option<String> {
    let mut luid = NET_LUID_LH::default();
    // SAFETY: out-pointer contract of ConvertInterfaceIndexToLuid.
    if unsafe { ConvertInterfaceIndexToLuid(index, &mut luid) }.is_err() {
        return None;
    }
    let mut buffer = [0u16; IF_MAX_STRING_SIZE as usize + 1];
    // SAFETY: buffer is sized for IF_MAX_STRING_SIZE characters plus the
    // terminator, as the API requires.
    if unsafe { ConvertInterfaceLuidToAlias(&luid, &mut buffer) }.is_err() {
        return None;
    }
    let len = buffer.iter().position(|c| *c == 0).unwrap_or(buffer.len());
    Some(String::from_utf16_lossy(&buffer[..len]))
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
fn find_route_rows_mib(
    family: ADDRESS_FAMILY,
    ip: IpAddr,
    prefix_len: u8,
) -> Result<Vec<MIB_IPFORWARD_ROW2>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let err = unsafe { GetIpForwardTable2(family, &mut table) };
    check_win32(err, "GetIpForwardTable2")?;

    let mut matches = Vec::new();
    unsafe {
        let count = (*table).NumEntries as usize;
        let rows = (*table).Table.as_ptr();
        for i in 0..count {
            let row = &*rows.add(i);
            if row.DestinationPrefix.PrefixLength == prefix_len {
                if let Some(network) = sockaddr_to_ip(&row.DestinationPrefix.Prefix) {
                    if network == ip {
                        matches.push(*row);
                    }
                }
            }
        }
    }
    unsafe { FreeMibTable(table as _) };
    Ok(matches)
}

/// Convert a kernel MIB row to an Leshy ObservedRoute (08D1 §41.3).
fn observed_of(
    row: &MIB_IPFORWARD_ROW2,
    names: Option<&HashMap<u32, String>>,
) -> Result<ObservedRoute> {
    let network = sockaddr_to_ip(&row.DestinationPrefix.Prefix)
        .ok_or_else(|| anyhow::anyhow!("Invalid destination address"))?;
    let prefix = RoutePrefix::new(network, row.DestinationPrefix.PrefixLength)?;
    let next_hop = sockaddr_to_ip(&row.NextHop);
    let target = match next_hop {
        Some(hop) if !hop.is_unspecified() => RouteTarget::Gateway(hop),
        _ => {
            let index = row.InterfaceIndex;
            let name = names
                .and_then(|n| n.get(&index))
                .cloned()
                .unwrap_or_else(|| interface_alias(index).unwrap_or_default());
            RouteTarget::Device {
                name,
                ifindex: Some(index),
            }
        }
    };
    Ok(ObservedRoute {
        key: RouteKey {
            prefix,
            table: MAIN_TABLE,
        },
        target,
        identity: RouteKernelIdentity {
            ifindex: Some(row.InterfaceIndex),
            next_hop: next_hop.filter(|hop| !hop.is_unspecified()),
            protocol: row.Protocol.0 as u8,
            metric: row.Metric,
            scope: 0,
            interface_luid: Some(unsafe { row.InterfaceLuid.Value }),
        },
    })
}

/// Enumerate every forwarding row of `family` as an [`ObservedRoute`].
fn dump_family(family: ADDRESS_FAMILY) -> Result<Vec<ObservedRoute>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: out-pointer contract of GetIpForwardTable2.
    let err = unsafe { GetIpForwardTable2(family, &mut table) };
    check_win32(err, "GetIpForwardTable2")?;

    let mut out = Vec::new();
    let mut aliases: HashMap<u32, String> = HashMap::new();
    // SAFETY: table is a valid heap table returned by the API.
    unsafe {
        let count = (*table).NumEntries as usize;
        let rows = (*table).Table.as_ptr();
        for i in 0..count {
            let row = &*rows.add(i);
            let Some(network) = sockaddr_to_ip(&row.DestinationPrefix.Prefix) else {
                continue;
            };
            let Ok(prefix) = RoutePrefix::new(network, row.DestinationPrefix.PrefixLength) else {
                continue;
            };
            let next_hop = sockaddr_to_ip(&row.NextHop);
            let target = match next_hop {
                // An all-zero next hop means the destination is on-link.
                Some(hop) if !hop.is_unspecified() => RouteTarget::Gateway(hop),
                _ => {
                    let index = row.InterfaceIndex;
                    let name = aliases
                        .entry(index)
                        .or_insert_with(|| interface_alias(index).unwrap_or_default())
                        .clone();
                    RouteTarget::Device {
                        name,
                        ifindex: Some(index),
                    }
                }
            };
            out.push(ObservedRoute {
                key: RouteKey {
                    prefix,
                    table: MAIN_TABLE,
                },
                target,
                identity: RouteKernelIdentity {
                    ifindex: Some(row.InterfaceIndex),
                    next_hop: next_hop.filter(|hop| !hop.is_unspecified()),
                    protocol: row.Protocol.0 as u8,
                    metric: row.Metric,
                    scope: 0,
                    // §31.19: the LUID is part of the exact Windows
                    // identity; the union's Value field carries the u64.
                    interface_luid: Some(row.InterfaceLuid.Value),
                },
            });
        }
    }
    // SAFETY: table was allocated by the IP Helper API.
    unsafe { FreeMibTable(table as _) };
    Ok(out)
}

/// Build a ready-to-install `MIB_IPFORWARD_ROW2`.
///
/// The row is initialized with `InitializeIpForwardEntry` first; a plain
/// `Default` row leaves fields the API expects initialized (08D1 §41.3).
fn build_row(desired: &ResolvedWindowsRoute) -> Result<MIB_IPFORWARD_ROW2> {
    let prefix = &desired.intent.key.prefix;
    let identity = &desired.identity;
    let index = identity
        .ifindex
        .ok_or_else(|| anyhow::anyhow!("desired Windows identity has no interface index"))?;
    let luid = identity
        .interface_luid
        .ok_or_else(|| anyhow::anyhow!("desired Windows identity has no interface LUID"))?;

    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: `row` is a valid writable MIB_IPFORWARD_ROW2.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = index;
    row.InterfaceLuid.Value = luid;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: address_sockaddr(prefix.network),
        PrefixLength: prefix.prefix_len,
    };
    row.NextHop = match identity.next_hop {
        Some(gateway) => address_sockaddr(gateway),
        None => prefix_sockaddr(prefix.network),
    };
    row.SitePrefixLength = 0;
    row.Metric = identity.metric;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    // 0xFFFFFFFF = infinite lifetime (`route add -p` semantics).
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    Ok(row)
}

/// The live MIB row carrying exactly this kernel identity, if any.
fn find_exact_mib_row(
    family: ADDRESS_FAMILY,
    key: &RouteKey,
    identity: &RouteKernelIdentity,
) -> Result<Option<MIB_IPFORWARD_ROW2>> {
    for row in find_route_rows_mib(family, key.prefix.network, key.prefix.prefix_len)? {
        if observed_of(&row, None)?.identity == *identity {
            return Ok(Some(row));
        }
    }
    Ok(None)
}

/// Upper bound on exact deletes for one key. A bounded loop keeps a table
/// that keeps re-publishing the row from spinning a shutdown forever.
const MAX_EXACT_DELETES: usize = 8;

/// Delete every live row that carries exactly `identity`, then prove the
/// table is empty for it.
///
/// `DeleteIpForwardEntry2` reports success while a second row with the same
/// identity can still be present: two concurrent ensures may publish the same
/// prefix twice, and a delete removes one copy. Deleting once and trusting the
/// return code left roughly 100 of 800 rows behind at shutdown (Production
/// Plan C4 stress run), so the loop re-reads the exact identity until nothing
/// matches and fails loudly if the table refuses to converge.
fn delete_all_matching(
    mut next_row: impl FnMut() -> Result<Option<MIB_IPFORWARD_ROW2>>,
    mut delete_row: impl FnMut(&MIB_IPFORWARD_ROW2) -> Result<()>,
) -> Result<usize> {
    let mut deleted = 0usize;
    while deleted < MAX_EXACT_DELETES {
        let Some(row) = next_row()? else {
            return Ok(deleted);
        };
        delete_row(&row)?;
        deleted += 1;
    }
    if next_row()?.is_some() {
        anyhow::bail!("exact route delete did not converge after {MAX_EXACT_DELETES} attempts");
    }
    Ok(deleted)
}

/// Production API over iphlpapi.dll.
#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct RealWindowsRouteApi;

#[async_trait]
impl WindowsRouteApi for RealWindowsRouteApi {
    async fn resolve_device(&self, name: &str) -> Result<WindowsInterfaceIdentity> {
        let index = resolve_interface_index(name)?;
        let luid = interface_luid(index)?;
        Ok(WindowsInterfaceIdentity { index, luid })
    }

    async fn resolve_gateway_interface(&self, gateway: IpAddr) -> Result<WindowsInterfaceIdentity> {
        let index = interface_for_gateway(gateway)?;
        let luid = interface_luid(index)?;
        Ok(WindowsInterfaceIdentity { index, luid })
    }

    async fn dump_family(&self, family: AddressFamily) -> Result<Vec<ObservedRoute>> {
        dump_family(windows_family(family))
    }

    async fn create(&self, desired: &ResolvedWindowsRoute) -> Result<WindowsCreateOutcome> {
        let row = build_row(desired)?;
        // SAFETY: `row` is a fully initialized MIB_IPFORWARD_ROW2.
        let err = unsafe { CreateIpForwardEntry2(&row) };
        if err.is_ok() {
            tracing::debug!(
                ip = %desired.intent.key.prefix.network,
                "Windows route created"
            );
            return Ok(WindowsCreateOutcome::Created);
        }
        if err == ERROR_OBJECT_ALREADY_EXISTS {
            // The caller re-reads and proves the identity; nothing is deleted
            // here (08D1 §41.3: no broad same-prefix replacement).
            tracing::debug!(
                ip = %desired.intent.key.prefix.network,
                "Windows route already exists; caller must prove identity"
            );
            return Ok(WindowsCreateOutcome::AlreadyExists);
        }
        anyhow::bail!(
            "CreateIpForwardEntry2 failed for {}: {err:?}",
            desired.intent.key.prefix.network
        )
    }

    async fn delete_exact(
        &self,
        key: &RouteKey,
        identity: &RouteKernelIdentity,
    ) -> Result<WindowsDeleteOutcome> {
        let family = family_of_key(key);
        let deleted = delete_all_matching(
            || find_exact_mib_row(family, key, identity),
            |row| {
                // SAFETY: `row` is a live MIB_IPFORWARD_ROW2 read from the table.
                let err = unsafe { DeleteIpForwardEntry2(row) };
                if err.is_ok() || err == ERROR_NOT_FOUND {
                    return Ok(());
                }
                anyhow::bail!(
                    "DeleteIpForwardEntry2 failed for {}: {err:?}",
                    key.prefix.network
                )
            },
        )?;
        if deleted == 0 {
            tracing::debug!(
                ip = %key.prefix.network,
                "no live row carries the recorded identity; nothing to delete"
            );
            return Ok(WindowsDeleteOutcome::Absent);
        }
        if deleted > 1 {
            // Concurrent ensures can publish the same identity twice (the
            // kernel accepts the second create while the first is not yet
            // visible). Every copy belongs to this process and must go.
            tracing::warn!(
                ip = %key.prefix.network,
                copies = deleted,
                "multiple rows carried the owned identity; all were deleted"
            );
        }
        Ok(WindowsDeleteOutcome::Deleted)
    }

    fn subscribe(
        &self,
        generation: Arc<AtomicU64>,
        tx: mpsc::UnboundedSender<RouteInvalidation>,
    ) -> Result<Box<dyn WindowsRouteSubscription>> {
        let context = Arc::new(ObserverContext { generation, tx });
        let mut handle = HANDLE::default();
        // SAFETY: the callback only reads the context allocation, which the
        // subscription keeps alive for the whole registration lifetime.
        let status = unsafe {
            NotifyRouteChange2(
                AF_UNSPEC,
                Some(route_change_callback),
                Arc::as_ptr(&context) as *const core::ffi::c_void,
                false,
                &mut handle,
            )
        };
        if status.is_err() {
            anyhow::bail!("NotifyRouteChange2 failed: {status:?}");
        }
        Ok(Box::new(RealWindowsRouteSubscription {
            handle: handle.0 as usize,
            _context: context,
        }))
    }
}

struct ObserverContext {
    generation: Arc<AtomicU64>,
    tx: mpsc::UnboundedSender<RouteInvalidation>,
}

unsafe extern "system" fn route_change_callback(
    context: *const core::ffi::c_void,
    row: *const MIB_IPFORWARD_ROW2,
    _notification_type: MIB_NOTIFICATION_TYPE,
) {
    if context.is_null() || row.is_null() {
        return;
    }
    // SAFETY: the context outlives the registration; see
    // `RealWindowsRouteSubscription::_context`.
    let context = unsafe { &*(context as *const ObserverContext) };
    let row = unsafe { &*row };
    let Some(network) = sockaddr_to_ip(&row.DestinationPrefix.Prefix) else {
        return;
    };
    let Ok(prefix) = RoutePrefix::new(network, row.DestinationPrefix.PrefixLength) else {
        return;
    };
    // Generation first: a reader that took the cache lock before this point
    // must be able to tell that the table changed (08D1 §41.3).
    context.generation.fetch_add(1, Ordering::SeqCst);
    let _ = context.tx.send(RouteInvalidation::Prefix(RouteKey {
        prefix,
        table: MAIN_TABLE,
    }));
}

struct RealWindowsRouteSubscription {
    handle: usize,
    /// Kept alive for the registration lifetime; never freed because a late
    /// callback must not observe freed memory.
    _context: Arc<ObserverContext>,
}

impl WindowsRouteSubscription for RealWindowsRouteSubscription {}

impl Drop for RealWindowsRouteSubscription {
    fn drop(&mut self) {
        // SAFETY: cancels the registration created in `subscribe`.
        let _ = unsafe { CancelMibChangeNotify2(HANDLE(self.handle as *mut core::ffi::c_void)) };
    }
}

fn interface_luid(index: u32) -> Result<u64> {
    let mut luid = NET_LUID_LH::default();
    // SAFETY: out-pointer is valid for the duration of the call; `Value` is
    // read immediately after a successful conversion.
    let err = unsafe { ConvertInterfaceIndexToLuid(index, &mut luid) };
    check_win32(err, "ConvertInterfaceIndexToLuid")?;
    Ok(unsafe { luid.Value })
}

/// Test-only reconstruction of a row for the sockaddr/prefix unit tests.
#[cfg(test)]
fn build_route_row_for_test(
    ip: IpAddr,
    prefix_len: u8,
    interface_index: u32,
    next_hop: Option<IpAddr>,
) -> MIB_IPFORWARD_ROW2 {
    let desired = ResolvedWindowsRoute {
        intent: RouteIntent {
            key: RouteKey {
                prefix: RoutePrefix::new(ip, prefix_len).expect("valid test prefix"),
                table: MAIN_TABLE,
            },
            zone: "test".to_string(),
            target: RouteTarget::Device {
                name: "test".to_string(),
                ifindex: Some(interface_index),
            },
            source: super::model::RouteSource::Dns,
        },
        identity: RouteKernelIdentity {
            ifindex: Some(interface_index),
            next_hop,
            protocol: WINDOWS_PROTOCOL_NETMGMT,
            metric: WINDOWS_METRIC,
            scope: 0,
            interface_luid: Some(0),
        },
    };
    build_row(&desired).expect("test row")
}

/// The exact-match predicate the moved unit tests exercise.
#[cfg(test)]
fn observed_matches(row: &ObservedRoute, intent: &RouteIntent) -> bool {
    row.key == intent.key
        && row.target == intent.target
        && row.identity.protocol == WINDOWS_PROTOCOL_NETMGMT
        && row.identity.metric == WINDOWS_METRIC
        && row.identity.scope == 0
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::sync::Mutex;

    /// Deterministic in-memory forwarding table with scripted create results.
    pub(crate) struct FakeWindowsRouteApi {
        state: Mutex<FakeState>,
    }

    /// One-shot script for the next `create` call.
    enum CreateScript {
        /// Insert this row and answer AlreadyExists (EEXIST analogue).
        AlreadyExists(ObservedRoute),
        /// Insert this row and answer Created even though it does not match
        /// the desired identity (simulates a successful create whose proof
        /// fails).
        Corrupt(ObservedRoute),
    }

    struct FakeState {
        devices: HashMap<String, WindowsInterfaceIdentity>,
        gateways: HashMap<IpAddr, WindowsInterfaceIdentity>,
        rows: Vec<ObservedRoute>,
        calls: Vec<String>,
        generation: Option<Arc<AtomicU64>>,
        dump_bumps: u32,
        script: Option<CreateScript>,
    }

    impl FakeWindowsRouteApi {
        pub(crate) fn new() -> Self {
            Self {
                state: Mutex::new(FakeState {
                    devices: HashMap::new(),
                    gateways: HashMap::new(),
                    rows: Vec::new(),
                    calls: Vec::new(),
                    generation: None,
                    dump_bumps: 0,
                    script: None,
                }),
            }
        }

        pub(crate) fn add_device(&self, name: &str, index: u32, luid: u64) {
            self.state
                .lock()
                .unwrap()
                .devices
                .insert(name.to_string(), WindowsInterfaceIdentity { index, luid });
        }

        pub(crate) fn add_gateway(&self, gateway: IpAddr, index: u32, luid: u64) {
            self.state
                .lock()
                .unwrap()
                .gateways
                .insert(gateway, WindowsInterfaceIdentity { index, luid });
        }

        pub(crate) fn push_row(&self, row: ObservedRoute) {
            self.state.lock().unwrap().rows.push(row);
        }

        pub(crate) fn rows(&self) -> Vec<ObservedRoute> {
            self.state.lock().unwrap().rows.clone()
        }

        pub(crate) fn calls(&self) -> Vec<String> {
            self.state.lock().unwrap().calls.clone()
        }

        /// Bump the notification generation during the next `times` dumps.
        pub(crate) fn bump_generation_during_next_dump(&self, times: u32) {
            self.state.lock().unwrap().dump_bumps = times;
        }

        /// The next create inserts `row` and answers AlreadyExists.
        pub(crate) fn script_already_exists(&self, row: ObservedRoute) {
            self.state.lock().unwrap().script = Some(CreateScript::AlreadyExists(row));
        }

        /// The next create inserts `row` and answers Created (proof fails).
        pub(crate) fn script_corrupt_create(&self, row: ObservedRoute) {
            self.state.lock().unwrap().script = Some(CreateScript::Corrupt(row));
        }
    }

    #[async_trait]
    impl WindowsRouteApi for FakeWindowsRouteApi {
        async fn resolve_device(&self, name: &str) -> Result<WindowsInterfaceIdentity> {
            let mut state = self.state.lock().unwrap();
            state.calls.push(format!("resolve_device:{name}"));
            state
                .devices
                .get(name)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("unknown fake device '{name}'"))
        }

        async fn resolve_gateway_interface(
            &self,
            gateway: IpAddr,
        ) -> Result<WindowsInterfaceIdentity> {
            let mut state = self.state.lock().unwrap();
            state.calls.push(format!("resolve_gateway:{gateway}"));
            state
                .gateways
                .get(&gateway)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("no fake interface reaches {gateway}"))
        }

        async fn dump_family(&self, family: AddressFamily) -> Result<Vec<ObservedRoute>> {
            let mut state = self.state.lock().unwrap();
            state.calls.push(format!("dump:{family:?}"));
            if state.dump_bumps > 0 {
                state.dump_bumps -= 1;
                if let Some(generation) = &state.generation {
                    generation.fetch_add(1, Ordering::SeqCst);
                }
            }
            Ok(state
                .rows
                .iter()
                .filter(|row| row.key.prefix.family() == family)
                .cloned()
                .collect())
        }

        async fn create(&self, desired: &ResolvedWindowsRoute) -> Result<WindowsCreateOutcome> {
            let mut state = self.state.lock().unwrap();
            state.calls.push("create".to_string());
            if let Some(script) = state.script.take() {
                return match script {
                    CreateScript::AlreadyExists(row) => {
                        state.rows.push(row);
                        Ok(WindowsCreateOutcome::AlreadyExists)
                    }
                    CreateScript::Corrupt(row) => {
                        state.rows.push(row);
                        Ok(WindowsCreateOutcome::Created)
                    }
                };
            }
            let observed = ObservedRoute {
                key: desired.intent.key.clone(),
                target: desired.intent.target.clone(),
                identity: desired.identity.clone(),
            };
            if state
                .rows
                .iter()
                .any(|row| row.key == observed.key && row.identity == observed.identity)
            {
                return Ok(WindowsCreateOutcome::AlreadyExists);
            }
            state.rows.push(observed);
            Ok(WindowsCreateOutcome::Created)
        }

        async fn delete_exact(
            &self,
            key: &RouteKey,
            identity: &RouteKernelIdentity,
        ) -> Result<WindowsDeleteOutcome> {
            let mut state = self.state.lock().unwrap();
            state
                .calls
                .push(format!("delete:{}:{identity:?}", key.prefix.network));
            match state
                .rows
                .iter()
                .position(|row| row.key == *key && row.identity == *identity)
            {
                Some(position) => {
                    state.rows.remove(position);
                    Ok(WindowsDeleteOutcome::Deleted)
                }
                None => Ok(WindowsDeleteOutcome::Absent),
            }
        }

        fn subscribe(
            &self,
            generation: Arc<AtomicU64>,
            _tx: mpsc::UnboundedSender<RouteInvalidation>,
        ) -> Result<Box<dyn WindowsRouteSubscription>> {
            let mut state = self.state.lock().unwrap();
            state.calls.push("subscribe".to_string());
            state.generation = Some(generation);
            Ok(Box::new(FakeSubscription))
        }
    }

    struct FakeSubscription;

    impl WindowsRouteSubscription for FakeSubscription {}
}

#[cfg(test)]
mod tests {
    use super::super::model::RouteSource;
    use super::*;

    #[test]
    fn destination_prefix_carries_the_address() {
        // Regression: the destination prefix used to be built with the zeroed
        // helper, so every route was created for 0.0.0.0/32 and silently
        // vanished from the table.
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let row = build_route_row_for_test(ip, 32, 11, None);
        assert_eq!(sockaddr_to_ip(&row.DestinationPrefix.Prefix), Some(ip));
        assert_eq!(row.DestinationPrefix.PrefixLength, 32);
        // The on-link next hop must stay zeroed: that is what "on-link" means.
        assert_eq!(
            sockaddr_to_ip(&row.NextHop),
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        );
    }

    #[test]
    fn destination_prefix_carries_the_address_v6() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0x6812, 0x202f));
        let row = build_route_row_for_test(ip, 128, 11, None);
        assert_eq!(sockaddr_to_ip(&row.DestinationPrefix.Prefix), Some(ip));
    }

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

    #[test]
    fn interface_alias_roundtrip() {
        let index = resolve_interface_index("Loopback Pseudo-Interface 1").unwrap();
        let alias = interface_alias(index).unwrap();
        assert!(alias.to_lowercase().contains("loopback"));
    }

    #[test]
    fn observed_matches_exact_identity() {
        let intent = RouteIntent {
            key: RouteKey {
                prefix: RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                table: MAIN_TABLE,
            },
            zone: "test".to_string(),
            target: RouteTarget::Device {
                name: "tun0".to_string(),
                ifindex: Some(7),
            },
            source: RouteSource::Dns,
        };
        let observed = ObservedRoute {
            key: intent.key.clone(),
            target: intent.target.clone(),
            identity: RouteKernelIdentity {
                ifindex: Some(7),
                next_hop: None,
                protocol: 3,
                metric: 0,
                scope: 0,
                interface_luid: Some(0x1000000000000000u64),
            },
        };
        assert!(observed_matches(&observed, &intent));
    }

    #[test]
    fn observed_matches_mismatched_protocol() {
        let intent = RouteIntent {
            key: RouteKey {
                prefix: RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                table: MAIN_TABLE,
            },
            zone: "test".to_string(),
            target: RouteTarget::Device {
                name: "tun0".to_string(),
                ifindex: Some(7),
            },
            source: RouteSource::Dns,
        };
        let observed = ObservedRoute {
            key: intent.key.clone(),
            target: intent.target.clone(),
            identity: RouteKernelIdentity {
                ifindex: Some(7),
                next_hop: None,
                protocol: 4, // Wrong protocol
                metric: 0,
                scope: 0,
                interface_luid: Some(0x1000000000000000u64),
            },
        };
        assert!(!observed_matches(&observed, &intent));
    }

    #[test]
    fn observed_matches_mismatched_metric() {
        let intent = RouteIntent {
            key: RouteKey {
                prefix: RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                table: MAIN_TABLE,
            },
            zone: "test".to_string(),
            target: RouteTarget::Device {
                name: "tun0".to_string(),
                ifindex: Some(7),
            },
            source: RouteSource::Dns,
        };
        let observed = ObservedRoute {
            key: intent.key.clone(),
            target: intent.target.clone(),
            identity: RouteKernelIdentity {
                ifindex: Some(7),
                next_hop: None,
                protocol: 3,
                metric: 5, // Wrong metric
                scope: 0,
                interface_luid: Some(0x1000000000000000u64),
            },
        };
        assert!(!observed_matches(&observed, &intent));
    }

    #[test]
    fn observed_matches_mismatched_scope() {
        let intent = RouteIntent {
            key: RouteKey {
                prefix: RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                table: MAIN_TABLE,
            },
            zone: "test".to_string(),
            target: RouteTarget::Device {
                name: "tun0".to_string(),
                ifindex: Some(7),
            },
            source: RouteSource::Dns,
        };
        let observed = ObservedRoute {
            key: intent.key.clone(),
            target: intent.target.clone(),
            identity: RouteKernelIdentity {
                ifindex: Some(7),
                next_hop: None,
                protocol: 3,
                metric: 0,
                scope: 1, // Wrong scope
                interface_luid: Some(0x1000000000000000u64),
            },
        };
        assert!(!observed_matches(&observed, &intent));
    }
}

#[cfg(test)]
mod drain_tests {
    use super::*;

    fn row(metric: u32) -> MIB_IPFORWARD_ROW2 {
        MIB_IPFORWARD_ROW2 {
            Metric: metric,
            ..Default::default()
        }
    }

    #[test]
    fn drains_every_copy_of_the_identity() {
        let mut table = vec![row(0), row(0), row(0)];
        let deleted = delete_all_matching(
            || {
                Ok(if table.is_empty() {
                    None
                } else {
                    Some(table.remove(0))
                })
            },
            |_| Ok(()),
        )
        .expect("drain");
        assert_eq!(deleted, 3);
        assert!(table.is_empty());
    }

    #[test]
    fn absent_identity_deletes_nothing() {
        let deleted = delete_all_matching(|| Ok(None), |_| Ok(())).expect("drain");
        assert_eq!(deleted, 0);
    }

    #[test]
    fn a_table_that_keeps_the_row_fails_instead_of_looping() {
        let result = delete_all_matching(|| Ok(Some(row(0))), |_| Ok(()));
        assert!(result.is_err(), "a non-converging delete must be an error");
    }

    #[test]
    fn a_delete_error_is_returned() {
        let result = delete_all_matching(|| Ok(Some(row(0))), |_| anyhow::bail!("boom"));
        assert!(result.is_err());
    }
}
