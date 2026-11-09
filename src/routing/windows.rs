//! Windows route backend: IP Helper API writer plus forwarding-table read-back.
//!
//! Windows keys forwarding rows by destination prefix, interface and next hop,
//! so a row for the same prefix may point somewhere else entirely — the
//! physical default installed before the tunnel came up is the common case.
//! `ensure_route` therefore compares the full row identity before reporting a
//! match, and replaces a stale row the way the Kikimora Go route owner does.

use super::backend::{EnsureOutcome, EnsureResult, RouteBackend, RouteInvalidation};
use super::model::{
    family_of, AddressFamily, ObservedRoute, RouteIntent, RouteKernelIdentity, RouteKey,
    RouteOwnership, RoutePrefix, RouteTarget,
};
use crate::config::{RouteType, ZoneConfig};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::mpsc;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, HANDLE, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, ConvertInterfaceAliasToLuid, ConvertInterfaceIndexToLuid,
    ConvertInterfaceLuidToAlias, ConvertInterfaceLuidToIndex, CreateIpForwardEntry2,
    DeleteIpForwardEntry2, FreeMibTable, GetAdaptersAddresses, GetBestInterface,
    GetBestInterfaceEx, GetIpForwardTable2, NotifyRouteChange2, GAA_FLAG_INCLUDE_ALL_INTERFACES,
    IP_ADAPTER_ADDRESSES_LH, IP_ADDRESS_PREFIX, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
    MIB_NOTIFICATION_TYPE,
};
use windows::Win32::NetworkManagement::Ndis::{IF_MAX_STRING_SIZE, NET_LUID_LH};
use windows::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0,
    MIB_IPPROTO_NETMGMT, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
};

/// The main routing table. Windows has no table selector in the IP Helper API;
/// every row lives in the system forwarding table.
const MAIN_TABLE: u32 = 254;

/// Exact match contract for a row Leshy considers already correct (08D1 §41.3).
///
/// Same key, same logical target, and the writer's protocol/metric/scope.
/// For Windows, the identity includes InterfaceLUID (§31.19).
fn observed_matches(row: &ObservedRoute, intent: &RouteIntent) -> bool {
    row.key == intent.key
        && row.target == intent.target
        && row.identity.protocol == 3 // MIB_IPPROTO_NETMGMT
        && row.identity.metric == 0
        && row.identity.scope == 0
}

/// Targeted read-back of one prefix (08D1 §41.3).
///
/// Unlike Linux's filtered dump, Windows requires enumerating all rows and
/// filtering by key in Rust. This is a small cost (usually 0-1 matches) and
/// keeps the Windows backend simpler than the Linux one.
pub async fn read_prefix(key: &RouteKey) -> Result<Vec<ObservedRoute>> {
    let family = if key.prefix.family() == AddressFamily::V6 {
        AF_INET6
    } else {
        AF_INET
    };
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let err = unsafe { GetIpForwardTable2(family, &mut table) };
    check_win32(err, "GetIpForwardTable2")?;

    let mut matches = Vec::new();
    unsafe {
        let count = (*table).NumEntries as usize;
        let rows = (*table).Table.as_ptr();
        for i in 0..count {
            let row = &*rows.add(i);
            if row.DestinationPrefix.PrefixLength == key.prefix.prefix_len {
                if let Some(network) = sockaddr_to_ip(&row.DestinationPrefix.Prefix) {
                    if network == key.prefix.network {
                        matches.push(observed_of(row, None)?);
                    }
                }
            }
        }
    }
    unsafe { FreeMibTable(table as _) };
    Ok(matches)
}

/// Exact delete: remove only the live row whose kernel identity equals the
/// recorded observation (08D1 section 14.5/49.5). A missing row or a different
/// identity performs no deletion, so a foreign row can never be removed by
/// accident.
pub async fn delete_route(intent: &RouteIntent, observed: &ObservedRoute) -> Result<()> {
    let family = family_of_key(&intent.key);
    let Some(row) = find_exact_row(family, &intent.key, &observed.identity)? else {
        tracing::debug!(
            ip = %intent.key.prefix.network,
            prefix_len = intent.key.prefix.prefix_len,
            "No exact owned route to delete"
        );
        return Ok(());
    };
    let err = unsafe { DeleteIpForwardEntry2(&row) };
    if err.is_ok() || err == ERROR_NOT_FOUND {
        return Ok(());
    }
    tracing::warn!(
        ip = %intent.key.prefix.network,
        prefix_len = intent.key.prefix.prefix_len,
        error = ?err,
        "Failed to delete route"
    );
    anyhow::bail!("DeleteIpForwardEntry2 failed: {err:?}");
}

fn family_of_key(key: &RouteKey) -> ADDRESS_FAMILY {
    if key.prefix.family() == AddressFamily::V6 {
        AF_INET6
    } else {
        AF_INET
    }
}

/// Find the live MIB row whose exact kernel identity matches one recorded
/// observation.
fn find_exact_row(
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

fn conflict_error(intent: &RouteIntent, owner: &str) -> anyhow::Error {
    anyhow::anyhow!(crate::routing::backend::RouteConflict {
        prefix: format!(
            "{}/{}",
            intent.key.prefix.network, intent.key.prefix.prefix_len
        ),
        owner: owner.to_string(),
    })
}

/// Route backend backed by the Windows IP Helper API (iphlpapi.dll).
///
/// Routes are created as static `MIB_IPPROTO_NETMGMT` entries with infinite
/// lifetime, the programmatic equivalent of `route add -p`.
pub struct WindowsRouteBackend {
    observer: Option<WindowsRouteObserver>,
}

impl Default for WindowsRouteBackend {
    fn default() -> Self {
        Self::new().unwrap_or(Self { observer: None })
    }
}

impl WindowsRouteBackend {
    /// Create the local backend and register the route-change observer.
    ///
    /// An observer that cannot register is not fatal: the same way Linux
    /// survives a missing monitor, forwarding keeps working and the operator
    /// loses the event-driven repair until restarted.
    pub fn new() -> Result<Self> {
        let generation = Arc::new(AtomicU64::new(0));
        let observer = match WindowsRouteObserver::new(generation) {
            Ok(observer) => Some(observer),
            Err(e) => {
                tracing::warn!(error = %e, "Windows route monitor unavailable");
                None
            }
        };
        Ok(Self { observer })
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
            // The destination prefix must carry the address bits; the zeroed
            // form is only correct for an on-link next hop, and using it here
            // created rows for 0.0.0.0/32 while the API still reported success.
            Prefix: address_sockaddr(ip),
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
) -> Result<Vec<ObservedRoute>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: out-pointer contract of GetIpForwardTable2; the table is freed
    // with FreeMibTable below.
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
                        matches.push(observed_of(row, None)?);
                    }
                }
            }
        }
    }
    unsafe { FreeMibTable(table as _) };
    Ok(matches)
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

/// Create the desired row.
///
/// An existing row is never deleted here (08D1 section 41.3): EEXIST is safe
/// only when the table already holds exactly the desired identity. Any other
/// occupant is a conflict the caller must resolve through recorded exact
/// ownership, never through a broad same-prefix delete.
fn create_route(row: &MIB_IPFORWARD_ROW2, intent: &RouteIntent) -> Result<()> {
    let err = unsafe { CreateIpForwardEntry2(row) };
    if err.is_ok() {
        tracing::debug!(ip = %intent.key.prefix.network, "Route added");
        return Ok(());
    }
    if err == ERROR_OBJECT_ALREADY_EXISTS {
        let family = family_of_key(&intent.key);
        let same_key = find_route_rows(
            family,
            intent.key.prefix.network,
            intent.key.prefix.prefix_len,
        )?;
        if same_key
            .iter()
            .any(|candidate| observed_matches(candidate, intent))
        {
            tracing::debug!(ip = %intent.key.prefix.network, "Route already present");
            return Ok(());
        }
        let owner = same_key
            .first()
            .map(|candidate| format!("{:?}", candidate.target))
            .unwrap_or_else(|| "unknown".to_string());
        return Err(conflict_error(intent, &owner));
    }
    tracing::error!(ip = %intent.key.prefix.network, error = ?err, "Failed to add route");
    anyhow::bail!("CreateIpForwardEntry2 failed: {err:?}")
}

/// Build the forwarding row an intent describes.
fn row_for_intent(intent: &RouteIntent) -> Result<MIB_IPFORWARD_ROW2> {
    let prefix = &intent.key.prefix;
    match &intent.target {
        RouteTarget::Gateway(gateway) => {
            if family_of(*gateway) != prefix.family() {
                anyhow::bail!(
                    "route {} cannot use gateway {gateway} of another family",
                    prefix.network
                );
            }
            let index = interface_for_gateway(*gateway)?;
            Ok(build_route_row(
                prefix.network,
                prefix.prefix_len,
                index,
                Some(*gateway),
            ))
        }
        RouteTarget::Device {
            ifindex: Some(index),
            ..
        } => Ok(build_route_row(
            prefix.network,
            prefix.prefix_len,
            *index,
            None,
        )),
        RouteTarget::Device {
            name,
            ifindex: None,
        } => {
            let index = resolve_interface_index(name)?;
            Ok(build_route_row(
                prefix.network,
                prefix.prefix_len,
                index,
                None,
            ))
        }
        RouteTarget::Unreachable => anyhow::bail!(
            "route {} cannot be installed as unreachable on Windows",
            prefix.network
        ),
    }
}

#[async_trait]
impl RouteBackend for WindowsRouteBackend {
    async fn resolve_target(
        &self,
        zone: &ZoneConfig,
        family: AddressFamily,
    ) -> Result<RouteTarget> {
        match zone.route_type {
            RouteType::Dev => {
                let device = std::fs::read_to_string(&zone.route_target).with_context(|| {
                    format!(
                        "Device file '{}' not found (VPN not connected?)",
                        zone.route_target
                    )
                })?;
                let device = device.trim().to_string();
                if device.is_empty() {
                    anyhow::bail!("Device file '{}' is empty", zone.route_target);
                }
                let ifindex = resolve_interface_index(&device)?;
                Ok(RouteTarget::Device {
                    name: device,
                    ifindex: Some(ifindex),
                })
            }
            RouteType::Via => {
                let gateway = zone.gateway_for(family)?.ok_or_else(|| {
                    anyhow::anyhow!("zone '{}': no gateway configured for {family:?}", zone.name)
                })?;
                Ok(RouteTarget::Gateway(gateway))
            }
        }
    }

    async fn ensure_route(
        &self,
        intent: &RouteIntent,
        previous: Option<&RouteOwnership>,
    ) -> Result<EnsureResult> {
        let prefix = &intent.key.prefix;
        let family = if prefix.family() == AddressFamily::V6 {
            AF_INET6
        } else {
            AF_INET
        };

        let row = row_for_intent(intent)?;

        // Exact identity classification (08D1 section 41.3/49.7). Only a row
        // that matches the desired identity is a no-op, and only the exact
        // recorded owned identity may be replaced. Every other same-key row is
        // foreign and must survive unchanged.
        let existing = find_route_rows(family, prefix.network, prefix.prefix_len)?;
        if let Some(exact) = existing
            .iter()
            .find(|candidate| observed_matches(candidate, intent))
        {
            let owned = previous
                .and_then(|o| o.observed.as_ref())
                .map(|prev| prev.identity == exact.identity)
                .unwrap_or(false);
            return Ok(EnsureResult {
                outcome: EnsureOutcome::AlreadyMatching,
                ownership: RouteOwnership {
                    owned,
                    observed: Some(exact.clone()),
                },
            });
        }

        if !existing.is_empty() {
            // More than one same-key row is ambiguous: even deleting the
            // recorded row would leave a foreign one behind.
            if existing.len() > 1 {
                let owner = format!("{:?}", existing[0].target);
                return Err(conflict_error(intent, &owner));
            }
            let replaceable = previous
                .filter(|ownership| ownership.owned)
                .and_then(|ownership| ownership.observed.as_ref())
                .map(|recorded| recorded.identity == existing[0].identity)
                .unwrap_or(false);
            if !replaceable {
                return Err(conflict_error(intent, &format!("{:?}", existing[0].target)));
            }
            // section 49.7: delete exactly the recorded owned row, then install
            // the desired target below.
            let Some(stale) = find_exact_row(family, &intent.key, &existing[0].identity)? else {
                anyhow::bail!(
                    "route {} changed identity between proof and replacement",
                    prefix.network
                );
            };
            let err = unsafe { DeleteIpForwardEntry2(&stale) };
            if !(err.is_ok() || err == ERROR_NOT_FOUND) {
                anyhow::bail!("DeleteIpForwardEntry2 failed while replacing: {err:?}");
            }
        }

        create_route(&row, intent)?;

        // Prove the exact row with targeted read-back (section 41.3).
        let observed = read_prefix(&intent.key).await?;
        let Some(exact) = observed
            .iter()
            .find(|candidate| observed_matches(candidate, intent))
            .cloned()
        else {
            anyhow::bail!(
                "route {} is missing or foreign right after it was added",
                prefix.network
            );
        };

        Ok(EnsureResult {
            outcome: EnsureOutcome::Added,
            ownership: RouteOwnership {
                owned: true,
                observed: Some(exact),
            },
        })
    }

    async fn remove_route(
        &self,
        intent: &RouteIntent,
        ownership: Option<&RouteOwnership>,
    ) -> Result<()> {
        // §14.5/§49.5: no ownership or owned=false performs no kernel deletion.
        // L12: exact delete only (not broad same-prefix delete).
        match ownership {
            Some(RouteOwnership {
                owned: true,
                observed: Some(observed),
            }) => delete_route(intent, observed).await,
            _ => Ok(()),
        }
    }

    async fn snapshot(&self) -> Result<Vec<ObservedRoute>> {
        let mut out = dump_family(AF_INET)?;
        out.extend(dump_family(AF_INET6)?);
        Ok(out)
    }

    async fn observe_key(&self, key: &RouteKey) -> Result<Vec<ObservedRoute>> {
        // Targeted read-back for one destination (08D1 §16.3). The Windows
        // writer has no event path yet (L12), so this exists for the shared
        // contract rather than for a listener.
        read_prefix(key).await
    }

    fn take_invalidation_receiver(&self) -> Option<mpsc::UnboundedReceiver<RouteInvalidation>> {
        self.observer.as_ref().and_then(|o| o.take_receiver())
    }
}

/// Windows route-change observer (NotifyRouteChange2).
///
/// The callback runs on a system thread. It bumps the shared generation before
/// publishing a targeted `Prefix` invalidation, so a concurrent reader can tell
/// that the table changed (08D1 §41.3) and the event path resolves one key
/// instead of dumping the FIB.
pub struct WindowsRouteObserver {
    handle: usize,
    rx: Mutex<Option<mpsc::UnboundedReceiver<RouteInvalidation>>>,
    /// Kept alive for the lifetime of the registration. The pointer handed to
    /// the kernel must stay valid even if a late callback races `Drop`, so the
    /// context is deliberately never freed (one allocation per backend).
    _context: Arc<ObserverContext>,
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
    // SAFETY: the context allocation outlives the registration; see the field
    // comment on `WindowsRouteObserver::_context`.
    let context = unsafe { &*(context as *const ObserverContext) };
    let row = unsafe { &*row };
    let Some(network) = sockaddr_to_ip(&row.DestinationPrefix.Prefix) else {
        return;
    };
    let Ok(prefix) = RoutePrefix::new(network, row.DestinationPrefix.PrefixLength) else {
        return;
    };
    context.generation.fetch_add(1, Ordering::SeqCst);
    let _ = context.tx.send(RouteInvalidation::Prefix(RouteKey {
        prefix,
        table: MAIN_TABLE,
    }));
}

impl WindowsRouteObserver {
    /// Register `NotifyRouteChange2` and keep the invalidation receiver.
    pub fn new(generation: Arc<AtomicU64>) -> Result<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        let context = Arc::new(ObserverContext {
            generation: Arc::clone(&generation),
            tx,
        });
        let mut handle = HANDLE::default();
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
        Ok(Self {
            handle: handle.0 as usize,
            rx: Mutex::new(Some(rx)),
            _context: context,
        })
    }

    /// Take the invalidation receiver exactly once.
    pub fn take_receiver(&self) -> Option<mpsc::UnboundedReceiver<RouteInvalidation>> {
        self.rx.lock().unwrap().take()
    }
}

impl Drop for WindowsRouteObserver {
    fn drop(&mut self) {
        // SAFETY: cancels the registration created in `new`; the context
        // allocation stays alive (see `_context`).
        let _ = unsafe { CancelMibChangeNotify2(HANDLE(self.handle as *mut core::ffi::c_void)) };
    }
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
        let row = build_route_row(ip, 32, 11, None);
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
        let row = build_route_row(ip, 128, 11, None);
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

    /// 08D1 §41.3/§8.3: the row constructor itself refuses a next hop of
    /// another family. Config validation is not the platform safety boundary,
    /// so this is a backend-layer regression, not a config test.
    #[test]
    fn gateway_of_another_family_is_rejected_by_row_construction() {
        let intent = RouteIntent {
            key: RouteKey {
                prefix: RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                table: MAIN_TABLE,
            },
            zone: "test".to_string(),
            target: RouteTarget::Gateway(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            source: RouteSource::Dns,
        };
        let error = match row_for_intent(&intent) {
            Ok(_) => panic!("a v6 next hop on a v4 prefix must be refused"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("another family"),
            "unexpected error: {error}"
        );
    }
}
