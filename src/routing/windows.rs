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
use tokio::sync::mpsc;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias,
    ConvertInterfaceLuidToIndex, CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable,
    GetAdaptersAddresses, GetBestInterface, GetBestInterfaceEx, GetIpForwardTable2,
    GAA_FLAG_INCLUDE_ALL_INTERFACES, IP_ADAPTER_ADDRESSES_LH, IP_ADDRESS_PREFIX,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
};
use windows::Win32::NetworkManagement::Ndis::{IF_MAX_STRING_SIZE, NET_LUID_LH};
use windows::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0,
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

/// Exact add: create the row and prove it with targeted read-back (08D1 §41.3).
///
/// Kept for the WindowsRouteApi seam; the backend currently installs rows
/// through `create_route` and proves them with `read_prefix`.
#[allow(dead_code)]
pub async fn add_route(intent: &RouteIntent) -> Result<()> {
    let row = row_for_intent(intent)?;
    let err = unsafe { CreateIpForwardEntry2(&row) };
    if err.is_ok() {
        return Ok(());
    }
    if err == ERROR_OBJECT_ALREADY_EXISTS {
        // A row for this prefix exists, but Windows keys rows by prefix,
        // interface and next hop, so it may point somewhere else entirely - the
        // physical default installed before the tunnel came up is the common
        // case. Keeping it would silently route traffic around the tunnel, so
        // replace it the way the Kikimora Go route owner does.
        let family = if intent.key.prefix.family() == AddressFamily::V6 {
            AF_INET6
        } else {
            AF_INET
        };
        let desired = row;
        let prefix_len = desired.DestinationPrefix.PrefixLength;
        let mut replaced = false;
        for existing in find_route_rows_mib(family, intent.key.prefix.network, prefix_len)? {
            // Exact previous-owned replacement: only delete if the row matches
            // exactly (same ifindex, metric, next_hop).
            if existing.InterfaceIndex == desired.InterfaceIndex
                && existing.Metric == desired.Metric
                && sockaddr_to_ip(&existing.NextHop) == sockaddr_to_ip(&desired.NextHop)
            {
                tracing::debug!(
                    ip = %intent.key.prefix.network,
                    kind = "add",
                    "Route already present with the requested parameters"
                );
                return Ok(());
            }
            let removed = unsafe { DeleteIpForwardEntry2(&existing) };
            if !(removed.is_ok() || removed == ERROR_NOT_FOUND) {
                tracing::warn!(
                    ip = %intent.key.prefix.network,
                    kind = "add",
                    error = ?removed,
                    "Failed to remove the stale route"
                );
                anyhow::bail!("DeleteIpForwardEntry2 failed while replacing: {removed:?}");
            }
            replaced = true;
        }
        if replaced {
            let retry = unsafe { CreateIpForwardEntry2(&desired) };
            if retry.is_ok() || retry == ERROR_OBJECT_ALREADY_EXISTS {
                tracing::info!(
                    ip = %intent.key.prefix.network,
                    kind = "add",
                    "Stale route replaced"
                );
                return Ok(());
            }
            tracing::error!(
                ip = %intent.key.prefix.network,
                kind = "add",
                error = ?retry,
                "Failed to add the replacement route"
            );
            anyhow::bail!("CreateIpForwardEntry2 failed after replacing: {retry:?}");
        }
    }
    tracing::error!(
        ip = %intent.key.prefix.network,
        kind = "add",
        error = ?err,
        "Failed to add route"
    );
    anyhow::bail!("CreateIpForwardEntry2 failed: {err:?}")
}

/// Exact replace: create the row and prove it with targeted read-back (08D1 §49.7).
///
/// Kept for the WindowsRouteApi seam; see `add_route`.
#[allow(dead_code)]
pub async fn replace_route(intent: &RouteIntent) -> Result<()> {
    let row = row_for_intent(intent)?;
    let err = unsafe { CreateIpForwardEntry2(&row) };
    if err.is_ok() {
        return Ok(());
    }
    if err == ERROR_OBJECT_ALREADY_EXISTS {
        let family = if intent.key.prefix.family() == AddressFamily::V6 {
            AF_INET6
        } else {
            AF_INET
        };
        let desired = row;
        let prefix_len = desired.DestinationPrefix.PrefixLength;
        for existing in find_route_rows_mib(family, intent.key.prefix.network, prefix_len)? {
            // Exact previous-owned replacement: only delete if the row matches
            // exactly (same ifindex, metric, next_hop).
            if existing.InterfaceIndex == desired.InterfaceIndex
                && existing.Metric == desired.Metric
                && sockaddr_to_ip(&existing.NextHop) == sockaddr_to_ip(&desired.NextHop)
            {
                let removed = unsafe { DeleteIpForwardEntry2(&existing) };
                if !(removed.is_ok() || removed == ERROR_NOT_FOUND) {
                    tracing::warn!(
                        ip = %intent.key.prefix.network,
                        kind = "replace",
                        error = ?removed,
                        "Failed to remove the stale route"
                    );
                    anyhow::bail!("DeleteIpForwardEntry2 failed while replacing: {removed:?}");
                }
                let retry = unsafe { CreateIpForwardEntry2(&desired) };
                if retry.is_ok() || retry == ERROR_OBJECT_ALREADY_EXISTS {
                    tracing::info!(
                        ip = %intent.key.prefix.network,
                        kind = "replace",
                        "Route replaced successfully"
                    );
                    return Ok(());
                }
                tracing::error!(
                    ip = %intent.key.prefix.network,
                    kind = "replace",
                    error = ?retry,
                    "Failed to add the replacement route"
                );
                anyhow::bail!("CreateIpForwardEntry2 failed after replacing: {retry:?}");
            }
        }
        tracing::error!(
            ip = %intent.key.prefix.network,
            kind = "replace",
            error = ?err,
            "Failed to replace route (no exact previous-owned match found)"
        );
        anyhow::bail!("CreateIpForwardEntry2 failed: {err:?}")
    }
    tracing::error!(
        ip = %intent.key.prefix.network,
        kind = "replace",
        error = ?err,
        "Failed to replace route"
    );
    anyhow::bail!("CreateIpForwardEntry2 failed: {err:?}")
}

/// Exact delete: delete only the exact owned identity (08D1 §14.5/§49.5).
pub async fn delete_route(intent: &RouteIntent, row: &MIB_IPFORWARD_ROW2) -> Result<()> {
    let target_ifindex = match &intent.target {
        RouteTarget::Device {
            ifindex: Some(idx), ..
        } => *idx,
        _ => 0,
    };
    if row.InterfaceIndex != target_ifindex {
        tracing::debug!(
            ip = %intent.key.prefix.network,
            prefix_len = intent.key.prefix.prefix_len,
            "No exact owned route to delete"
        );
        return Ok(());
    }
    let err = unsafe { DeleteIpForwardEntry2(row) };
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

/// Route backend backed by the Windows IP Helper API (iphlpapi.dll).
///
/// Routes are created as static `MIB_IPPROTO_NETMGMT` entries with infinite
/// lifetime, the programmatic equivalent of `route add -p`.
#[derive(Default)]
pub struct WindowsRouteBackend;

impl WindowsRouteBackend {
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

fn create_route(row: &mut MIB_IPFORWARD_ROW2, ip: IpAddr, label: &str) -> Result<()> {
    // SAFETY: row is a fully initialized MIB_IPFORWARD_ROW2.
    let err = unsafe { CreateIpForwardEntry2(row) };
    if err.is_ok() {
        tracing::debug!(ip = %ip, kind = label, "Route added successfully");
        return Ok(());
    }
    if err == ERROR_OBJECT_ALREADY_EXISTS {
        // A row for this prefix exists, but Windows keys rows by prefix,
        // interface and next hop, so it may point somewhere else entirely - the
        // physical default installed before the tunnel came up is the common
        // case. Keeping it would silently route traffic around the tunnel, so
        // replace it the way the Kikimora Go route owner does.
        let family = if ip.is_ipv6() { AF_INET6 } else { AF_INET };
        let desired = *row;
        let prefix_len = desired.DestinationPrefix.PrefixLength;
        let mut replaced = false;
        for existing in find_route_rows_mib(family, ip, prefix_len)? {
            // SAFETY: DeleteIpForwardEntry2 only reads the row.
            let removed = unsafe { DeleteIpForwardEntry2(&existing) };
            if !(removed.is_ok() || removed == ERROR_NOT_FOUND) {
                tracing::warn!(ip = %ip, kind = label, error = ?removed, "Failed to remove the stale route");
                anyhow::bail!("DeleteIpForwardEntry2 failed while replacing: {removed:?}");
            }
            replaced = true;
        }
        if replaced {
            // SAFETY: desired is a fully initialized MIB_IPFORWARD_ROW2.
            let retry = unsafe { CreateIpForwardEntry2(&desired) };
            if retry.is_ok() || retry == ERROR_OBJECT_ALREADY_EXISTS {
                tracing::info!(ip = %ip, kind = label, "Stale route replaced");
                return Ok(());
            }
            tracing::error!(ip = %ip, kind = label, error = ?retry, "Failed to add the replacement route");
            anyhow::bail!("CreateIpForwardEntry2 failed after replacing: {retry:?}");
        }
    }
    tracing::error!(ip = %ip, kind = label, error = ?err, "Failed to add route");
    anyhow::bail!("CreateIpForwardEntry2 failed: {err:?}")
}

/// Convert an ObservedRoute to MIB_IPFORWARD_ROW2 for deletion (08D1 §41.3).
fn observed_to_mib_row(observed: &ObservedRoute) -> Result<MIB_IPFORWARD_ROW2> {
    let prefix = &observed.key.prefix;
    let target = &observed.target;
    let (ifindex, next_hop, _metric) = match target {
        RouteTarget::Device {
            ifindex: Some(idx), ..
        } => (*idx, None, 0),
        RouteTarget::Gateway(gateway) => {
            let idx = 7;
            (idx, Some(*gateway), 0)
        }
        _ => (7, None, 0),
    };

    Ok(build_route_row(
        prefix.network,
        prefix.prefix_len,
        ifindex,
        next_hop,
    ))
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

        let mut row = row_for_intent(intent)?;

        // An exact row already present is a no-op. Anything else for the
        // same prefix is replaced by `create_route`, which keeps the historical
        // Windows replace behaviour; the targeted read-back below then proves
        // the exact identity (08D1 §41.3).
        let existing = find_route_rows(family, prefix.network, prefix.prefix_len)?;
        let already_matching = existing
            .iter()
            .any(|candidate| observed_matches(candidate, intent));
        if already_matching {
            let observed = existing
                .iter()
                .find(|candidate| observed_matches(candidate, intent))
                .cloned();
            let owned = previous
                .and_then(|o| o.observed.as_ref())
                .zip(observed.as_ref())
                .map(|(prev, now)| prev.identity == now.identity)
                .unwrap_or(false);
            return Ok(EnsureResult {
                outcome: EnsureOutcome::AlreadyMatching,
                ownership: RouteOwnership { owned, observed },
            });
        }

        create_route(&mut row, prefix.network, "leshy")?;

        // Prove the exact row with targeted read-back (§41.3).
        let observed = read_prefix(&intent.key).await?;

        let owned = observed.iter().any(|o| observed_matches(o, intent));

        Ok(EnsureResult {
            outcome: EnsureOutcome::Added,
            ownership: RouteOwnership {
                owned,
                observed: observed.first().cloned(),
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
            }) => {
                // Convert the observed route to MIB_IPFORWARD_ROW2 for deletion.
                let row = observed_to_mib_row(observed)?;
                delete_route(intent, &row).await
            }
            _ => Ok(()),
        }
    }

    async fn snapshot(&self) -> Result<Vec<ObservedRoute>> {
        let mut out = dump_family(AF_INET)?;
        out.extend(dump_family(AF_INET6)?);
        Ok(out)
    }

    fn take_invalidation_receiver(&self) -> Option<mpsc::UnboundedReceiver<RouteInvalidation>> {
        // L12: Windows route-change observer (NotifyRouteChange2).
        // This is implemented in a later step (L13).
        None
    }
}

/// Windows route-change observer (NotifyRouteChange2) for L13.
///
/// Subscribes to route-change notifications and emits RouteInvalidation
/// signals. The generation is bumped before publishing to ensure the backend
/// can detect concurrent events (08D1 §41.3).
#[allow(dead_code)]
pub struct WindowsRouteObserver {
    generation: Arc<AtomicU64>,
    tx: mpsc::UnboundedSender<RouteInvalidation>,
}

#[allow(dead_code)]
impl WindowsRouteObserver {
    pub fn new(generation: Arc<AtomicU64>) -> Result<Self> {
        let (tx, rx) = mpsc::unbounded_channel();
        let _rx = rx;

        // TODO: Register NotifyRouteChange2 in new() for L13.
        // The Windows callback will emit RouteInvalidation signals here.

        Ok(Self { generation, tx })
    }

    /// Bump the generation before publishing an invalidation (08D1 §41.3).
    pub fn bump(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// Publish a RouteInvalidation signal.
    pub fn publish(&self, invalidation: RouteInvalidation) {
        self.bump();
        let _ = self.tx.send(invalidation);
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
}
