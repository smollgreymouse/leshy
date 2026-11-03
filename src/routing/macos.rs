//! macOS route backend: `/sbin/route` writer.
//!
//! macOS has no read-back implementation yet, so `snapshot` reports an empty
//! table and no invalidation stream is offered. The registry still dedupes
//! intents, which is what keeps repeated DNS classifications from shelling out
//! to `route` on every query.

use super::backend::{EnsureOutcome, RouteBackend, RouteInvalidation};
use super::model::{family_of, AddressFamily, ObservedRoute, RouteIntent, RouteTarget};
use crate::config::{RouteType, ZoneConfig};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::net::IpAddr;
use tokio::process::Command;
use tokio::sync::mpsc;

pub struct MacosRouteBackend;

impl MacosRouteBackend {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}

/// Run `/sbin/route` and translate the "already there" / "not there" cases
/// into success.
async fn run_route(args: &[&str], tolerate: &[&str]) -> Result<()> {
    let output = Command::new("/sbin/route").args(args).output().await?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if tolerate.iter().any(|needle| stderr.contains(needle)) {
        return Ok(());
    }
    anyhow::bail!("route {} failed: {stderr}", args.join(" "))
}

/// Build the destination argument for `/sbin/route`.
fn destination(ip: IpAddr, prefix_len: u8) -> String {
    let max_prefix = if ip.is_ipv6() { 128 } else { 32 };
    if prefix_len == max_prefix {
        ip.to_string()
    } else {
        format!("{ip}/{prefix_len}")
    }
}

#[async_trait]
impl RouteBackend for MacosRouteBackend {
    async fn resolve_target(
        &self,
        zone: &ZoneConfig,
        family: AddressFamily,
    ) -> Result<RouteTarget> {
        match zone.route_type {
            RouteType::Dev => {
                let device = tokio::fs::read_to_string(&zone.route_target)
                    .await
                    .with_context(|| {
                        format!(
                            "Device file '{}' not found (VPN not connected?)",
                            zone.route_target
                        )
                    })?;
                let device = device.trim().to_string();
                if device.is_empty() {
                    anyhow::bail!("Device file '{}' is empty", zone.route_target);
                }
                Ok(RouteTarget::Device {
                    name: device,
                    ifindex: None,
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

    async fn ensure_route(&self, intent: &RouteIntent) -> Result<EnsureOutcome> {
        let prefix = &intent.key.prefix;
        let dest = destination(prefix.network, prefix.prefix_len);
        let is_host = prefix.prefix_len == if prefix.network.is_ipv6() { 128 } else { 32 };

        let mut args: Vec<&str> = vec!["-n", "add"];
        if prefix.network.is_ipv6() {
            args.push("-inet6");
        }
        args.push(if is_host { "-host" } else { "-net" });
        args.push(&dest);

        let target_arg;
        match &intent.target {
            RouteTarget::Gateway(gateway) => {
                target_arg = gateway.to_string();
                args.push(&target_arg);
            }
            RouteTarget::Device { name, .. } => {
                args.push("-interface");
                target_arg = name.clone();
                args.push(&target_arg);
            }
            RouteTarget::Unreachable => anyhow::bail!(
                "route {} cannot be installed as unreachable on macOS",
                prefix.network
            ),
        }

        // "File exists" means the row is already there. macOS has no read-back
        // here, so the registry's dedupe is what prevents repeated calls.
        run_route(&args, &["File exists"]).await?;
        Ok(EnsureOutcome::Added)
    }

    async fn remove_route(&self, intent: &RouteIntent) -> Result<()> {
        let prefix = &intent.key.prefix;
        let dest = destination(prefix.network, prefix.prefix_len);
        let is_host = prefix.prefix_len == if prefix.network.is_ipv6() { 128 } else { 32 };

        let mut args: Vec<&str> = vec!["-n", "delete"];
        if prefix.network.is_ipv6() {
            args.push("-inet6");
        }
        args.push(if is_host { "-host" } else { "-net" });
        args.push(&dest);

        run_route(&args, &["not in table"]).await
    }

    async fn snapshot(&self) -> Result<Vec<ObservedRoute>> {
        // No read-back implementation yet: the registry treats every entry as
        // unverified after an invalidation, which is the safe direction.
        Ok(Vec::new())
    }

    fn take_invalidation_receiver(&self) -> Option<mpsc::UnboundedReceiver<RouteInvalidation>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn host_destination_has_no_prefix() {
        assert_eq!(
            destination(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 32),
            "10.0.0.1"
        );
        assert_eq!(destination(IpAddr::V6(Ipv6Addr::LOCALHOST), 128), "::1");
    }

    #[test]
    fn network_destination_carries_the_prefix() {
        assert_eq!(
            destination(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24),
            "10.0.0.0/24"
        );
        assert_eq!(
            destination(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                64
            ),
            "2001:db8::/64"
        );
    }
}
