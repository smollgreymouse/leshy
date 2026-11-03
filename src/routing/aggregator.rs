//! Pure IPv4 desired-prefix planner.
//!
//! The aggregator decides which prefixes Leshy *wants* in the kernel; it never
//! claims to know what is actually there. Verification belongs to the registry
//! and the platform backend.
//!
//! Splitting a broad aggregate is ordered so a failure can never open a gap:
//! the more-specific replacements are added and verified first, the conflicting
//! host route is added next, and the superseded broad route is removed last.

use crate::config::RouteType;
use crate::routing::model::{RouteIntent, RouteKey, RoutePrefix, RouteSource, RouteTarget};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

/// The main routing table every Leshy route lives in.
const MAIN_TABLE: u32 = 254;

/// Who owns a desired prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteOwner {
    pub zone_name: String,
    pub route_type: RouteType,
    pub route_target: String,
}

/// One step the caller must execute, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteAction {
    Add(RouteIntent),
    Remove(RouteIntent),
}

/// The result of planning one address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AggregationPlan {
    /// Actions in execution order: adds first, removals last.
    pub actions: Vec<RouteAction>,
}

impl AggregationPlan {
    /// Whether the plan needs no kernel work at all.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }
}

/// Aggregates individual /32 host routes into wider CIDR prefixes to reduce
/// the size of the kernel routing table.
///
/// When aggregation is enabled (prefix < 32), adding an IP installs a wider
/// prefix (e.g. /22) covering that IP. Future IPs in the same range and zone
/// are automatic no-ops. If an IP from a *different* zone falls into an
/// existing aggregate, the aggregate is split into non-conflicting sub-prefixes.
pub struct RouteAggregator {
    /// Desired prefixes: (network_as_u32, prefix_len) -> owner.
    desired: HashMap<(u32, u8), RouteOwner>,
    /// Ground truth: individual IP -> zone name (for conflict detection).
    known_ips: HashMap<Ipv4Addr, String>,
    /// Target aggregation prefix length (e.g. 22 for /22). 32 = disabled.
    prefix_len: u8,
}

impl RouteAggregator {
    pub fn new(prefix_len: Option<u8>) -> Self {
        Self {
            desired: HashMap::new(),
            known_ips: HashMap::new(),
            prefix_len: prefix_len.unwrap_or(32),
        }
    }

    /// Plan the actions needed to route `ip` through `zone_name`.
    ///
    /// The returned actions are ordered so that a partial failure leaves a
    /// route in place rather than a hole: every add precedes every remove.
    pub fn plan_ip(
        &mut self,
        ip: Ipv4Addr,
        zone_name: &str,
        route_type: RouteType,
        route_target: &str,
    ) -> AggregationPlan {
        self.known_ips.insert(ip, zone_name.to_string());

        let owner = RouteOwner {
            zone_name: zone_name.to_string(),
            route_type,
            route_target: route_target.to_string(),
        };

        // Disabled (prefix_len == 32): always install /32.
        if self.prefix_len >= 32 {
            let key = (u32::from(ip), 32);
            if self.desired.contains_key(&key) {
                return AggregationPlan::default();
            }
            self.desired.insert(key, owner.clone());
            return AggregationPlan {
                actions: vec![RouteAction::Add(intent_for(ip, 32, &owner))],
            };
        }

        // Already covered by a desired prefix of the same zone: nothing to do.
        if let Some((existing_key, existing_owner)) = self.find_covering(ip) {
            if existing_owner.zone_name == zone_name {
                return AggregationPlan::default();
            }

            // A different zone owns a prefix covering this address: split it.
            let old_net = existing_key.0;
            let old_prefix = existing_key.1;
            let old_owner = existing_owner.clone();
            self.desired.remove(&(old_net, old_prefix));

            let mut adds = Vec::new();
            let mut cur_net = old_net;
            let mut cur_prefix = old_prefix;
            let ip_u32 = u32::from(ip);

            // Halve repeatedly, keeping the half that does not contain the
            // conflicting address, until the /32 slot is reached.
            while cur_prefix < 32 {
                let child_prefix = cur_prefix + 1;
                let (left, right) = split_network(cur_net, cur_prefix);
                let (contains_ip, sibling) = if ip_in_network(ip_u32, left, child_prefix) {
                    (left, right)
                } else {
                    (right, left)
                };

                self.desired
                    .insert((sibling, child_prefix), old_owner.clone());
                adds.push(RouteAction::Add(intent_for(
                    Ipv4Addr::from(sibling),
                    child_prefix,
                    &old_owner,
                )));

                cur_net = contains_ip;
                cur_prefix = child_prefix;
            }

            // The conflicting host route goes in after its siblings.
            self.desired.insert((ip_u32, 32), owner.clone());
            adds.push(RouteAction::Add(intent_for(ip, 32, &owner)));

            // The superseded broad route is removed last, once every
            // replacement is in place.
            let mut actions = adds;
            actions.push(RouteAction::Remove(intent_for(
                Ipv4Addr::from(old_net),
                old_prefix,
                &old_owner,
            )));
            return AggregationPlan { actions };
        }

        // Not covered: create a new aggregate, carving out known conflicts.
        let agg_net = network_address(u32::from(ip), self.prefix_len);

        let conflicts: Vec<Ipv4Addr> = self
            .known_ips
            .iter()
            .filter(|(known_ip, known_zone)| {
                *known_zone != zone_name
                    && ip_in_network(u32::from(**known_ip), agg_net, self.prefix_len)
            })
            .map(|(known_ip, _)| *known_ip)
            .collect();

        self.desired
            .insert((agg_net, self.prefix_len), owner.clone());
        let mut adds = vec![RouteAction::Add(intent_for(
            Ipv4Addr::from(agg_net),
            self.prefix_len,
            &owner,
        ))];

        if conflicts.is_empty() {
            return AggregationPlan { actions: adds };
        }

        // Carve each conflicting address out of the aggregate we just planned.
        for conflict_ip in conflicts {
            let Some((cov_key, cov_owner)) = self.find_covering(conflict_ip) else {
                continue;
            };
            if cov_owner.zone_name != zone_name {
                continue;
            }
            let cov_net = cov_key.0;
            let cov_prefix = cov_key.1;
            let cov_owner = cov_owner.clone();
            self.desired.remove(&(cov_net, cov_prefix));

            let mut cur_net = cov_net;
            let mut cur_prefix = cov_prefix;
            let conflict_u32 = u32::from(conflict_ip);

            while cur_prefix < 32 {
                let child_prefix = cur_prefix + 1;
                let (left, right) = split_network(cur_net, cur_prefix);
                let (contains_conflict, sibling) =
                    if ip_in_network(conflict_u32, left, child_prefix) {
                        (left, right)
                    } else {
                        (right, left)
                    };

                self.desired
                    .insert((sibling, child_prefix), cov_owner.clone());
                adds.push(RouteAction::Add(intent_for(
                    Ipv4Addr::from(sibling),
                    child_prefix,
                    &cov_owner,
                )));

                cur_net = contains_conflict;
                cur_prefix = child_prefix;
            }

            // The /32 slot for the conflict belongs to another zone; it is
            // installed when that zone's own plan runs.
        }

        // The broad aggregate is superseded by its carved-out children, so it
        // is removed after they are in place.
        let mut actions = adds;
        actions.push(RouteAction::Remove(intent_for(
            Ipv4Addr::from(agg_net),
            self.prefix_len,
            &owner,
        )));
        AggregationPlan { actions }
    }

    /// Register a static route's IP so aggregates don't overlap with it.
    pub fn register_static_ip(&mut self, ip: Ipv4Addr, zone_name: &str) {
        self.known_ips.insert(ip, zone_name.to_string());
    }

    /// Remove all tracking for a zone.
    pub fn cleanup_zone(&mut self, zone_name: &str) {
        self.desired.retain(|_, owner| owner.zone_name != zone_name);
        self.known_ips.retain(|_, zone| zone != zone_name);
    }

    /// The most specific desired prefix covering `ip`, if any.
    pub fn installed_prefix(&self, ip: Ipv4Addr) -> Option<u8> {
        self.find_covering(ip).map(|(key, _)| key.1)
    }

    /// Find a desired prefix that covers the given IP.
    fn find_covering(&self, ip: Ipv4Addr) -> Option<((u32, u8), &RouteOwner)> {
        let ip_u32 = u32::from(ip);
        for prefix in (0..=32).rev() {
            let net = network_address(ip_u32, prefix);
            if let Some(owner) = self.desired.get(&(net, prefix)) {
                return Some(((net, prefix), owner));
            }
        }
        None
    }
}

/// Build the intent for a planned prefix.
fn intent_for(network: Ipv4Addr, prefix_len: u8, owner: &RouteOwner) -> RouteIntent {
    let target = match owner.route_type {
        // A `via` target is a literal gateway address; a `dev` target is a
        // device-file path the backend resolves at execution time.
        RouteType::Via => owner
            .route_target
            .trim()
            .parse::<IpAddr>()
            .map(RouteTarget::Gateway)
            .unwrap_or(RouteTarget::Unreachable),
        RouteType::Dev => RouteTarget::Device {
            name: owner.route_target.clone(),
            ifindex: None,
        },
    };
    RouteIntent {
        key: RouteKey {
            prefix: RoutePrefix::new(IpAddr::V4(network), prefix_len)
                .expect("planner only produces valid prefixes"),
            table: MAIN_TABLE,
        },
        zone: owner.zone_name.clone(),
        target,
        source: RouteSource::Dns,
    }
}

/// Compute the network address for an IP at a given prefix length.
fn network_address(ip: u32, prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        ip & !((1u32 << (32 - prefix_len)) - 1)
    }
}

/// Split a network into its two child halves (prefix_len + 1).
fn split_network(net: u32, prefix_len: u8) -> (u32, u32) {
    let child_prefix = prefix_len + 1;
    let left = net;
    let right = net | (1u32 << (32 - child_prefix));
    (left, right)
}

/// Check if an IP (as u32) is within a network/prefix.
fn ip_in_network(ip: u32, network: u32, prefix_len: u8) -> bool {
    network_address(ip, prefix_len) == network
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adds(plan: &AggregationPlan) -> Vec<&RouteIntent> {
        plan.actions
            .iter()
            .filter_map(|a| match a {
                RouteAction::Add(intent) => Some(intent),
                _ => None,
            })
            .collect()
    }

    fn removes(plan: &AggregationPlan) -> Vec<&RouteIntent> {
        plan.actions
            .iter()
            .filter_map(|a| match a {
                RouteAction::Remove(intent) => Some(intent),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn basic_aggregation() {
        let mut agg = RouteAggregator::new(Some(24));
        let plan = agg.plan_ip(
            Ipv4Addr::new(10, 0, 0, 5),
            "zone1",
            RouteType::Via,
            "192.168.1.1",
        );
        assert_eq!(plan.actions.len(), 1);
        let add = adds(&plan);
        assert_eq!(add.len(), 1);
        assert_eq!(
            add[0].key.prefix.network,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))
        );
        assert_eq!(add[0].key.prefix.prefix_len, 24);
    }

    #[test]
    fn same_zone_noop() {
        let mut agg = RouteAggregator::new(Some(24));
        agg.plan_ip(
            Ipv4Addr::new(10, 0, 0, 5),
            "zone1",
            RouteType::Via,
            "192.168.1.1",
        );
        let plan = agg.plan_ip(
            Ipv4Addr::new(10, 0, 0, 100),
            "zone1",
            RouteType::Via,
            "192.168.1.1",
        );
        assert!(plan.is_empty());
    }

    #[test]
    fn cross_zone_split_adds_before_removing_the_broad_route() {
        let mut agg = RouteAggregator::new(Some(24));
        agg.plan_ip(
            Ipv4Addr::new(10, 0, 0, 5),
            "zone1",
            RouteType::Via,
            "192.168.1.1",
        );

        let plan = agg.plan_ip(
            Ipv4Addr::new(10, 0, 0, 200),
            "zone2",
            RouteType::Via,
            "192.168.2.1",
        );

        // The broad /24 must be the very last action: a failure before it
        // leaves the old route in place instead of opening a gap.
        let last = plan.actions.last().unwrap();
        match last {
            RouteAction::Remove(intent) => {
                assert_eq!(intent.key.prefix.prefix_len, 24);
                assert_eq!(
                    intent.key.prefix.network,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))
                );
            }
            other => panic!("expected the broad removal last, got {other:?}"),
        }

        // Every add precedes the removal.
        let remove_index = plan.actions.len() - 1;
        for (index, action) in plan.actions.iter().enumerate() {
            if matches!(action, RouteAction::Remove(_)) {
                assert_eq!(index, remove_index, "only the broad route is removed");
            }
        }

        // 8 siblings for zone1 plus the /32 for zone2.
        assert_eq!(adds(&plan).len(), 9);
        assert_eq!(removes(&plan).len(), 1);
    }

    #[test]
    fn cross_zone_split_keeps_the_conflicting_host_route() {
        let mut agg = RouteAggregator::new(Some(24));
        agg.plan_ip(
            Ipv4Addr::new(10, 0, 0, 5),
            "zone1",
            RouteType::Via,
            "192.168.1.1",
        );
        let plan = agg.plan_ip(
            Ipv4Addr::new(10, 0, 0, 200),
            "zone2",
            RouteType::Via,
            "192.168.2.1",
        );

        let host = adds(&plan)
            .into_iter()
            .find(|intent| {
                intent.key.prefix.prefix_len == 32
                    && intent.key.prefix.network == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 200))
            })
            .expect("the conflicting host route must be planned");
        assert_eq!(host.zone, "zone2");
    }

    #[test]
    fn new_aggregate_with_preexisting_conflicts() {
        let mut agg = RouteAggregator::new(Some(24));

        // zone2 already owns 10.0.0.100.
        agg.plan_ip(
            Ipv4Addr::new(10, 0, 0, 100),
            "zone2",
            RouteType::Via,
            "192.168.2.1",
        );

        // zone1 now wants the whole /24, which must carve 10.0.0.100 out.
        let plan = agg.plan_ip(
            Ipv4Addr::new(10, 0, 0, 5),
            "zone1",
            RouteType::Via,
            "192.168.1.1",
        );

        assert!(!adds(&plan).is_empty());
        assert!(!removes(&plan).is_empty());

        // The carve-out must not install a /32 for the other zone's address.
        let conflict_host = adds(&plan).into_iter().find(|intent| {
            intent.key.prefix.prefix_len == 32
                && intent.key.prefix.network == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100))
        });
        assert!(conflict_host.is_none());
    }

    #[test]
    fn disabled_always_returns_32() {
        let mut agg = RouteAggregator::new(Some(32));
        let plan = agg.plan_ip(
            Ipv4Addr::new(10, 0, 0, 5),
            "zone1",
            RouteType::Via,
            "192.168.1.1",
        );
        assert_eq!(plan.actions.len(), 1);
        assert_eq!(adds(&plan)[0].key.prefix.prefix_len, 32);

        let again = agg.plan_ip(
            Ipv4Addr::new(10, 0, 0, 5),
            "zone1",
            RouteType::Via,
            "192.168.1.1",
        );
        assert!(again.is_empty());
    }

    #[test]
    fn none_means_disabled() {
        let mut agg = RouteAggregator::new(None);
        let plan = agg.plan_ip(
            Ipv4Addr::new(10, 0, 0, 5),
            "zone1",
            RouteType::Via,
            "192.168.1.1",
        );
        assert_eq!(adds(&plan)[0].key.prefix.prefix_len, 32);
    }

    #[test]
    fn aggregate_network_is_canonical() {
        let mut agg = RouteAggregator::new(Some(22));
        let plan = agg.plan_ip(
            Ipv4Addr::new(104, 16, 133, 229),
            "zone1",
            RouteType::Via,
            "192.168.1.1",
        );
        let add = adds(&plan)[0];
        assert_eq!(
            add.key.prefix.network,
            IpAddr::V4(Ipv4Addr::new(104, 16, 132, 0))
        );
        assert_eq!(add.key.prefix.prefix_len, 22);
    }

    #[test]
    fn cleanup_zone_removes_tracking() {
        let mut agg = RouteAggregator::new(Some(24));
        agg.plan_ip(
            Ipv4Addr::new(10, 0, 0, 5),
            "zone1",
            RouteType::Via,
            "192.168.1.1",
        );
        agg.plan_ip(
            Ipv4Addr::new(10, 1, 0, 5),
            "zone2",
            RouteType::Via,
            "192.168.2.1",
        );

        agg.cleanup_zone("zone1");

        assert!(!agg.desired.values().any(|o| o.zone_name == "zone1"));
        assert!(!agg.known_ips.values().any(|z| z == "zone1"));
        assert!(agg.desired.values().any(|o| o.zone_name == "zone2"));
    }

    #[test]
    fn register_static_ip_prevents_overlap() {
        let mut agg = RouteAggregator::new(Some(24));
        agg.register_static_ip(Ipv4Addr::new(10, 0, 0, 50), "zone2");

        let plan = agg.plan_ip(
            Ipv4Addr::new(10, 0, 0, 5),
            "zone1",
            RouteType::Via,
            "192.168.1.1",
        );
        assert!(!removes(&plan).is_empty());
    }

    #[test]
    fn installed_prefix_reports_the_covering_aggregate() {
        let mut agg = RouteAggregator::new(Some(24));
        agg.plan_ip(
            Ipv4Addr::new(10, 0, 0, 5),
            "zone1",
            RouteType::Via,
            "192.168.1.1",
        );
        assert_eq!(agg.installed_prefix(Ipv4Addr::new(10, 0, 0, 200)), Some(24));
        assert_eq!(agg.installed_prefix(Ipv4Addr::new(10, 0, 1, 1)), None);
    }

    #[test]
    fn dev_zone_plans_a_device_target() {
        let mut agg = RouteAggregator::new(Some(24));
        let plan = agg.plan_ip(
            Ipv4Addr::new(10, 0, 0, 5),
            "corp",
            RouteType::Dev,
            "/run/vpn/corp.dev",
        );
        let add = adds(&plan)[0];
        assert_eq!(
            add.target,
            RouteTarget::Device {
                name: "/run/vpn/corp.dev".to_string(),
                ifindex: None,
            }
        );
    }

    #[test]
    fn network_address_computation() {
        assert_eq!(
            network_address(u32::from(Ipv4Addr::new(10, 0, 0, 5)), 24),
            u32::from(Ipv4Addr::new(10, 0, 0, 0))
        );
        assert_eq!(
            network_address(u32::from(Ipv4Addr::new(10, 0, 0, 255)), 24),
            u32::from(Ipv4Addr::new(10, 0, 0, 0))
        );
        assert_eq!(
            network_address(u32::from(Ipv4Addr::new(104, 16, 132, 229)), 22),
            u32::from(Ipv4Addr::new(104, 16, 132, 0))
        );
        assert_eq!(
            network_address(u32::from(Ipv4Addr::new(192, 168, 1, 100)), 32),
            u32::from(Ipv4Addr::new(192, 168, 1, 100))
        );
    }

    #[test]
    fn split_network_correctness() {
        let net = u32::from(Ipv4Addr::new(10, 0, 0, 0));
        let (left, right) = split_network(net, 24);
        assert_eq!(left, u32::from(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(right, u32::from(Ipv4Addr::new(10, 0, 0, 128)));
    }
}
