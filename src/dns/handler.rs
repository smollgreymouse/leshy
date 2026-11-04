use crate::config::{
    Config, DnsProtocol, DnsServerConfig, RouteFailureMode, ServerConfig, ZoneConfig, ZoneMode,
};
use crate::dns::cache::DnsCache;
use crate::routing::{RouteError, RouteManager};
use crate::zones::{MatchedZone, ZoneMatcher};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::RecordType;
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;

/// Outcome of applying the route intents from one DNS response.
///
/// All three variants allow the answer to proceed; the difference is
/// observability only. Safety failures are `Err(RouteError)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteResponse {
    /// Every requested route intent is verified.
    Ready,
    /// No route was needed (no zone match, or no A/AAAA answers).
    NoRouteNeeded,
    /// At least one answer family was suppressed by zone policy (an explicit
    /// `ipv6 = false` zone answering an AAAA-carrying response). The answer
    /// proceeds without that family; `without_aaaa` keeps the response itself
    /// consistent.
    FamilySuppressed,
}

pub struct DnsHandler {
    config: Arc<Config>,
    matcher: Arc<ZoneMatcher>,
    route_manager: Arc<RwLock<RouteManager>>,
    cache: Arc<DnsCache>,
}

impl DnsHandler {
    pub fn new(config: Config, matcher: ZoneMatcher) -> anyhow::Result<Self> {
        let route_manager = RouteManager::for_server(&config.server)?;
        let cache = Arc::new(DnsCache::new(config.server.cache_size));

        Ok(Self {
            config: Arc::new(config),
            matcher: Arc::new(matcher),
            route_manager: Arc::new(RwLock::new(route_manager)),
            cache,
        })
    }

    /// Build a handler around a caller-provided route manager. Used by tests
    /// to drive reconciliation against the fake backend.
    #[cfg(test)]
    pub(crate) fn with_route_manager(
        config: Config,
        matcher: ZoneMatcher,
        route_manager: RouteManager,
    ) -> Self {
        let cache = Arc::new(DnsCache::new(config.server.cache_size));
        Self {
            config: Arc::new(config),
            matcher: Arc::new(matcher),
            route_manager: Arc::new(RwLock::new(route_manager)),
            cache,
        }
    }

    async fn forward_query(
        &self,
        request: &Request,
        upstream: SocketAddr,
    ) -> Result<Message, ResponseCode> {
        // Create UDP socket
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to bind UDP socket");
                ResponseCode::ServFail
            })?;

        // Connect to upstream
        socket.connect(upstream).await.map_err(|e| {
            tracing::error!(upstream = %upstream, error = %e, "Failed to connect to upstream");
            ResponseCode::ServFail
        })?;

        // Serialize the DNS query message
        let query_msg = Message::new();
        let mut query_msg = query_msg.clone();
        query_msg.add_query(hickory_proto::op::Query::query(
            request.query().name().clone().into(),
            request.query().query_type(),
        ));
        query_msg.set_id(request.id());
        query_msg.set_message_type(MessageType::Query);
        query_msg.set_op_code(request.op_code());
        query_msg.set_recursion_desired(request.recursion_desired());

        let request_bytes = query_msg.to_vec().map_err(|e| {
            tracing::error!(error = %e, "Failed to serialize query");
            ResponseCode::ServFail
        })?;

        // Send request
        socket.send(&request_bytes).await.map_err(|e| {
            tracing::error!(upstream = %upstream, error = %e, "Failed to send request");
            ResponseCode::ServFail
        })?;

        // Receive response with timeout
        let mut buf = vec![0u8; 4096];
        let len = tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .map_err(|_| {
                tracing::warn!(upstream = %upstream, "Query timeout");
                ResponseCode::ServFail
            })?
            .map_err(|e| {
                tracing::error!(upstream = %upstream, error = %e, "Failed to receive response");
                ResponseCode::ServFail
            })?;

        // Parse response
        Message::from_vec(&buf[..len]).map_err(|e| {
            tracing::error!(error = %e, "Failed to parse response");
            ResponseCode::ServFail
        })
    }

    async fn forward_query_tcp(
        &self,
        request: &Request,
        upstream: SocketAddr,
    ) -> Result<Message, ResponseCode> {
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::TcpStream::connect(upstream),
        )
        .await
        .map_err(|_| {
            tracing::warn!(upstream = %upstream, "TCP connect timeout");
            ResponseCode::ServFail
        })?
        .map_err(|e| {
            tracing::error!(upstream = %upstream, error = %e, "Failed to connect TCP to upstream");
            ResponseCode::ServFail
        })?;

        // Build query message
        let mut query_msg = Message::new();
        query_msg.add_query(hickory_proto::op::Query::query(
            request.query().name().clone().into(),
            request.query().query_type(),
        ));
        query_msg.set_id(request.id());
        query_msg.set_message_type(MessageType::Query);
        query_msg.set_op_code(request.op_code());
        query_msg.set_recursion_desired(request.recursion_desired());

        let request_bytes = query_msg.to_vec().map_err(|e| {
            tracing::error!(error = %e, "Failed to serialize query");
            ResponseCode::ServFail
        })?;

        // DNS over TCP: 2-byte big-endian length prefix + message
        let len_prefix = (request_bytes.len() as u16).to_be_bytes();
        stream.write_all(&len_prefix).await.map_err(|e| {
            tracing::error!(upstream = %upstream, error = %e, "Failed to send TCP length prefix");
            ResponseCode::ServFail
        })?;
        stream.write_all(&request_bytes).await.map_err(|e| {
            tracing::error!(upstream = %upstream, error = %e, "Failed to send TCP request");
            ResponseCode::ServFail
        })?;

        // Read response: 2-byte length prefix then message
        let resp_len = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_u16(),
        )
        .await
        .map_err(|_| {
            tracing::warn!(upstream = %upstream, "TCP response timeout");
            ResponseCode::ServFail
        })?
        .map_err(|e| {
            tracing::error!(upstream = %upstream, error = %e, "Failed to read TCP response length");
            ResponseCode::ServFail
        })? as usize;

        let mut buf = vec![0u8; resp_len];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut buf),
        )
        .await
        .map_err(|_| {
            tracing::warn!(upstream = %upstream, "TCP response body timeout");
            ResponseCode::ServFail
        })?
        .map_err(|e| {
            tracing::error!(upstream = %upstream, error = %e, "Failed to read TCP response body");
            ResponseCode::ServFail
        })?;

        Message::from_vec(&buf).map_err(|e| {
            tracing::error!(error = %e, "Failed to parse TCP response");
            ResponseCode::ServFail
        })
    }

    /// Install host routes for the addresses in `message`.
    ///
    /// The address family of every intent comes from the record itself: an A
    /// record is always attempted, an AAAA record only when the zone enables
    /// IPv6 — so one response can legitimately install both families.
    ///
    /// Errors are typed. `CapacityExceeded`, `Conflict` and `AuthorityDenied`
    /// are safety denials: the caller must never hand out the affected
    /// address without its selected route, whatever `route_failure_mode`
    /// says. Only `Apply` honours the legacy compatibility fallback.
    async fn add_routes_from_response(
        &self,
        message: &mut Message,
        qname: &str,
    ) -> Result<RouteResponse, RouteError> {
        let matched_zone = match self.matcher.find_zone(qname) {
            Some(z) => z,
            None => return Ok(RouteResponse::NoRouteNeeded), // No zone match, no routing needed
        };

        // Extract A and AAAA records from answers
        let ips: Vec<IpAddr> = message
            .answers()
            .iter()
            .filter_map(|record| match record.record_type() {
                RecordType::A => record
                    .data()
                    .and_then(|d| d.as_a())
                    .map(|a| IpAddr::V4(a.0)),
                RecordType::AAAA => record
                    .data()
                    .and_then(|d| d.as_aaaa())
                    .map(|aaaa| IpAddr::V6(aaaa.0)),
                _ => None,
            })
            .collect();

        if ips.is_empty() {
            tracing::debug!(qname = qname, "No A/AAAA records in response");
            return Ok(RouteResponse::NoRouteNeeded);
        }

        let manager = self.route_manager.read().await;
        let mut suppressed = false;
        let mut first_error: Option<RouteError> = None;
        for ip in ips {
            // Per-zone exclusion check (exclusive zones skip IPs in their CIDR ranges)
            if matched_zone.is_excluded(ip) {
                tracing::debug!(
                    ip = %ip,
                    zone = matched_zone.config.name,
                    "IP is in zone's excluded range, skipping route"
                );
                continue;
            }
            // Family policy: AAAA is routed only when the zone enables IPv6.
            // The answer itself is filtered by `without_aaaa`, so the client
            // never sees the suppressed family either.
            if !matched_zone
                .config
                .family_enabled(crate::routing::family_of(ip))
            {
                tracing::debug!(
                    ip = %ip,
                    zone = matched_zone.config.name,
                    "Family is disabled for this zone, skipping route"
                );
                suppressed = true;
                continue;
            }
            if let Err(e) = manager.add_route(ip, &matched_zone.config).await {
                // `add_route` propagates registry classification verbatim;
                // anything it raised itself counts as an ordinary apply error.
                let classified = match e.downcast::<RouteError>() {
                    Ok(error) => error,
                    Err(e) => RouteError::Apply(e),
                };
                // A controller "family N is not ready" denial is the family
                // suppression contract (08D §12 suppressed/denied): answer
                // without that family (NODATA) instead of failing the whole
                // response.
                if let RouteError::AuthorityDenied { reason } = &classified {
                    if reason.contains("is not ready for this role")
                        && crate::routing::family_of(ip) == crate::routing::AddressFamily::V6
                    {
                        suppressed = true;
                        message
                            .answers_mut()
                            .retain(|record| record.record_type() != RecordType::AAAA);
                        continue;
                    }
                }
                tracing::warn!(
                    ip = %ip,
                    zone = matched_zone.config.name,
                    qname = qname,
                    error = %classified,
                    "Failed to add route"
                );
                match &first_error {
                    // Safety denials outrank anything recorded before them.
                    Some(previous) if denial_rank(previous) >= denial_rank(&classified) => {}
                    _ => first_error = Some(classified),
                }
            }
        }

        if let Some(error) = first_error {
            tracing::warn!(
                qname = qname,
                zone = matched_zone.config.name,
                error = %error,
                "Route installation incomplete"
            );
            return Err(error);
        }
        if suppressed {
            return Ok(RouteResponse::FamilySuppressed);
        }
        Ok(RouteResponse::Ready)
    }

    /// Whether a routing error must suppress the answer outright.
    ///
    /// `CapacityExceeded`, `Conflict` and `AuthorityDenied` are safety
    /// denials: an address without its selected route is never answered,
    /// whatever the legacy fallback says. `Apply` honours `route_failure_mode`.
    fn must_fail_closed(&self, error: &RouteError) -> bool {
        match error {
            RouteError::CapacityExceeded
            | RouteError::Conflict
            | RouteError::AuthorityDenied { .. } => true,
            RouteError::Apply(_) => {
                self.config.server.route_failure_mode == RouteFailureMode::Servfail
            }
        }
    }

    /// Get current config
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Cleanup routes for a specific zone
    pub async fn cleanup_zone(&self, zone_name: &str) -> anyhow::Result<()> {
        let manager = self.route_manager.read().await;
        manager.cleanup_zone(zone_name).await
    }

    /// Apply static routes for all zones that have them.
    /// Returns the number of failed routes (0 = all applied successfully).
    pub async fn apply_static_routes(&self) -> usize {
        let route_manager = self.route_manager.read().await;
        let mut failures = 0;
        for zone in &self.config.zones {
            // Exclusive zones use static_routes as exclusion ranges, not actual routes
            if zone.mode == ZoneMode::Exclusive {
                continue;
            }
            for cidr in &zone.static_routes {
                if let Err(e) = route_manager.add_static_route(cidr, zone).await {
                    tracing::warn!(
                        cidr = cidr,
                        zone = zone.name,
                        error = %e,
                        "Failed to add static route"
                    );
                    failures += 1;
                }
            }
        }
        failures
    }

    /// Apply static routes for one zone. Exclusive zones use `static_routes`
    /// as exclusion ranges, not routes. Registry dedupe makes re-applying an
    /// unchanged zone free.
    pub async fn apply_static_routes_for_zone(&self, zone: &ZoneConfig) -> usize {
        if zone.mode == ZoneMode::Exclusive {
            return 0;
        }
        let route_manager = self.route_manager.read().await;
        let mut failures = 0;
        for cidr in &zone.static_routes {
            if let Err(e) = route_manager.add_static_route(cidr, zone).await {
                tracing::warn!(
                    cidr = cidr,
                    zone = zone.name,
                    error = %e,
                    "Failed to add static route"
                );
                failures += 1;
            }
        }
        failures
    }

    /// Snapshot the route intents currently owned by a zone (reload support).
    pub async fn zone_route_intents(&self, zone: &str) -> Vec<crate::routing::RouteIntent> {
        let route_manager = self.route_manager.read().await;
        route_manager.zone_intents(zone).await
    }

    /// Retire exactly these owned intents (old-zone state during a reload).
    /// Returns how many were retired.
    pub async fn retire_zone_intents(&self, intents: &[crate::routing::RouteIntent]) -> usize {
        let route_manager = self.route_manager.read().await;
        route_manager.retire_intents(intents).await
    }

    /// Mark every registry entry dirty and run one reconcile (the tail step
    /// of a config reload).
    pub async fn reconcile_routes_after_reload(&self) -> usize {
        let route_manager = self.route_manager.read().await;
        let report = route_manager
            .handle_invalidation(crate::routing::backend::RouteInvalidation::Full)
            .await;
        if report.adds > 0 || report.removes > 0 {
            tracing::info!(
                adds = report.adds,
                removes = report.removes,
                "Reload reconciliation applied route changes"
            );
        }
        report.adds + report.removes
    }

    /// Returns true if any zone has static routes configured
    pub fn has_static_routes(&self) -> bool {
        self.config
            .zones
            .iter()
            .any(|z| z.mode != ZoneMode::Exclusive && !z.static_routes.is_empty())
    }

    /// Update config and matcher (for hot reload)
    pub async fn update_config(
        &mut self,
        new_config: Config,
        new_matcher: ZoneMatcher,
    ) -> anyhow::Result<()> {
        // Recreate cache if size changed, otherwise just clear
        if new_config.server.cache_size != self.config.server.cache_size {
            self.cache = Arc::new(DnsCache::new(new_config.server.cache_size));
        } else {
            self.cache.clear();
        }
        self.config = Arc::new(new_config);
        self.matcher = Arc::new(new_matcher);
        tracing::debug!("Handler config updated, cache cleared");
        Ok(())
    }
}

/// Ranking used to keep the most severe error when several addresses of one
/// response fail. Safety denials (rank 1) always win over apply errors.
fn denial_rank(error: &RouteError) -> u8 {
    match error {
        RouteError::Apply(_) => 0,
        RouteError::CapacityExceeded
        | RouteError::Conflict
        | RouteError::AuthorityDenied { .. } => 1,
    }
}

/// Remove AAAA answers from a response before it reaches a client of an
/// IPv4-only zone. The remaining A records keep their TTLs, so the cache and
/// the client treat the answer as an authoritative “no IPv6 here”.
fn without_aaaa(mut message: Message) -> Message {
    let answers: Vec<_> = message
        .take_answers()
        .into_iter()
        .filter(|record| record.record_type() != RecordType::AAAA)
        .collect();
    message.insert_answers(answers);
    message
}

/// `min_ttl` only applies when the upstream sends TTL=0; otherwise the
/// authoritative TTL is honored and capped by `max_ttl`.
fn resolve_cache_ttl(
    server_cfg: Option<&DnsServerConfig>,
    zone: Option<&ZoneConfig>,
    global: &ServerConfig,
    message: &Message,
) -> Duration {
    let min_ttl = server_cfg
        .and_then(|s| s.cache_min_ttl)
        .or(zone.and_then(|z| z.cache_min_ttl))
        .unwrap_or(global.cache_min_ttl);
    let max_ttl = server_cfg
        .and_then(|s| s.cache_max_ttl)
        .or(zone.and_then(|z| z.cache_max_ttl))
        .unwrap_or(global.cache_max_ttl);
    let negative_ttl = server_cfg
        .and_then(|s| s.cache_negative_ttl)
        .or(zone.and_then(|z| z.cache_negative_ttl))
        .unwrap_or(global.cache_negative_ttl);

    if message.response_code() == ResponseCode::NXDomain || message.answers().is_empty() {
        Duration::from_secs(negative_ttl)
    } else {
        let record_min = message
            .answers()
            .iter()
            .map(|r| r.ttl() as u64)
            .min()
            .unwrap_or(0);
        let ttl = if record_min == 0 { min_ttl } else { record_min };
        Duration::from_secs(ttl.min(max_ttl))
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        // Only handle queries
        if request.op_code() != OpCode::Query {
            let builder = MessageResponseBuilder::from_message_request(request);
            let response = builder.error_msg(request.header(), ResponseCode::NotImp);
            return response_handle.send_response(response).await.unwrap();
        }

        // Get query name - convert to string
        let qname = request.query().name().to_string();
        let qtype = request.query().query_type();

        tracing::info!(qname = qname, qtype = ?qtype, "Received query");

        // Check cache before forwarding
        if self.cache.is_enabled() {
            if let Some(mut cached) = self.cache.lookup(&qname, qtype) {
                tracing::debug!(qname = qname, qtype = ?qtype, "Cache hit");

                // Still add routes from the cached response; a routing failure
                // has to be able to turn into SERVFAIL, so wait for the result.
                let route_result = self.add_routes_from_response(&mut cached, &qname).await;
                if let Err(error) = &route_result {
                    if self.must_fail_closed(error) {
                        tracing::warn!(
                            qname = qname,
                            error = %error,
                            "Route failure: refusing the cached answer"
                        );
                        let builder = MessageResponseBuilder::from_message_request(request);
                        let servfail = builder.error_msg(request.header(), ResponseCode::ServFail);
                        return response_handle.send_response(servfail).await.unwrap();
                    }
                }

                // A cached answer is filtered the same way as a fresh one:
                // an IPv4-only zone never hands out AAAA records.
                let cached = match self.matcher.find_zone(&qname) {
                    Some(z) if !z.config.advertises_ipv6() => without_aaaa(cached),
                    _ => cached,
                };

                // Use the current request's ID so the client matches the response
                let mut header = *cached.header();
                header.set_id(request.id());

                let builder = MessageResponseBuilder::from_message_request(request);
                let response_msg = builder.build(
                    header,
                    cached.answers().iter(),
                    cached.name_servers().iter(),
                    std::iter::empty(),
                    cached.additionals().iter(),
                );
                return response_handle.send_response(response_msg).await.unwrap();
            }
        }

        // Find matching zone and determine upstream servers + protocol
        let zone: Option<MatchedZone> = self.matcher.find_zone(&qname);
        let (upstreams, protocol): (Vec<(SocketAddr, Option<&DnsServerConfig>)>, DnsProtocol) =
            match &zone {
                Some(z) if !z.config.dns_servers.is_empty() => {
                    tracing::debug!(
                        qname = qname,
                        zone = z.config.name,
                        servers = ?z.config.dns_servers.iter().map(|s| s.address).collect::<Vec<_>>(),
                        protocol = ?z.config.dns_protocol,
                        "Routing to zone DNS"
                    );
                    let ups = z
                        .config
                        .dns_servers
                        .iter()
                        .map(|s| (s.address, Some(s)))
                        .collect();
                    (ups, z.config.dns_protocol)
                }
                _ => {
                    tracing::debug!(
                        qname = qname,
                        upstreams = ?self.config.server.default_upstream,
                        "Routing to default DNS"
                    );
                    let ups = self
                        .config
                        .server
                        .default_upstream
                        .iter()
                        .map(|&a| (a, None))
                        .collect();
                    (ups, DnsProtocol::Udp)
                }
            };

        // Sequential failover: try servers in order, fail only when all exhausted.
        // Both transport errors and SERVFAIL/REFUSED responses trigger failover.
        let mut last_err = ResponseCode::ServFail;
        let mut result: Option<(Message, Option<&DnsServerConfig>)> = None;
        for (i, (upstream, server_cfg)) in upstreams.iter().enumerate() {
            let res = match protocol {
                DnsProtocol::Udp => self.forward_query(request, *upstream).await,
                DnsProtocol::Tcp => self.forward_query_tcp(request, *upstream).await,
            };
            match res {
                Ok(response)
                    if response.response_code() == ResponseCode::ServFail
                        || response.response_code() == ResponseCode::Refused =>
                {
                    tracing::warn!(
                        qname = qname,
                        upstream = %upstream,
                        rcode = ?response.response_code(),
                        remaining = upstreams.len() - i - 1,
                        "Upstream returned error response, trying next"
                    );
                    last_err = response.response_code();
                }
                Ok(response) => {
                    result = Some((response, *server_cfg));
                    break;
                }
                Err(rcode) => {
                    tracing::warn!(
                        qname = qname,
                        upstream = %upstream,
                        rcode = ?rcode,
                        remaining = upstreams.len() - i - 1,
                        "Upstream failed, trying next"
                    );
                    last_err = rcode;
                }
            }
        }

        match result {
            Some((response, server_cfg)) => {
                // A zone pinned to a managed device that carries only IPv4
                // must not hand out AAAA answers: the client would send
                // that traffic around the tunnel over the physical link
                // (or into a black hole) while the A path stays protected.
                let mut response = match &zone {
                    Some(z) if !z.config.advertises_ipv6() => {
                        tracing::debug!(
                            qname = qname,
                            zone = z.config.name,
                            "IPv4-only zone: dropping AAAA answers"
                        );
                        without_aaaa(response)
                    }
                    _ => response,
                };
                tracing::debug!(
                    qname = qname,
                    answers = response.answers().len(),
                    "Got response"
                );

                // Install routes for the resolved IPs before answering, so the
                // configured failure mode can act on a routing failure.
                let route_result = self.add_routes_from_response(&mut response, &qname).await;
                if let Err(error) = &route_result {
                    if self.must_fail_closed(error) {
                        tracing::warn!(
                            qname = qname,
                            error = %error,
                            "Route failure: refusing the answer"
                        );
                        let builder = MessageResponseBuilder::from_message_request(request);
                        let servfail = builder.error_msg(request.header(), ResponseCode::ServFail);
                        return response_handle.send_response(servfail).await.unwrap();
                    }
                }

                // Cache the response (skip ServFail)
                if self.cache.is_enabled() && response.response_code() != ResponseCode::ServFail {
                    let ttl = resolve_cache_ttl(
                        server_cfg,
                        zone.as_ref().map(|z| z.config.as_ref()),
                        &self.config.server,
                        &response,
                    );
                    self.cache.insert(&qname, qtype, response.clone(), ttl);
                }

                // Convert Message to MessageResponse
                let builder = MessageResponseBuilder::from_message_request(request);
                let response_msg = builder.build(
                    *response.header(),
                    response.answers().iter(),
                    response.name_servers().iter(),
                    std::iter::empty(),
                    response.additionals().iter(),
                );

                response_handle.send_response(response_msg).await.unwrap()
            }
            None => {
                tracing::error!(qname = qname, rcode = ?last_err, "All upstreams failed");
                let builder = MessageResponseBuilder::from_message_request(request);
                let response = builder.error_msg(request.header(), last_err);
                response_handle.send_response(response).await.unwrap()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RouteFailureMode;
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn make_server_config(min_ttl: u64, max_ttl: u64, negative_ttl: u64) -> ServerConfig {
        ServerConfig {
            listen_address: "0.0.0.0:53".parse().unwrap(),
            default_upstream: vec!["1.1.1.1:53".parse().unwrap()],
            route_failure_mode: RouteFailureMode::Fallback,
            auto_reload: false,
            config_dir: None,
            cache_size: 1000,
            cache_min_ttl: min_ttl,
            cache_max_ttl: max_ttl,
            cache_negative_ttl: negative_ttl,
            route_aggregation_prefix: None,
            max_dynamic_routes: crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES,
            routing_backend: crate::config::RoutingBackend::Local,
            kikimora_socket: None,
        }
    }

    fn make_response_with_ttl(ttl: u32) -> Message {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::NoError);
        let mut record = Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            ttl,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(1, 2, 3, 4))),
        );
        record.set_record_type(RecordType::A);
        msg.add_answer(record);
        msg
    }

    fn make_nxdomain() -> Message {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::NXDomain);
        msg
    }

    #[test]
    fn authoritative_ttl_is_not_extended_by_min_ttl() {
        let cfg = make_server_config(60, 3600, 30);
        let response = make_response_with_ttl(10);

        let ttl = resolve_cache_ttl(None, None, &cfg, &response);
        assert_eq!(ttl, Duration::from_secs(10));
    }

    #[test]
    fn authoritative_ttl_is_capped_by_max_ttl() {
        let cfg = make_server_config(0, 300, 30);
        let response = make_response_with_ttl(3600);

        let ttl = resolve_cache_ttl(None, None, &cfg, &response);
        assert_eq!(ttl, Duration::from_secs(300));
    }

    #[test]
    fn record_ttl_zero_falls_back_to_min_ttl() {
        let cfg = make_server_config(45, 3600, 30);
        let response = make_response_with_ttl(0);

        let ttl = resolve_cache_ttl(None, None, &cfg, &response);
        assert_eq!(ttl, Duration::from_secs(45));
    }

    fn make_response_with_a_and_aaaa() -> Message {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::NoError);
        let mut a = Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            60,
            RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(1, 2, 3, 4))),
        );
        a.set_record_type(RecordType::A);
        msg.add_answer(a);
        let mut aaaa = Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            60,
            RData::AAAA(hickory_proto::rr::rdata::AAAA(std::net::Ipv6Addr::new(
                0x2a06, 0x98c1, 0x3122, 0x8000, 0, 0, 0, 0,
            ))),
        );
        aaaa.set_record_type(RecordType::AAAA);
        msg.add_answer(aaaa);
        msg
    }

    #[test]
    fn ipv4_only_zone_drops_aaaa_answers() {
        let filtered = without_aaaa(make_response_with_a_and_aaaa());
        let types: Vec<_> = filtered.answers().iter().map(|r| r.record_type()).collect();
        assert_eq!(types, vec![RecordType::A]);
        assert_eq!(filtered.response_code(), ResponseCode::NoError);
    }

    #[test]
    fn device_zones_are_ipv4_only_unless_they_opt_in() {
        let cfg: Config = toml::from_str(
            r#"
[server]
listen_address = "127.0.0.1:53"
default_upstream = ["1.1.1.1:53"]

[[zones]]
name = "vpn"
route_type = "dev"
route_target = "/run/vpn.dev"
"#,
        )
        .unwrap();
        assert!(!cfg.zones[0].advertises_ipv6());

        let cfg6: Config = toml::from_str(
            r#"
[server]
listen_address = "127.0.0.1:53"
default_upstream = ["1.1.1.1:53"]

[[zones]]
name = "vpn"
route_type = "dev"
route_target = "/run/vpn.dev"
ipv6 = true
"#,
        )
        .unwrap();
        assert!(cfg6.zones[0].advertises_ipv6());

        let cfg_via: Config = toml::from_str(
            r#"
[server]
listen_address = "127.0.0.1:53"
default_upstream = ["1.1.1.1:53"]

[[zones]]
name = "gw"
route_type = "via"
route_target = "192.0.2.1"
"#,
        )
        .unwrap();
        // A `via` zone is no longer implicitly dual-stack: IPv6 is an explicit
        // opt-in for every zone type.
        assert!(!cfg_via.zones[0].advertises_ipv6());
    }

    #[test]
    fn record_ttl_zero_with_min_ttl_zero_does_not_cache_long() {
        let cfg = make_server_config(0, 3600, 30);
        let response = make_response_with_ttl(0);

        let ttl = resolve_cache_ttl(None, None, &cfg, &response);
        assert_eq!(ttl, Duration::from_secs(0));
    }

    #[test]
    fn nxdomain_uses_negative_ttl() {
        let cfg = make_server_config(60, 3600, 15);
        let response = make_nxdomain();

        let ttl = resolve_cache_ttl(None, None, &cfg, &response);
        assert_eq!(ttl, Duration::from_secs(15));
    }

    // ------------------------------------------------------------------
    // Typed route results: end-to-end through handle_request with the
    // fake backend. The cache is pre-seeded, so no upstream is contacted.
    // ------------------------------------------------------------------

    use crate::config::{DnsProtocol, RouteType, ZoneMode};
    use crate::routing::backend::fake::FakeBackend;
    use crate::routing::backend::RouteInvalidation;
    use crate::routing::{RouteKey, RouteManager, RoutePrefix};
    use hickory_proto::op::Query;
    use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncoder};
    use hickory_server::authority::{MessageRequest, MessageResponse};
    use hickory_server::server::Protocol;
    use std::sync::Mutex;

    /// A ResponseHandler that captures every response it is asked to send,
    /// decoded back into a plain Message for assertions.
    #[derive(Clone, Default)]
    struct CaptureHandler(Arc<Mutex<Vec<Message>>>);

    #[async_trait::async_trait]
    impl ResponseHandler for CaptureHandler {
        async fn send_response<'a>(
            &mut self,
            response: MessageResponse<
                '_,
                'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
                impl Iterator<Item = &'a Record> + Send + 'a,
            >,
        ) -> std::io::Result<ResponseInfo> {
            let mut buf = Vec::with_capacity(512);
            let info = {
                let mut encoder = BinEncoder::new(&mut buf);
                response
                    .destructive_emit(&mut encoder)
                    .map_err(|e| std::io::Error::other(e.to_string()))?
            };
            let message =
                Message::from_vec(&buf).map_err(|e| std::io::Error::other(e.to_string()))?;
            self.0.lock().unwrap().push(message);
            Ok(info)
        }
    }

    fn e2e_zone() -> ZoneConfig {
        ZoneConfig {
            name: "vpn".to_string(),
            mode: ZoneMode::Inclusive,
            dns_servers: vec![],
            route_type: RouteType::Via,
            route_target: "192.168.1.1".to_string(),
            route_target_ipv6: None,
            domains: vec!["example.com".to_string(), "example.org".to_string()],
            patterns: vec![],
            static_routes: vec![],
            dns_protocol: DnsProtocol::Udp,
            cache_min_ttl: None,
            cache_max_ttl: None,
            cache_negative_ttl: None,
            ipv6: false,
        }
    }

    fn e2e_config(failure_mode: RouteFailureMode, max_dynamic_routes: usize) -> Config {
        let mut server = make_server_config(60, 3600, 30);
        server.route_failure_mode = failure_mode;
        server.max_dynamic_routes = max_dynamic_routes;
        Config {
            server,
            zones: vec![e2e_zone()],
        }
    }

    fn e2e_handler(config: Config, backend: &Arc<FakeBackend>) -> DnsHandler {
        let matcher = ZoneMatcher::new(config.zones.clone()).unwrap();
        let manager = RouteManager::with_backend(
            Arc::clone(backend),
            config.server.route_aggregation_prefix,
            config.server.max_dynamic_routes,
        );
        DnsHandler::with_route_manager(config, matcher, manager)
    }

    fn make_request(qname: &str, qtype: RecordType) -> Request {
        let mut msg = Message::new();
        msg.set_id(42);
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);
        msg.add_query(Query::query(Name::from_str(qname).unwrap(), qtype));
        let bytes = msg.to_vec().unwrap();
        let mut decoder = BinDecoder::new(&bytes);
        let mreq = MessageRequest::read(&mut decoder).unwrap();
        Request::new(mreq, "127.0.0.1:53001".parse().unwrap(), Protocol::Udp)
    }

    async fn run_query(handler: &DnsHandler, qname: &str, qtype: RecordType) -> Message {
        let capture = CaptureHandler::default();
        let sink = capture.clone();
        handler
            .handle_request(&make_request(qname, qtype), capture)
            .await;
        let responses = sink.0.lock().unwrap();
        assert_eq!(responses.len(), 1, "exactly one response must be sent");
        responses[0].clone()
    }

    fn cached_response(qname: &str, ips: &[IpAddr]) -> Message {
        let mut msg = Message::new();
        msg.set_message_type(MessageType::Response);
        msg.set_response_code(ResponseCode::NoError);
        for ip in ips {
            let record = match ip {
                IpAddr::V4(v4) => Record::from_rdata(
                    Name::from_str(qname).unwrap(),
                    60,
                    RData::A(hickory_proto::rr::rdata::A(*v4)),
                ),
                IpAddr::V6(v6) => Record::from_rdata(
                    Name::from_str(qname).unwrap(),
                    60,
                    RData::AAAA(hickory_proto::rr::rdata::AAAA(*v6)),
                ),
            };
            msg.add_answer(record);
        }
        msg
    }

    fn host_key(ip: IpAddr) -> RouteKey {
        RouteKey {
            prefix: RoutePrefix::host(ip),
            table: 254,
        }
    }

    #[tokio::test]
    async fn cache_replay_produces_zero_kernel_churn() {
        let backend = Arc::new(FakeBackend::new());
        let config = e2e_config(
            RouteFailureMode::Fallback,
            crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES,
        );
        let handler = e2e_handler(config, &backend);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        handler.cache.insert(
            "example.com.",
            RecordType::A,
            cached_response("example.com.", &[ip]),
            Duration::from_secs(60),
        );

        // First classification -> one backend mutation.
        let answer = run_query(&handler, "example.com", RecordType::A).await;
        assert_eq!(answer.response_code(), ResponseCode::NoError);
        assert_eq!(backend.ensure_count(), 1);

        // 1000 subsequent cache hits -> zero additional backend mutations.
        for _ in 0..1000 {
            run_query(&handler, "example.com", RecordType::A).await;
        }
        assert_eq!(backend.ensure_count(), 1);

        // One targeted invalidation -> exactly one reconciliation mutation.
        let manager = handler.route_manager.read().await;
        manager
            .handle_invalidation(RouteInvalidation::Prefix(host_key(ip)))
            .await;
        drop(manager);
        assert_eq!(backend.ensure_count(), 2);

        // The next 1000 hits are the fast path again -> zero mutations.
        for _ in 0..1000 {
            run_query(&handler, "example.com", RecordType::A).await;
        }
        assert_eq!(backend.ensure_count(), 2);
    }

    #[tokio::test]
    async fn capacity_is_servfail_even_with_fallback_configured() {
        let backend = Arc::new(FakeBackend::new());
        let config = e2e_config(RouteFailureMode::Fallback, 1);
        let handler = e2e_handler(config, &backend);

        let first = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let second = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        handler.cache.insert(
            "example.com.",
            RecordType::A,
            cached_response("example.com.", &[first]),
            Duration::from_secs(60),
        );
        handler.cache.insert(
            "example.org.",
            RecordType::A,
            cached_response("example.org.", &[second]),
            Duration::from_secs(60),
        );

        // The first unique address fills the registry.
        let answer = run_query(&handler, "example.com", RecordType::A).await;
        assert_eq!(answer.response_code(), ResponseCode::NoError);

        // A new unique address over capacity is denied even though the legacy
        // mode is "fallback": there is no safe selected route to offer.
        let answer = run_query(&handler, "example.org", RecordType::A).await;
        assert_eq!(answer.response_code(), ResponseCode::ServFail);
        assert_eq!(backend.ensure_count(), 1);
    }

    #[tokio::test]
    async fn conflict_is_servfail_even_with_fallback_configured() {
        let backend = Arc::new(FakeBackend::new());
        backend.set_conflict("1.2.3.4/32", "RouteTarget::Gateway(192.0.2.254)");
        let config = e2e_config(
            RouteFailureMode::Fallback,
            crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES,
        );
        let handler = e2e_handler(config, &backend);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        handler.cache.insert(
            "example.com.",
            RecordType::A,
            cached_response("example.com.", &[ip]),
            Duration::from_secs(60),
        );

        // A foreign route owns the destination; the answer must be refused.
        let answer = run_query(&handler, "example.com", RecordType::A).await;
        assert_eq!(answer.response_code(), ResponseCode::ServFail);
        assert_eq!(backend.ensure_count(), 1);
    }

    #[tokio::test]
    async fn apply_error_honours_the_legacy_failure_mode() {
        let backend = Arc::new(FakeBackend::new());
        backend.set_outcome(Err(anyhow::anyhow!("netlink EPERM")));
        let config = e2e_config(
            RouteFailureMode::Servfail,
            crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES,
        );
        let handler = e2e_handler(config, &backend);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        handler.cache.insert(
            "example.com.",
            RecordType::A,
            cached_response("example.com.", &[ip]),
            Duration::from_secs(60),
        );

        // Ordinary apply errors keep the documented kill switch.
        let answer = run_query(&handler, "example.com", RecordType::A).await;
        assert_eq!(answer.response_code(), ResponseCode::ServFail);

        // ...and the fallback mode answers anyway.
        let backend = Arc::new(FakeBackend::new());
        backend.set_outcome(Err(anyhow::anyhow!("netlink EPERM")));
        let config = e2e_config(
            RouteFailureMode::Fallback,
            crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES,
        );
        let handler = e2e_handler(config, &backend);
        handler.cache.insert(
            "example.com.",
            RecordType::A,
            cached_response("example.com.", &[ip]),
            Duration::from_secs(60),
        );
        let answer = run_query(&handler, "example.com", RecordType::A).await;
        assert_eq!(answer.response_code(), ResponseCode::NoError);
    }

    #[tokio::test]
    async fn disabled_aaaa_gets_no_ipv6_intent_and_no_aaaa_answer() {
        let backend = Arc::new(FakeBackend::new());
        let config = e2e_config(
            RouteFailureMode::Servfail,
            crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES,
        );
        let handler = e2e_handler(config, &backend);
        let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let v6 = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

        // A stale dual-stack answer sits in the cache of an IPv4-only zone.
        handler.cache.insert(
            "example.com.",
            RecordType::A,
            cached_response("example.com.", &[v4, v6]),
            Duration::from_secs(60),
        );

        let answer = run_query(&handler, "example.com", RecordType::A).await;
        assert_eq!(answer.response_code(), ResponseCode::NoError);
        // The AAAA answer is stripped (NODATA for that family) and no IPv6
        // intent ever reached the backend.
        let types: Vec<_> = answer.answers().iter().map(|r| r.record_type()).collect();
        assert_eq!(types, vec![RecordType::A]);
        assert_eq!(backend.ensure_count(), 1);
    }

    #[tokio::test]
    async fn enabled_dual_stack_verifies_both_families_before_answering() {
        let backend = Arc::new(FakeBackend::new());
        let mut config = e2e_config(
            RouteFailureMode::Servfail,
            crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES,
        );
        config.zones[0].ipv6 = true;
        config.zones[0].route_target_ipv6 = Some("2001:db8::1".to_string());
        let handler = e2e_handler(config, &backend);
        let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let v6 = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        handler.cache.insert(
            "example.com.",
            RecordType::A,
            cached_response("example.com.", &[v4, v6]),
            Duration::from_secs(60),
        );

        let answer = run_query(&handler, "example.com", RecordType::A).await;
        assert_eq!(answer.response_code(), ResponseCode::NoError);
        let types: Vec<_> = answer.answers().iter().map(|r| r.record_type()).collect();
        assert_eq!(types, vec![RecordType::A, RecordType::AAAA]);
        // Both families were verified before the response went out.
        assert_eq!(backend.ensure_count(), 2);
    }

    #[tokio::test]
    async fn one_family_failure_does_not_answer_the_other_family() {
        let backend = Arc::new(FakeBackend::new());
        backend.set_outcome(Err(anyhow::anyhow!("netlink EPERM")));
        let mut config = e2e_config(
            RouteFailureMode::Servfail,
            crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES,
        );
        config.zones[0].ipv6 = true;
        config.zones[0].route_target_ipv6 = Some("2001:db8::1".to_string());
        let handler = e2e_handler(config, &backend);
        let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let v6 = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        handler.cache.insert(
            "example.com.",
            RecordType::A,
            cached_response("example.com.", &[v4, v6]),
            Duration::from_secs(60),
        );

        // The A route fails; the response must not silently become a
        // AAAA-only (or any other) answer.
        let answer = run_query(&handler, "example.com", RecordType::A).await;
        assert_eq!(answer.response_code(), ResponseCode::ServFail);
    }

    #[tokio::test]
    async fn managed_controller_denial_is_servfail_even_with_fallback_configured() {
        use crate::routing::kikimora::{
            fake::{applied_result, FakeTransport},
            KikimoraRouteBackend,
        };

        // The controller refuses the intent: the address must not be
        // answered without its selected route, whatever the fallback says.
        let transport = Arc::new(FakeTransport::new());
        let mut result = applied_result("1.2.3.4/32", 4);
        result.state = "denied".to_string();
        transport.set_result(result);

        let backend = KikimoraRouteBackend::with_test_transport(Box::new(Arc::clone(&transport)));
        let config = e2e_config(
            RouteFailureMode::Fallback,
            crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES,
        );
        let matcher = ZoneMatcher::new(config.zones.clone()).unwrap();
        let manager = RouteManager::with_backend(
            Arc::new(backend),
            config.server.route_aggregation_prefix,
            config.server.max_dynamic_routes,
        );
        let handler = DnsHandler::with_route_manager(config, matcher, manager);
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        handler.cache.insert(
            "example.com.",
            RecordType::A,
            cached_response("example.com.", &[ip]),
            Duration::from_secs(60),
        );

        let answer = run_query(&handler, "example.com", RecordType::A).await;
        assert_eq!(answer.response_code(), ResponseCode::ServFail);
        // The refusal reached the controller exactly once; no local writer
        // was ever involved.
        assert_eq!(transport.call_count(), 1);
    }

    #[tokio::test]
    async fn controller_family_not_ready_denial_suppresses_aaaa_with_nodata() {
        use crate::routing::kikimora::{fake::FakeTransport, KikimoraRouteBackend};

        // The controller denies the AAAA intent with the family-not-ready
        // marker: the answer proceeds without AAAA (NODATA) instead of
        // SERVFAIL — the suppressed shape of 08D §12.
        let transport = Arc::new(FakeTransport::new());
        let mut v6denial = crate::routing::kikimora::fake::applied_result("2001:db8::10/128", 6);
        v6denial.state = "denied".to_string();
        v6denial.reason = Some("family 6 is not ready for this role".to_string());
        transport.set_result_for_family(6, v6denial);
        transport.set_result(crate::routing::kikimora::fake::applied_result(
            "1.2.3.4/32",
            4,
        ));

        let backend = KikimoraRouteBackend::with_test_transport(Box::new(Arc::clone(&transport)));
        let mut config = e2e_config(
            RouteFailureMode::Servfail,
            crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES,
        );
        config.zones[0].ipv6 = true;
        config.zones[0].route_target_ipv6 = Some("2001:db8::1".to_string());
        let matcher = ZoneMatcher::new(config.zones.clone()).unwrap();
        let manager = RouteManager::with_backend(
            Arc::new(backend),
            config.server.route_aggregation_prefix,
            config.server.max_dynamic_routes,
        );
        let handler = DnsHandler::with_route_manager(config, matcher, manager);
        let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let v6 = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        handler.cache.insert(
            "example.com.",
            RecordType::A,
            cached_response("example.com.", &[v4, v6]),
            Duration::from_secs(60),
        );

        let answer = run_query(&handler, "example.com", RecordType::A).await;
        assert_eq!(answer.response_code(), ResponseCode::NoError);
        let types: Vec<_> = answer.answers().iter().map(|r| r.record_type()).collect();
        assert_eq!(types, vec![RecordType::A], "AAAA must be suppressed");
        // The A route was still installed; only the AAAA intent was denied.
        assert_eq!(transport.call_count(), 2);
    }

    #[tokio::test]
    async fn controller_capacity_denial_still_servfails_aaaa() {
        use crate::routing::kikimora::{fake::FakeTransport, KikimoraRouteBackend};

        // A non-family denial (capacity) stays a fail-closed SERVFAIL: only the
        // family-not-ready marker suppresses with NODATA.
        let transport = Arc::new(FakeTransport::new());
        let mut v6denial = crate::routing::kikimora::fake::applied_result("2001:db8::10/128", 6);
        v6denial.state = "denied".to_string();
        v6denial.reason = Some("selected-route capacity 16384 reached for this role".to_string());
        transport.set_result_for_family(6, v6denial);
        transport.set_result(crate::routing::kikimora::fake::applied_result(
            "1.2.3.4/32",
            4,
        ));

        let backend = KikimoraRouteBackend::with_test_transport(Box::new(Arc::clone(&transport)));
        let mut config = e2e_config(
            RouteFailureMode::Fallback,
            crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES,
        );
        config.zones[0].ipv6 = true;
        config.zones[0].route_target_ipv6 = Some("2001:db8::1".to_string());
        let matcher = ZoneMatcher::new(config.zones.clone()).unwrap();
        let manager = RouteManager::with_backend(
            Arc::new(backend),
            config.server.route_aggregation_prefix,
            config.server.max_dynamic_routes,
        );
        let handler = DnsHandler::with_route_manager(config, matcher, manager);
        let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let v6 = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        handler.cache.insert(
            "example.com.",
            RecordType::A,
            cached_response("example.com.", &[v4, v6]),
            Duration::from_secs(60),
        );

        let answer = run_query(&handler, "example.com", RecordType::A).await;
        assert_eq!(answer.response_code(), ResponseCode::ServFail);
    }

    // --- live forwarding: a real stub upstream answers over UDP/TCP -------

    /// Behavior of the in-test upstream server.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum StubMode {
        /// Answer every A query with 203.0.113.10.
        Answer,
        /// Receive and never answer: Leshy must time out into SERVFAIL.
        Drop,
        /// Reply with garbage bytes: Leshy must treat it as a parse failure.
        Garbage,
    }

    /// Spawn a stub upstream. Returns the UDP address (the query target) and
    /// the TCP address (for zones pinned to `dns_protocol = "tcp"`).
    async fn spawn_stub_upstream(mode: StubMode) -> (SocketAddr, SocketAddr) {
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp.local_addr().unwrap();
        let tcp_addr = tcp.local_addr().unwrap();
        // UDP and TCP sides run as independent loops: blocking one must not
        // starve the other.
        tokio::spawn(async move {
            loop {
                let mut buf = vec![0u8; 4096];
                if let Ok((len, peer)) = udp.recv_from(&mut buf).await {
                    let payload: Option<Vec<u8>> = match mode {
                        StubMode::Drop => None,
                        StubMode::Garbage => Some(vec![0xde, 0xad, 0xbe, 0xef]),
                        StubMode::Answer => stub_answer(&buf[..len]),
                    };
                    if let Some(payload) = payload {
                        let _ = udp.send_to(&payload, peer).await;
                    }
                }
            }
        });
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = tcp.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut header = [0u8; 2];
                    if stream.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    let len = u16::from_be_bytes(header) as usize;
                    let mut query = vec![0u8; len];
                    if stream.read_exact(&mut query).await.is_err() {
                        return;
                    }
                    match mode {
                        StubMode::Drop => {}
                        StubMode::Garbage => {
                            let _ = stream
                                .write_all(&[0x00, 0x04, 0xde, 0xad, 0xbe, 0xef])
                                .await;
                        }
                        StubMode::Answer => {
                            if let Some(reply) = stub_answer(&query) {
                                let framed = [
                                    (reply.len() as u16).to_be_bytes().as_slice(),
                                    reply.as_slice(),
                                ]
                                .concat();
                                let _ = stream.write_all(&framed).await;
                            }
                        }
                    }
                });
            }
        });
        (udp_addr, tcp_addr)
    }

    /// Build a canned upstream response for a parsed query.
    fn stub_answer(query: &[u8]) -> Option<Vec<u8>> {
        let query = Message::from_vec(query).ok()?;
        let question = query.queries().first()?.clone();
        let mut reply = Message::new();
        reply.set_id(query.id());
        reply.set_message_type(MessageType::Response);
        reply.set_response_code(ResponseCode::NoError);
        reply.set_recursion_desired(query.recursion_desired());
        reply.add_query(question.clone());
        let record_type = question.query_type();
        let name = question.name().clone();
        let answer = match record_type {
            RecordType::A => Record::from_rdata(
                name,
                60,
                RData::A(hickory_proto::rr::rdata::A(Ipv4Addr::new(203, 0, 113, 10))),
            ),
            RecordType::AAAA => Record::from_rdata(
                name,
                60,
                RData::AAAA(hickory_proto::rr::rdata::AAAA(std::net::Ipv6Addr::new(
                    0x2001, 0xdb8, 0, 0, 0, 0, 0, 10,
                ))),
            ),
            _ => return Some(reply.to_vec().ok()?),
        };
        reply.add_answer(answer);
        reply.to_vec().ok()
    }

    #[tokio::test]
    async fn udp_forwarding_answers_and_installs_routes() {
        let (udp_addr, _tcp_addr) = spawn_stub_upstream(StubMode::Answer).await;
        let backend = Arc::new(FakeBackend::new());
        let mut config = e2e_config(
            RouteFailureMode::Servfail,
            crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES,
        );
        config.server.default_upstream = vec![udp_addr];
        let matcher = ZoneMatcher::new(config.zones.clone()).unwrap();
        let manager = RouteManager::with_backend(
            Arc::clone(&backend),
            config.server.route_aggregation_prefix,
            config.server.max_dynamic_routes,
        );
        let handler = DnsHandler::with_route_manager(config, matcher, manager);

        // Cache miss: the query reaches the stub upstream, then routes are
        // installed and the answer goes out.
        let answer = run_query(&handler, "example.com", RecordType::A).await;
        assert_eq!(answer.response_code(), ResponseCode::NoError);
        let types: Vec<_> = answer.answers().iter().map(|r| r.record_type()).collect();
        assert_eq!(types, vec![RecordType::A]);
        assert_eq!(backend.ensure_count(), 1);
        assert_eq!(
            backend.ensured()[0].key.prefix,
            RoutePrefix::host(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))
        );
    }

    #[tokio::test]
    async fn tcp_pinned_zone_forwards_over_tcp() {
        let (_udp_addr, tcp_addr) = spawn_stub_upstream(StubMode::Answer).await;
        let backend = Arc::new(FakeBackend::new());
        let mut config = e2e_config(
            RouteFailureMode::Servfail,
            crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES,
        );
        let mut zone = config.zones[0].clone();
        zone.dns_servers = vec![crate::config::DnsServerConfig {
            address: tcp_addr,
            cache_min_ttl: None,
            cache_max_ttl: None,
            cache_negative_ttl: None,
        }];
        zone.dns_protocol = crate::config::DnsProtocol::Tcp;
        config.zones[0] = zone;
        let matcher = ZoneMatcher::new(config.zones.clone()).unwrap();
        let manager = RouteManager::with_backend(
            Arc::clone(&backend),
            config.server.route_aggregation_prefix,
            config.server.max_dynamic_routes,
        );
        let handler = DnsHandler::with_route_manager(config, matcher, manager);

        let answer = run_query(&handler, "example.com", RecordType::A).await;
        assert_eq!(answer.response_code(), ResponseCode::NoError);
        let types: Vec<_> = answer.answers().iter().map(|r| r.record_type()).collect();
        assert_eq!(types, vec![RecordType::A]);
        assert_eq!(backend.ensure_count(), 1);
    }

    #[tokio::test]
    async fn dead_upstream_servfails_and_never_installs_routes() {
        // A silent upstream: Leshy must time out into SERVFAIL without a
        // single kernel mutation.
        let (drop_addr, _tcp) = spawn_stub_upstream(StubMode::Drop).await;
        let backend = Arc::new(FakeBackend::new());
        let mut config = e2e_config(
            RouteFailureMode::Servfail,
            crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES,
        );
        config.server.default_upstream = vec![drop_addr];
        let matcher = ZoneMatcher::new(config.zones.clone()).unwrap();
        let manager = RouteManager::with_backend(
            Arc::clone(&backend),
            config.server.route_aggregation_prefix,
            config.server.max_dynamic_routes,
        );
        let handler = DnsHandler::with_route_manager(config, matcher, manager);

        let answer = run_query(&handler, "example.com", RecordType::A).await;
        assert_eq!(answer.response_code(), ResponseCode::ServFail);
        assert_eq!(backend.ensure_count(), 0);
    }

    #[tokio::test]
    async fn garbage_upstream_response_servfails() {
        let (udp_addr, _tcp_addr) = spawn_stub_upstream(StubMode::Garbage).await;
        let backend = Arc::new(FakeBackend::new());
        let mut config = e2e_config(
            RouteFailureMode::Servfail,
            crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES,
        );
        config.server.default_upstream = vec![udp_addr];
        let matcher = ZoneMatcher::new(config.zones.clone()).unwrap();
        let manager = RouteManager::with_backend(
            Arc::clone(&backend),
            config.server.route_aggregation_prefix,
            config.server.max_dynamic_routes,
        );
        let handler = DnsHandler::with_route_manager(config, matcher, manager);

        let answer = run_query(&handler, "example.com", RecordType::A).await;
        assert_eq!(answer.response_code(), ResponseCode::ServFail);
        assert_eq!(backend.ensure_count(), 0);
    }
}
