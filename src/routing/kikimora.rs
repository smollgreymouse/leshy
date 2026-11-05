//! Kikimora managed route backend (plan section 12).
//!
//! In managed mode Kikimora is the single FIB writer for Leshy-selected
//! routes. This backend never touches the local kernel: it forwards typed
//! route intents over the framed JSON control socket (API v3,
//! `managed_selected_routes_v1`) and maps the controller's exact status back
//! into the registry's outcome/error taxonomy.
//!
//! Trust boundary (08D §2.2): a request carries only the zone, the canonical
//! prefix and the source kind. Gateway, interface, ifindex, table, metric,
//! protocol and parking state are derived by the controller from its own
//! authoritative role state.
//!
//! There is deliberately no fallback to the local writer: if the controller
//! is unreachable the intents fail and the DNS layer applies its failure
//! policy. A socket loss marks every entry's authority unknown through a
//! full invalidation, so a stale Verified entry is never trusted for a new
//! intent.

use crate::config::ZoneConfig;
use crate::routing::backend::{
    ControllerDenied, EnsureOutcome, RouteBackend, RouteConflict, RouteInvalidation,
};
use crate::routing::model::{AddressFamily, ObservedRoute, RouteIntent, RouteSource, RouteTarget};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

/// API version spoken by this backend (Kikimora control API v3).
pub(crate) const API_VERSION: i32 = 3;

/// Handshake capability required before any route call is made.
pub(crate) const MANAGED_CAPABILITY: &str = "managed_selected_routes_v1";

/// One framed transaction must not hang the DNS request path.
const CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// Frame size cap, mirroring the controller's own limit.
const MAX_FRAME: usize = 1024 * 1024;

/// Subscription reconnect backoff bounds (no busy retry loop).
const RECONNECT_MIN: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Wire types (mirror Kikimora internal/control API v3, 08D §2.1)
// ---------------------------------------------------------------------------

/// The only fields Leshy may specify about a route.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct LeshyRouteIntentWire {
    pub zone: String,
    /// Canonical `network/len` (host /32 or /128 for DNS source).
    pub prefix: String,
    /// "dns" or "static".
    pub source: String,
}

/// The controller's exact verdict for one intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct LeshyRouteResultWire {
    pub role: String,
    pub zone: String,
    pub prefix: String,
    /// 4 or 6.
    pub family: u8,
    /// Authoritative selected-route generation.
    pub generation: u64,
    /// applied | already-applied | denied | conflict
    pub state: String,
    /// Denial marker: "family N is not ready for this role" lets the DNS
    /// layer suppress that family with NODATA instead of SERVFAIL.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ControlRequest {
    version: i32,
    id: String,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    leshy_route: Option<LeshyRouteIntentWire>,
    /// Service-to-service bearer credential for privileged methods
    /// (08D1 §31.6). Absent on the wire when the install carries no
    /// credential file.
    #[serde(skip_serializing_if = "Option::is_none")]
    privileged_auth: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ControlResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: String,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    leshy_route: Option<LeshyRouteResultWire>,
    #[serde(default)]
    snapshot: Option<CoreSnapshot>,
}

/// The slice of the controller snapshot the subscription pump consumes.
/// Unknown fields are ignored, absent fields default.
#[derive(Debug, Clone, Deserialize)]
struct CoreSnapshot {
    #[serde(default)]
    roles: Vec<CoreRole>,
}

#[derive(Debug, Clone, Deserialize)]
struct CoreRole {
    id: String,
    #[serde(default)]
    publication: Option<CorePublication>,
}

#[derive(Debug, Clone, Deserialize)]
struct CorePublication {
    #[serde(default)]
    zone: Option<String>,
    #[serde(default)]
    generation: Option<u64>,
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// One request/response transaction with the controller, plus the
/// capabilities it advertised.
///
/// async_trait's generated #[must_use] on boxed futures trips this lint on
/// newer clippy versions; the futures are always awaited internally.
#[allow(clippy::double_must_use)]
#[async_trait]
pub(crate) trait ControlTransport: Send + Sync {
    async fn call(
        &self,
        method: &str,
        intent: Option<&LeshyRouteIntentWire>,
    ) -> Result<(Vec<String>, Option<LeshyRouteResultWire>)>;
}

/// Real transport over the Kikimora control socket. Every call dials a fresh
/// connection, exactly like the controller's own `Call` helper; the socket is
/// length-prefixed JSON frames.
pub(crate) struct SocketTransport {
    path: String,
    next_id: AtomicU64,
    credential: Option<String>,
}

impl SocketTransport {
    pub(crate) fn new(path: &str, credential: Option<String>) -> Self {
        Self {
            path: path.to_string(),
            next_id: AtomicU64::new(1),
            credential,
        }
    }

    fn next_id(&self) -> String {
        format!("leshy-{}", self.next_id.fetch_add(1, Ordering::Relaxed))
    }
}

#[async_trait]
impl ControlTransport for SocketTransport {
    async fn call(
        &self,
        method: &str,
        intent: Option<&LeshyRouteIntentWire>,
    ) -> Result<(Vec<String>, Option<LeshyRouteResultWire>)> {
        let request = ControlRequest {
            version: API_VERSION,
            id: self.next_id(),
            method: method.to_string(),
            leshy_route: intent.cloned(),
            privileged_auth: self.credential.clone(),
        };

        let io = async {
            let mut conn = connect(&self.path).await?;
            write_frame(&mut conn, &request).await?;
            let response: ControlResponse = read_frame(&mut conn).await?;
            anyhow::Ok(response)
        };

        let response = tokio::time::timeout(CALL_TIMEOUT, io)
            .await
            .map_err(|_| anyhow::anyhow!("kikimora call {method} timed out"))??;

        if !response.ok {
            bail!("kikimora {method} failed: {}", response.error);
        }
        Ok((response.capabilities, response.leshy_route))
    }
}

#[cfg(unix)]
async fn connect(path: &str) -> Result<tokio::net::UnixStream> {
    Ok(tokio::net::UnixStream::connect(path).await?)
}

#[cfg(not(unix))]
async fn connect(_path: &str) -> Result<tokio::net::TcpStream> {
    // Managed mode is Linux/macOS-only until Kikimora ships a Windows named
    // pipe transport; the error keeps the type checking out.
    bail!("the Kikimora managed backend currently requires a Unix control socket")
}

// ---------------------------------------------------------------------------
// Framing (4-byte big-endian length prefix + JSON, mirroring the controller)
// ---------------------------------------------------------------------------

async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: AsyncWriteExt + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(value).context("encode control frame")?;
    if payload.is_empty() || payload.len() > MAX_FRAME {
        bail!("control frame size {} out of range", payload.len());
    }
    let header = (payload.len() as u32).to_be_bytes();
    writer.write_all(&header).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frame<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncReadExt + Unpin,
    T: DeserializeOwned,
{
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME {
        bail!("invalid control frame size {size}");
    }
    let mut payload = vec![0u8; size];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload).context("decode control frame")
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

pub(crate) struct KikimoraRouteBackend {
    transport: Box<dyn ControlTransport>,
    invalidation_rx: Mutex<Option<mpsc::UnboundedReceiver<RouteInvalidation>>>,
    /// Keeps the subscription pump alive for real transports.
    _pump: Option<tokio::task::JoinHandle<()>>,
}

/// Loads the privileged bearer credential (08D1 §31.6): the file holds
/// exactly 64 lowercase hex characters plus one trailing newline. A
/// configured but unreadable/malformed file fails managed startup closed —
/// there is no local-writer fallback.
pub(crate) fn load_auth_credential(path: Option<&str>) -> Result<Option<String>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read kikimora auth file {path}: {e}"))?;
    let text = raw
        .strip_suffix(char::from(0x0a))
        .ok_or_else(|| anyhow::anyhow!("kikimora auth file {path} must end with one newline"))?;
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("kikimora auth file {path} must hold 64 lowercase hex characters");
    }
    Ok(Some(text.to_string()))
}

impl KikimoraRouteBackend {
    /// Production constructor: real socket transport plus the subscription
    /// pump that invalidates registry entries on controller generation
    /// changes and marks authority unknown on socket loss. A configured
    /// auth file is loaded before any route call; failure is fatal.
    pub(crate) fn new(socket_path: &str, auth_file: Option<&str>) -> Result<Self> {
        let credential = load_auth_credential(auth_file)?;
        let (tx, rx) = mpsc::unbounded_channel();
        let pump_socket = socket_path.to_string();
        let pump = tokio::spawn(async move {
            subscription_pump(pump_socket, tx).await;
        });
        Ok(Self::with_parts(
            Box::new(SocketTransport::new(socket_path, credential)),
            Mutex::new(Some(rx)),
            Some(pump),
        ))
    }

    /// Test constructor around a scripted transport. The invalidation stream
    /// has no live sender, so the monitor sees a closed channel immediately.
    #[cfg(test)]
    pub(crate) fn with_test_transport(transport: Box<dyn ControlTransport>) -> Self {
        let (_tx, rx) = mpsc::unbounded_channel();
        Self::with_parts(transport, Mutex::new(Some(rx)), None)
    }

    fn with_parts(
        transport: Box<dyn ControlTransport>,
        invalidation_rx: Mutex<Option<mpsc::UnboundedReceiver<RouteInvalidation>>>,
        pump: Option<tokio::task::JoinHandle<()>>,
    ) -> Self {
        Self {
            transport,
            invalidation_rx,
            _pump: pump,
        }
    }

    fn wire_intent(intent: &RouteIntent) -> LeshyRouteIntentWire {
        LeshyRouteIntentWire {
            zone: intent.zone.clone(),
            prefix: format!(
                "{}/{}",
                intent.key.prefix.network, intent.key.prefix.prefix_len
            ),
            source: match intent.source {
                RouteSource::Dns => "dns".to_string(),
                RouteSource::Static => "static".to_string(),
            },
        }
    }

    fn map_result(result: LeshyRouteResultWire) -> Result<EnsureOutcome> {
        match result.state.as_str() {
            "applied" => Ok(EnsureOutcome::Added),
            "already-applied" => Ok(EnsureOutcome::AlreadyMatching),
            "denied" => Err(anyhow::anyhow!(ControllerDenied {
                // The controller's own marker wins: a family-not-ready
                // denial is the family-suppression contract.
                reason: result.reason.clone().unwrap_or_else(|| {
                    format!(
                        "role '{}' generation {} refused {}",
                        result.role, result.generation, result.prefix
                    )
                }),
            })),
            "conflict" => Err(anyhow::anyhow!(RouteConflict {
                prefix: result.prefix.clone(),
                owner: format!("role '{}'", result.role),
            })),
            other => bail!("kikimora returned an unknown route state '{other}'"),
        }
    }
}

#[async_trait]
impl RouteBackend for KikimoraRouteBackend {
    async fn resolve_target(
        &self,
        zone: &ZoneConfig,
        family: AddressFamily,
    ) -> Result<RouteTarget> {
        // Family policy is still enforced locally: a disabled family must
        // not even reach the controller.
        if !zone.family_enabled(family) {
            bail!(
                "zone '{}': {family:?} routing is disabled for this zone",
                zone.name
            );
        }
        // The controller derives the real next hop from its own authoritative
        // role state; Leshy deliberately does not name a gateway, interface,
        // table or metric. The synthetic device target exists only for the
        // registry's equality checks and never reaches a kernel write.
        Ok(RouteTarget::Device {
            name: format!("kikimora:{}", zone.name),
            ifindex: None,
        })
    }

    async fn ensure_route(&self, intent: &RouteIntent) -> Result<EnsureOutcome> {
        let wire = Self::wire_intent(intent);
        let (_, result) = self.transport.call("EnsureLeshyRoute", Some(&wire)).await?;
        let Some(result) = result else {
            bail!("kikimora EnsureLeshyRoute returned no route result");
        };
        tracing::debug!(
            zone = result.zone,
            prefix = result.prefix,
            generation = result.generation,
            state = result.state,
            "Kikimora route verdict"
        );
        Self::map_result(result)
    }

    async fn remove_route(&self, intent: &RouteIntent) -> Result<()> {
        let wire = Self::wire_intent(intent);
        self.transport.call("ForgetLeshyRoute", Some(&wire)).await?;
        Ok(())
    }

    async fn snapshot(&self) -> Result<Vec<ObservedRoute>> {
        // The controller is the writer and verifies its own rows; its verdict
        // on every Ensure/Forget is the observation. A reconcile therefore
        // re-asks the controller per dirty entry, which answers
        // idempotently.
        Ok(Vec::new())
    }

    fn take_invalidation_receiver(&self) -> Option<mpsc::UnboundedReceiver<RouteInvalidation>> {
        self.invalidation_rx.try_lock().ok()?.take()
    }
}

// ---------------------------------------------------------------------------
// Subscription pump
// ---------------------------------------------------------------------------

/// Long-lived subscription loop: on every controller generation change for a
/// zone the matching registry entries are invalidated; on any socket loss the
/// whole registry's authority is marked unknown. Reconnects with bounded
/// backoff, never falling back to the local writer.
async fn subscription_pump(socket_path: String, tx: mpsc::UnboundedSender<RouteInvalidation>) {
    let mut backoff = RECONNECT_MIN;
    loop {
        let started = tokio::time::Instant::now();
        match subscription_session(&socket_path, &tx).await {
            Ok(()) => tracing::debug!("Kikimora subscription ended"),
            Err(e) => tracing::debug!(error = %e, "Kikimora subscription lost"),
        }
        // Socket loss: every entry's authority is now unknown.
        let _ = tx.send(RouteInvalidation::Full);
        if started.elapsed() >= Duration::from_secs(60) {
            backoff = RECONNECT_MIN;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
    }
}

/// One subscription session: handshake, capability gate, then snapshot
/// frames. Returns Ok only when the connection ends cleanly.
async fn subscription_session(
    socket_path: &str,
    tx: &mpsc::UnboundedSender<RouteInvalidation>,
) -> Result<()> {
    let mut conn = connect(socket_path).await?;

    // Handshake and capability gate.
    write_frame(
        &mut conn,
        &ControlRequest {
            version: API_VERSION,
            id: "leshy-sub-handshake".to_string(),
            method: "Handshake".to_string(),
            leshy_route: None,
            privileged_auth: None,
        },
    )
    .await?;
    let handshake: ControlResponse = read_frame(&mut conn).await?;
    if !handshake.ok {
        bail!("kikimora handshake failed: {}", handshake.error);
    }
    if !handshake
        .capabilities
        .iter()
        .any(|c| c == MANAGED_CAPABILITY)
    {
        bail!(
            "kikimora does not advertise {MANAGED_CAPABILITY}; managed mode stays inactive \
             (never falls back to the local writer)"
        );
    }

    // Subscribe: every material controller state change arrives as a frame.
    write_frame(
        &mut conn,
        &ControlRequest {
            version: API_VERSION,
            id: "leshy-sub".to_string(),
            method: "Subscribe".to_string(),
            leshy_route: None,
            privileged_auth: None,
        },
    )
    .await?;

    let mut generations: HashMap<String, u64> = HashMap::new();
    loop {
        let response: ControlResponse = read_frame(&mut conn).await?;
        if !response.ok {
            bail!("kikimora subscription failed: {}", response.error);
        }
        let Some(snapshot) = response.snapshot else {
            continue;
        };
        for invalidation in snapshot_invalidations(&mut generations, &snapshot) {
            let _ = tx.send(invalidation);
        }
    }
}

/// Pure core of the pump: given the previous per-role generations and a fresh
/// controller snapshot, decide the invalidations and advance the map.
///
/// The controller bumps the generation on every change that makes the
/// previous routes stale (transport generation, ifindex, family readiness,
/// freeze/withdraw cycles). A role with a zone invalidates just that zone;
/// anything unattributable invalidates everything.
fn snapshot_invalidations(
    generations: &mut HashMap<String, u64>,
    snapshot: &CoreSnapshot,
) -> Vec<RouteInvalidation> {
    let mut out = Vec::new();
    for role in &snapshot.roles {
        let Some(publication) = &role.publication else {
            continue;
        };
        let changed = match publication.generation {
            Some(gen) => generations.insert(role.id.clone(), gen) != Some(gen),
            None => false,
        };
        if !changed {
            continue;
        }
        match &publication.zone {
            Some(zone) if !zone.is_empty() => out.push(RouteInvalidation::Zone(zone.clone())),
            _ => out.push(RouteInvalidation::Full),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Tests: scripted transport + protocol fixtures
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::sync::Mutex;

    /// Scripted controller for tests. Records every request so the trust
    /// boundary (only zone/prefix/source) can be asserted on the wire.
    pub(crate) struct FakeTransport {
        requests: Mutex<Vec<ControlRequest>>,
        response: Mutex<Option<ControlResponse>>,
        /// Per-family overrides: a real controller denies one family while
        /// applying the other.
        by_family: Mutex<std::collections::HashMap<u8, ControlResponse>>,
        /// Credential the fake records into every request, mirroring what a
        /// real SocketTransport loads from the auth file.
        credential: Mutex<Option<String>>,
    }

    impl FakeTransport {
        pub(crate) fn new() -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                response: Mutex::new(None),
                by_family: Mutex::new(std::collections::HashMap::new()),
                credential: Mutex::new(None),
            }
        }

        /// Point the fake at a credential so request recording exercises the
        /// privileged_auth field.
        pub(crate) fn set_credential(&self, credential: Option<String>) {
            *self.credential.lock().unwrap() = credential;
        }

        /// Script the verdict for one address family only.
        pub(crate) fn set_result_for_family(&self, family: u8, result: LeshyRouteResultWire) {
            let response = ControlResponse {
                ok: true,
                error: String::new(),
                capabilities: vec![MANAGED_CAPABILITY.to_string()],
                leshy_route: Some(result),
                snapshot: None,
            };
            self.by_family.lock().unwrap().insert(family, response);
        }

        pub(crate) fn set_result(&self, result: LeshyRouteResultWire) {
            *self.response.lock().unwrap() = Some(ControlResponse {
                ok: true,
                error: String::new(),
                capabilities: vec![MANAGED_CAPABILITY.to_string()],
                leshy_route: Some(result),
                snapshot: None,
            });
        }

        pub(crate) fn set_error(&self, error: &str) {
            *self.response.lock().unwrap() = Some(ControlResponse {
                ok: false,
                error: error.to_string(),
                capabilities: vec![],
                leshy_route: None,
                snapshot: None,
            });
        }

        pub(crate) fn requests(&self) -> Vec<ControlRequest> {
            self.requests.lock().unwrap().clone()
        }

        /// Snapshot of the recorded requests for wire-shape assertions.
        pub(crate) fn recorded_requests(&self) -> Vec<ControlRequest> {
            self.requests.lock().unwrap().clone()
        }

        pub(crate) fn call_count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }
    }

    impl Default for FakeTransport {
        fn default() -> Self {
            Self::new()
        }
    }

    #[async_trait]
    impl ControlTransport for FakeTransport {
        async fn call(
            &self,
            method: &str,
            intent: Option<&LeshyRouteIntentWire>,
        ) -> Result<(Vec<String>, Option<LeshyRouteResultWire>)> {
            self.requests.lock().unwrap().push(ControlRequest {
                version: API_VERSION,
                id: "test".to_string(),
                method: method.to_string(),
                leshy_route: intent.cloned(),
                privileged_auth: self.credential.lock().unwrap().clone(),
            });
            // Family-scoped scripts win: a real controller answers per family.
            if let Some(intent) = intent {
                let family = if intent.prefix.contains(':') { 6 } else { 4 };
                if let Some(response) = self.by_family.lock().unwrap().get(&family) {
                    if response.ok {
                        return Ok((response.capabilities.clone(), response.leshy_route.clone()));
                    }
                    return Err(anyhow::anyhow!(
                        "kikimora {method} failed: {}",
                        response.error
                    ));
                }
            }
            match self.response.lock().unwrap().clone() {
                Some(response) if response.ok => Ok((response.capabilities, response.leshy_route)),
                Some(response) => bail!("kikimora {method} failed: {}", response.error),
                None => bail!("kikimora transport offline"),
            }
        }
    }

    /// Shared-handle adapter so a test keeps its assertions while the backend
    /// owns the trait object.
    #[async_trait]
    impl ControlTransport for std::sync::Arc<FakeTransport> {
        async fn call(
            &self,
            method: &str,
            intent: Option<&LeshyRouteIntentWire>,
        ) -> Result<(Vec<String>, Option<LeshyRouteResultWire>)> {
            self.as_ref().call(method, intent).await
        }
    }

    /// Protocol fixture: the exact verdict shape API v3 returns.
    pub(crate) fn applied_result(prefix: &str, family: u8) -> LeshyRouteResultWire {
        LeshyRouteResultWire {
            role: "primary".to_string(),
            zone: "corp".to_string(),
            prefix: prefix.to_string(),
            family,
            generation: 7,
            state: "applied".to_string(),
            reason: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::{applied_result, FakeTransport};
    use super::*;
    use crate::config::{DnsProtocol, RouteType, ZoneMode};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    fn via_zone() -> ZoneConfig {
        ZoneConfig {
            name: "corp".to_string(),
            mode: ZoneMode::Inclusive,
            dns_servers: vec![],
            route_type: RouteType::Via,
            route_target: "192.168.1.1".to_string(),
            route_target_ipv6: None,
            domains: vec!["corp.example.com".to_string()],
            patterns: vec![],
            static_routes: vec![],
            dns_protocol: DnsProtocol::Udp,
            cache_min_ttl: None,
            cache_max_ttl: None,
            cache_negative_ttl: None,
            ipv6: false,
        }
    }

    fn host_intent(ip: IpAddr, zone: &str) -> RouteIntent {
        RouteIntent {
            key: crate::routing::RouteKey {
                prefix: crate::routing::RoutePrefix::host(ip),
                table: 254,
            },
            zone: zone.to_string(),
            target: RouteTarget::Device {
                name: format!("kikimora:{zone}"),
                ifindex: None,
            },
            source: RouteSource::Dns,
        }
    }

    #[tokio::test]
    async fn applied_state_maps_to_added() {
        let transport = Arc::new(FakeTransport::new());
        transport.set_result(applied_result("10.0.0.1/32", 4));
        let backend = KikimoraRouteBackend::with_test_transport(Box::new(Arc::clone(&transport)));

        let intent = host_intent(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), "corp");
        let outcome = backend.ensure_route(&intent).await.unwrap();
        assert_eq!(outcome, EnsureOutcome::Added);
    }

    #[tokio::test]
    async fn already_applied_state_maps_to_already_matching() {
        let transport = Arc::new(FakeTransport::new());
        let mut result = applied_result("10.0.0.1/32", 4);
        result.state = "already-applied".to_string();
        transport.set_result(result);
        let backend = KikimoraRouteBackend::with_test_transport(Box::new(Arc::clone(&transport)));

        let intent = host_intent(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), "corp");
        let outcome = backend.ensure_route(&intent).await.unwrap();
        assert_eq!(outcome, EnsureOutcome::AlreadyMatching);
    }

    #[tokio::test]
    async fn denied_state_classifies_as_authority_denied() {
        let transport = Arc::new(FakeTransport::new());
        let mut result = applied_result("10.0.0.1/32", 4);
        result.state = "denied".to_string();
        transport.set_result(result);
        let backend = KikimoraRouteBackend::with_test_transport(Box::new(Arc::clone(&transport)));

        let intent = host_intent(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), "corp");
        let err = backend.ensure_route(&intent).await.unwrap_err();
        assert!(err.downcast_ref::<ControllerDenied>().is_some());
    }

    #[tokio::test]
    async fn conflict_state_classifies_as_route_conflict() {
        let transport = Arc::new(FakeTransport::new());
        let mut result = applied_result("10.0.0.1/32", 4);
        result.state = "conflict".to_string();
        transport.set_result(result);
        let backend = KikimoraRouteBackend::with_test_transport(Box::new(Arc::clone(&transport)));

        let intent = host_intent(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), "corp");
        let err = backend.ensure_route(&intent).await.unwrap_err();
        assert!(err.downcast_ref::<RouteConflict>().is_some());
    }

    #[tokio::test]
    async fn transport_error_is_an_ordinary_apply_error() {
        let transport = Arc::new(FakeTransport::new());
        transport.set_error("socket unavailable");
        let backend = KikimoraRouteBackend::with_test_transport(Box::new(Arc::clone(&transport)));

        let intent = host_intent(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), "corp");
        let err = backend.ensure_route(&intent).await.unwrap_err();
        // Not a safety denial: the legacy failure mode may apply.
        assert!(err.downcast_ref::<ControllerDenied>().is_none());
        assert!(err.downcast_ref::<RouteConflict>().is_none());
    }

    #[tokio::test]
    async fn requests_carry_only_zone_prefix_and_source() {
        let transport = Arc::new(FakeTransport::new());
        transport.set_result(applied_result("10.0.0.1/32", 4));
        let backend = KikimoraRouteBackend::with_test_transport(Box::new(Arc::clone(&transport)));

        let intent = host_intent(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), "corp");
        backend.ensure_route(&intent).await.unwrap();

        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "EnsureLeshyRoute");
        assert_eq!(requests[0].version, API_VERSION);
        let wire = requests[0].leshy_route.as_ref().unwrap();
        let encoded = serde_json::to_value(wire).unwrap();
        let mut keys: Vec<&str> = encoded
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["prefix", "source", "zone"]);
        assert_eq!(encoded["source"], "dns");
        // No gateway, interface, ifindex, table, metric, protocol anywhere.
        let raw = serde_json::to_string(wire).unwrap();
        for forbidden in [
            "gateway",
            "interface",
            "ifindex",
            "table",
            "metric",
            "protocol",
        ] {
            assert!(!raw.contains(forbidden), "{forbidden} must not be sent");
        }
    }

    #[tokio::test]
    async fn static_source_is_labelled_on_the_wire() {
        let transport = Arc::new(FakeTransport::new());
        transport.set_result(applied_result("10.0.0.0/8", 4));
        let backend = KikimoraRouteBackend::with_test_transport(Box::new(Arc::clone(&transport)));

        let mut intent = host_intent(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), "corp");
        intent.key.prefix =
            crate::routing::RoutePrefix::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).unwrap();
        intent.source = RouteSource::Static;
        backend.ensure_route(&intent).await.unwrap();

        let requests = transport.requests();
        let encoded = serde_json::to_value(requests[0].leshy_route.as_ref().unwrap()).unwrap();
        assert_eq!(encoded["source"], "static");
        assert_eq!(encoded["prefix"], "10.0.0.0/8");
    }

    #[tokio::test]
    async fn disabled_family_never_reaches_the_controller() {
        let transport = Arc::new(FakeTransport::new());
        let backend = KikimoraRouteBackend::with_test_transport(Box::new(Arc::clone(&transport)));

        // The zone is IPv4-only; an IPv6 intent is refused locally.
        let err = backend
            .resolve_target(&via_zone(), AddressFamily::V6)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("disabled"));
        assert_eq!(transport.call_count(), 0);
    }

    #[tokio::test]
    async fn forget_forwards_to_the_controller() {
        let transport = Arc::new(FakeTransport::new());
        transport.set_result(applied_result("10.0.0.1/32", 4));
        let backend = KikimoraRouteBackend::with_test_transport(Box::new(Arc::clone(&transport)));

        let intent = host_intent(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), "corp");
        backend.remove_route(&intent).await.unwrap();
        let requests = transport.requests();
        assert_eq!(requests[0].method, "ForgetLeshyRoute");
    }

    #[tokio::test]
    async fn registry_classifies_controller_denial_as_authority_denied() {
        let transport = Arc::new(FakeTransport::new());
        let mut result = applied_result("10.0.0.1/32", 4);
        result.state = "denied".to_string();
        transport.set_result(result);
        let backend = KikimoraRouteBackend::with_test_transport(Box::new(Arc::clone(&transport)));

        let mgr = crate::routing::RouteManager::with_backend(
            Arc::new(backend),
            None,
            crate::routing::DEFAULT_MAX_DYNAMIC_ROUTES,
        );
        let zone = via_zone();
        let err = mgr
            .add_route(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &zone)
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "route authority denied by the controller: role 'primary' generation 7 refused 10.0.0.1/32"
        );
    }

    #[test]
    fn wire_types_round_trip_like_the_go_api() {
        let result = LeshyRouteResultWire {
            role: "primary".to_string(),
            zone: "corp".to_string(),
            prefix: "2001:db8::1/128".to_string(),
            family: 6,
            generation: 7,
            state: "applied".to_string(),
            reason: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"role\":\"primary\""));
        assert!(json.contains("\"family\":6"));
        assert!(json.contains("\"generation\":7"));
        assert!(json.contains("\"state\":\"applied\""));
        let decoded: LeshyRouteResultWire = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, result);
    }

    #[test]
    fn snapshot_frames_decode_leniently() {
        // Generation changes drive zone invalidation; unknown fields are
        // ignored and absent publication entries are skipped.
        let frame = r#"{"roles":[
            {"id":"primary","state":"active","publication":{"published":true,"zone":"corp","generation":9}},
            {"id":"secondary","state":"idle"}
        ]}"#;
        let snapshot: CoreSnapshot = serde_json::from_str(frame).unwrap();
        assert_eq!(snapshot.roles.len(), 2);
        let publication = snapshot.roles[0].publication.as_ref().unwrap();
        assert_eq!(publication.zone.as_deref(), Some("corp"));
        assert_eq!(publication.generation, Some(9));
        assert!(snapshot.roles[1].publication.is_none());
    }

    #[tokio::test]
    async fn frame_round_trip_matches_the_go_framing() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let value = applied_result("10.0.0.1/32", 4);
        let expected = value.clone();

        let writer = tokio::spawn(async move {
            write_frame(&mut client, &value).await.unwrap();
        });

        // The controller side reads with the same framing rules.
        let mut header = [0u8; 4];
        server.read_exact(&mut header).await.unwrap();
        let size = u32::from_be_bytes(header) as usize;
        let mut payload = vec![0u8; size];
        server.read_exact(&mut payload).await.unwrap();
        let decoded: LeshyRouteResultWire = serde_json::from_slice(&payload).unwrap();

        writer.await.unwrap();
        assert_eq!(decoded, expected);
    }

    /// The synthetic controller target must never collide with a real
    /// interface name used by a dev zone.
    #[test]
    fn synthetic_target_names_the_controller() {
        let target = RouteTarget::Device {
            name: "kikimora:corp".to_string(),
            ifindex: None,
        };
        let rendered = format!("{target:?}");
        assert!(rendered.contains("kikimora"));
    }

    #[test]
    fn generation_change_invalidates_the_zone() {
        let mut generations = HashMap::new();
        generations.insert("primary".to_string(), 9);
        let snapshot: CoreSnapshot = serde_json::from_str(
            r#"{"roles":[{"id":"primary","publication":{"zone":"primary","generation":10}}]}"#,
        )
        .unwrap();
        let out = snapshot_invalidations(&mut generations, &snapshot);
        assert_eq!(out, vec![RouteInvalidation::Zone("primary".to_string())]);
        // The map advanced: the same generation again is a no-op.
        let out = snapshot_invalidations(&mut generations, &snapshot);
        assert!(out.is_empty());
    }

    #[test]
    fn generation_change_without_a_zone_invalidates_everything() {
        let mut generations = HashMap::new();
        let snapshot: CoreSnapshot = serde_json::from_str(
            r#"{"roles":[{"id":"secondary","publication":{"published":true,"generation":3}}]}"#,
        )
        .unwrap();
        let out = snapshot_invalidations(&mut generations, &snapshot);
        assert_eq!(out, vec![RouteInvalidation::Full]);
    }

    #[test]
    fn first_snapshot_invalidates_once_then_settles() {
        // A fresh pump has no generation memory: the first snapshot marks the
        // role stale once (a restarted Leshy must not trust stale Verified
        // entries), and every following identical snapshot is a no-op.
        let mut generations = HashMap::new();
        let snapshot: CoreSnapshot = serde_json::from_str(
            r#"{"roles":[{"id":"primary","publication":{"zone":"primary","generation":5}}]}"#,
        )
        .unwrap();
        let out = snapshot_invalidations(&mut generations, &snapshot);
        assert_eq!(out, vec![RouteInvalidation::Zone("primary".to_string())]);
        assert!(snapshot_invalidations(&mut generations, &snapshot).is_empty());
    }

    #[test]
    fn roles_without_publication_are_skipped() {
        let mut generations = HashMap::new();
        let snapshot: CoreSnapshot =
            serde_json::from_str(r#"{"roles":[{"id":"idle"},{"id":"empty","publication":{}}]}"#)
                .unwrap();
        assert!(snapshot_invalidations(&mut generations, &snapshot).is_empty());
    }

    #[test]
    fn frame_rejects_a_zero_size_header() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let (mut client, mut server) = tokio::io::duplex(64);
            client.write_all(&[0, 0, 0, 0]).await.unwrap();
            drop(client);
            let err = read_frame::<_, LeshyRouteResultWire>(&mut server)
                .await
                .unwrap_err();
            assert!(err.to_string().contains("invalid control frame size 0"));
        });
    }
}

#[cfg(test)]
mod auth_tests {
    use super::*;

    #[test]
    fn loads_valid_credential_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control-route-auth.key");
        std::fs::write(&path, format!("{}\n", "a".repeat(64))).unwrap();
        let credential = load_auth_credential(Some(path.to_str().unwrap())).unwrap();
        assert_eq!(credential.as_deref(), Some("a".repeat(64).as_str()));
    }

    #[test]
    fn absent_configuration_carries_no_credential() {
        assert_eq!(load_auth_credential(None).unwrap(), None);
    }

    #[test]
    fn missing_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.key");
        assert!(load_auth_credential(Some(path.to_str().unwrap())).is_err());
    }

    #[test]
    fn malformed_files_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        for bad in [
            "short\n".to_string(),
            format!("{}\n", "A".repeat(64)), // uppercase is not the on-disk form
            "a".repeat(64),                  // missing trailing newline
            format!("{}x\n", "a".repeat(63)), // not hex
        ] {
            let path = dir.path().join("bad.key");
            std::fs::write(&path, bad).unwrap();
            assert!(
                load_auth_credential(Some(path.to_str().unwrap())).is_err(),
                "malformed credential must fail managed startup closed"
            );
        }
    }

    #[test]
    fn wire_carries_the_token_only_when_present() {
        let with = serde_json::to_string(&ControlRequest {
            version: API_VERSION,
            id: "t1".into(),
            method: "EnsureLeshyRoute".into(),
            leshy_route: None,
            privileged_auth: Some("a".repeat(64)),
        })
        .unwrap();
        assert!(
            with.contains("privileged_auth"),
            "token must travel: {with}"
        );

        let without = serde_json::to_string(&ControlRequest {
            version: API_VERSION,
            id: "t2".into(),
            method: "Handshake".into(),
            leshy_route: None,
            privileged_auth: None,
        })
        .unwrap();
        assert!(
            !without.contains("privileged_auth"),
            "unconfigured installs keep the legacy wire shape: {without}"
        );
    }
}

#[cfg(test)]
mod auth_wire_tests {
    use super::fake::{applied_result, FakeTransport};
    use super::KikimoraRouteBackend;
    use crate::routing::backend::{fake::host_intent_v4, RouteBackend};
    use std::sync::Arc;

    #[tokio::test]
    async fn ensure_request_records_the_bearer_credential() {
        let transport = Arc::new(FakeTransport::new());
        transport.set_result(applied_result("10.0.0.1/32", 4));
        transport.set_credential(Some("a".repeat(64)));
        let backend = KikimoraRouteBackend::with_test_transport(Box::new(Arc::clone(&transport)));

        let intent = host_intent_v4(10, 0, 0, 1, "corp");
        backend.ensure_route(&intent).await.unwrap();

        let requests = transport.recorded_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].privileged_auth.as_deref(),
            Some("a".repeat(64).as_str()),
            "privileged requests must carry the service credential"
        );
    }

    #[tokio::test]
    async fn ensure_request_without_credential_keeps_legacy_shape() {
        let transport = Arc::new(FakeTransport::new());
        transport.set_result(applied_result("10.0.0.1/32", 4));
        let backend = KikimoraRouteBackend::with_test_transport(Box::new(Arc::clone(&transport)));

        let intent = host_intent_v4(10, 0, 0, 1, "corp");
        backend.ensure_route(&intent).await.unwrap();

        let requests = transport.recorded_requests();
        assert_eq!(requests[0].privileged_auth, None);
    }
}
