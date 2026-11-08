//! Windows route API seam (08D1 §41.3).
//!
//! L12 uses the same injected seam pattern as Linux (KernelIo) and K15b
//! (WindowsRouteApi). Production code uses `RealWindowsRouteApi`; tests use
//! `FakeWindowsRouteApi`. This keeps the Windows codebase testable and allows
//! deterministic scripted errors.

use super::model::{AddressFamily, ObservedRoute, RouteIntent, RouteKernelIdentity, RouteKey, RouteTarget};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::collections::HashMap;

/// Windows route API seam. Production uses `RealWindowsRouteApi`.
#[async_trait]
pub trait WindowsRouteApi: Send + Sync {
    /// Resolve a device name to its interface index.
    async fn ifindex_of(&self, device: &str) -> Result<u32>;

    /// Enumerate all forwarding rows of a family.
    async fn dump_family(&self, family: AddressFamily) -> Result<Vec<ObservedRoute>>;

    /// Read back a single prefix (targeted read-back).
    async fn read_prefix(&self, key: &RouteKey) -> Result<Vec<ObservedRoute>>;

    /// Install a new route.
    async fn add(&self, intent: &RouteIntent) -> Result<()>;

    /// Replace an existing route (exact previous-owned only).
    async fn replace(&self, intent: &RouteIntent) -> Result<()>;

    /// Delete a route (exact owned only).
    async fn delete(&self, intent: &RouteIntent) -> Result<()>;

    /// Get the current interface names map.
    async fn link_names(&self) -> Result<HashMap<u32, String>>;
}

/// Real Windows API implementation.
pub struct RealWindowsRouteApi;

#[async_trait]
impl WindowsRouteApi for RealWindowsRouteApi {
    async fn ifindex_of(&self, device: &str) -> Result<u32> {
        super::windows::resolve_interface_index(device)
    }

    async fn dump_family(&self, family: AddressFamily) -> Result<Vec<ObservedRoute>> {
        super::windows::dump_family(family.into())
    }

    async fn read_prefix(&self, key: &RouteKey) -> Result<Vec<ObservedRoute>> {
        super::windows::read_prefix(key)
    }

    async fn add(&self, intent: &RouteIntent) -> Result<()> {
        super::windows::add_route(intent)
    }

    async fn replace(&self, intent: &RouteIntent) -> Result<()> {
        super::windows::replace_route(intent)
    }

    async fn delete(&self, intent: &RouteIntent) -> Result<()> {
        super::windows::delete_route(intent)
    }

    async fn link_names(&self) -> Result<HashMap<u32, String>> {
        super::windows::enumerate_adapters(AddressFamily::AF_INET)?
            .into_iter()
            .map(|(name, index)| (index, name))
            .collect()
    }
}

/// Fake Windows API for tests.
pub struct FakeWindowsRouteApi {
    state: std::sync::Mutex<FakeState>,
}

struct FakeState {
    rows: Vec<ObservedRoute>,
    names: HashMap<u32, String>,
    adds: Vec<RouteIntent>,
    replaces: Vec<RouteIntent>,
    deletes: Vec<RouteIntent>,
    force_read: Option<Vec<ObservedRoute>>,
}

impl FakeWindowsRouteApi {
    pub fn new(rows: Vec<ObservedRoute>) -> Self {
        let mut names = HashMap::new();
        names.insert(7u32, "tun0".to_string());
        Self {
            state: std::sync::Mutex::new(FakeState {
                rows,
                names,
                adds: Vec::new(),
                replaces: Vec::new(),
                deletes: Vec::new(),
                force_read: None,
            }),
        }
    }

    pub fn with_force_read(mut self, rows: Vec<ObservedRoute>) -> Self {
        self.state.get_mut().unwrap().force_read = Some(rows);
        self
    }

    pub fn bump_during_first_dump(mut self, generation: Arc<AtomicU64>) -> Self {
        self.state.get_mut().unwrap().bump_generation = Some(generation);
        self.state.get_mut().unwrap().bump_after_first_dump = true;
        self
    }

    pub fn adds(&self) -> Vec<RouteIntent> {
        self.state.lock().unwrap().adds.clone()
    }

    pub fn replaces(&self) -> Vec<RouteIntent> {
        self.state.lock().unwrap().replaces.clone()
    }

    pub fn deletes(&self) -> Vec<RouteIntent> {
        self.state.lock().unwrap().deletes.clone()
    }

    pub fn rows(&self) -> Vec<ObservedRoute> {
        self.state.lock().unwrap().rows.clone()
    }
}

use std::sync::Arc;

#[async_trait]
impl WindowsRouteApi for FakeWindowsRouteApi {
    async fn ifindex_of(&self, device: &str) -> Result<u32> {
        let state = self.state.lock().unwrap();
        state
            .names
            .iter()
            .find(|(_, name)| name == device)
            .map(|(index, _)| *index)
            .ok_or_else(|| anyhow::anyhow!("Device '{device}' not found"))
    }

    async fn dump_family(&self, _family: AddressFamily) -> Result<Vec<ObservedRoute>> {
        let state = self.state.lock().unwrap();
        Ok(state.rows.clone())
    }

    async fn read_prefix(&self, key: &RouteKey) -> Result<Vec<ObservedRoute>> {
        let mut state = self.state.lock().unwrap();
        if let Some(rows) = &state.force_read {
            return Ok(rows.clone());
        }
        Ok(state
            .rows
            .iter()
            .filter(|row| row.key == *key)
            .cloned()
            .collect())
    }

    async fn add(&self, intent: &RouteIntent) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.adds.push(intent.clone());
        if !state.rows.iter().any(|row| row.key == intent.key) {
            state.rows.push(synthesize(intent));
        }
        Ok(())
    }

    async fn replace(&self, intent: &RouteIntent) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.replaces.push(intent.clone());
        state.rows.retain(|row| row.key != intent.key);
        state.rows.push(synthesize(intent));
        Ok(())
    }

    async fn delete(&self, intent: &RouteIntent) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.deletes.push(intent.clone());
        state.rows.retain(|row| row.key != intent.key);
        Ok(())
    }

    async fn link_names(&self) -> Result<HashMap<u32, String>> {
        Ok(self.state.lock().unwrap().names.clone())
    }
}

fn synthesize(intent: &RouteIntent) -> ObservedRoute {
    let target = intent.target.clone();
    let (ifindex, next_hop, metric) = match &intent.target {
        RouteTarget::Device {
            ifindex: Some(index),
            ..
        } => (*index, None, 0),
        RouteTarget::Gateway(gateway) => {
            let idx = 7;
            (idx, Some(*gateway), 0)
        }
        _ => (7, None, 0),
    };

    ObservedRoute {
        key: intent.key.clone(),
        target,
        identity: RouteKernelIdentity {
            ifindex: Some(ifindex),
            next_hop,
            protocol: 3,
            metric,
            scope: 0,
            interface_luid: Some(0x1000000000000000u64),
        },
    }
}
