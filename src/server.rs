use crate::config::{Config, ServerConfig};
use crate::dns::{DnsHandler, DnsServer};
use crate::reload::{diff_zones, ConfigWatcher, ZoneChange};
use crate::zones::ZoneMatcher;
use anyhow::Context;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

/// Initialize console (stdout) logging for CLI runs. Service mode installs a
/// file-based subscriber instead.
pub fn init_console_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
}

/// Default config search paths, used when no --config argument is given.
/// The last entry is the fallback path reported when nothing exists.
pub fn default_config_candidates() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let mut candidates = vec![
            PathBuf::from("leshy.toml"),  // Current directory
            PathBuf::from("config.toml"), // Current directory
            PathBuf::from(r"C:\ProgramData\leshy\config.toml"),
        ];
        if let Ok(appdata) = std::env::var("APPDATA") {
            candidates.push(PathBuf::from(appdata).join(r"leshy\config.toml"));
        }
        candidates
            .into_iter()
            .find(|p| p.exists())
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\leshy\config.toml"))
    }

    #[cfg(not(target_os = "windows"))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        let candidates = vec![
            PathBuf::from("leshy.toml"),  // Current directory
            PathBuf::from("config.toml"), // Current directory
            PathBuf::from(format!("{home}/.config/leshy/config.toml")),
            PathBuf::from("/etc/leshy/config.toml"),
        ];

        candidates
            .into_iter()
            .find(|p| p.exists())
            .unwrap_or_else(|| PathBuf::from("/etc/leshy/config.toml"))
    }
}

/// Load the configuration, start the DNS server, and run until the returned
/// future is dropped or the process exits.
pub async fn run_server(config_arg: Option<PathBuf>) -> anyhow::Result<()> {
    let config_path = config_arg.unwrap_or_else(default_config_candidates);

    tracing::info!(config_path = ?config_path, "Loading configuration");

    // Load configuration (includes config.d directory if present)
    let config = Config::from_file_with_includes(&config_path)?;
    let auto_reload = config.server.auto_reload;

    // Process-lifetime writer fence (08D1 §31.2): taken before RouteManager
    // construction, DNS binding, or any route mutation. Held for the whole
    // run; a second Leshy on the same generated installation fails here.
    let _writer_lease = crate::lease::WriterLease::acquire_optional(
        config
            .server
            .writer_lock
            .as_ref()
            .map(std::path::PathBuf::from)
            .as_deref(),
    )?;

    tracing::info!(
        listen = %config.server.listen_address,
        zones = config.zones.len(),
        auto_reload = auto_reload,
        "Configuration loaded"
    );

    // Create zone matcher
    let matcher = ZoneMatcher::new(config.zones.clone())?;

    // Create DNS handler (wrapped in Arc for reload)
    let handler = Arc::new(RwLock::new(DnsHandler::new(config.clone(), matcher)?));

    // Apply static routes (and spawn retry loop for dev zones where VPN may not be up yet)
    {
        let handler_guard = handler.read().await;
        let failures = handler_guard.apply_static_routes().await;
        if failures > 0 && handler_guard.has_static_routes() {
            let handler_retry = handler.clone();
            tokio::spawn(async move {
                retry_static_routes(handler_retry).await;
            });
        }
    }

    // Create and start DNS server
    let server = DnsServer::new(config.server.listen_address, handler.clone()).await?;

    tracing::info!("Leshy DNS server started");

    // Spawn config watcher if auto_reload is enabled
    if auto_reload {
        let config_dir = config.server.config_dir.as_ref().map(PathBuf::from);
        let (watcher, mut reload_rx) = ConfigWatcher::new(config_path.clone(), config_dir);

        // Spawn watcher task
        tokio::spawn(async move {
            if let Err(e) = watcher.watch().await {
                tracing::error!("Config watcher error: {}", e);
            }
        });

        // Spawn reload handler task
        let handler_for_reload = handler.clone();
        tokio::spawn(async move {
            while let Some(new_config) = reload_rx.recv().await {
                tracing::info!("Applying new configuration");

                if let Err(e) = apply_reload(&handler_for_reload, new_config).await {
                    tracing::error!(error = %e, "Failed to apply reload, keeping old config");
                }
            }
        });
    }

    // Run server
    server.run().await?;

    // Production Plan C2: exact local-owned cleanup on the ordinary exit path.
    // The timeout bounds shutdown; managed mode performs no RPC and no local
    // FIB mutation inside shutdown_routes.
    let cleanup = async {
        let handler_guard = handler.read().await;
        handler_guard.shutdown_routes().await
    };
    match tokio::time::timeout(std::time::Duration::from_secs(10), cleanup).await {
        Ok(Ok(removed)) => {
            tracing::info!(removed, "Shutdown route cleanup complete");
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "Shutdown route cleanup failed");
        }
        Err(_) => {
            tracing::error!("Shutdown route cleanup timed out after 10s");
        }
    }

    Ok(())
}

/// Apply one reload transaction against the running handler.
///
/// The handler write lock is the transaction boundary: no request observes a
/// half-applied configuration. The order follows the reconciliation plan:
/// build and validate the new state, add replacement rows, retire old-zone
/// owned rows only afterwards, swap config/matcher, then one dirty+reconcile.
pub async fn apply_reload(
    handler: &Arc<RwLock<DnsHandler>>,
    new_config: Config,
) -> anyhow::Result<()> {
    let mut handler_guard = handler.write().await;
    let old_config = handler_guard.config().clone();

    // (0) Routing-manager construction is restart-only (08D1 §19.1). Validate
    // before the matcher or any route retirement: a hot swap cannot rebuild
    // RouteManager, so these changes must be applied by a process restart.
    if routing_manager_restart_required(&old_config.server, &new_config.server) {
        anyhow::bail!(
            "routing manager configuration changed; restart Leshy to apply routing \
             backend/capacity changes"
        );
    }

    // (1) Build and validate the new matcher first: a broken config must
    // never retire the old routes.
    let new_matcher = ZoneMatcher::new(new_config.zones.clone())?;
    let changes = diff_zones(&old_config.zones, &new_config.zones);

    // Affected zones for the targeted reload invalidation, fixed before the
    // swap so it cannot observe half-applied state.
    let affected_zones = {
        let mut zones: Vec<String> = changes
            .iter()
            .map(|change| match change {
                ZoneChange::Added(zone) => zone.name.clone(),
                ZoneChange::Removed(zone) => zone.name.clone(),
                ZoneChange::Changed { new, .. } => new.name.clone(),
            })
            .collect();
        zones.sort();
        zones.dedup();
        zones
    };

    // Snapshot the owned intents of same-name changed zones before the new
    // state replaces them in the registry.
    let mut old_intents = Vec::new();
    for change in &changes {
        if let ZoneChange::Changed { old, .. } = change {
            old_intents.push(handler_guard.zone_route_intents(&old.name).await);
        }
    }

    // (2)+(3) Apply the new static/target state first, so replacement rows
    // exist before any old row is removed.
    for change in &changes {
        if let ZoneChange::Changed { new, .. } = change {
            let failures = handler_guard.apply_static_routes_for_zone(new).await;
            if failures > 0 {
                anyhow::bail!(
                    "zone '{}': {failures} new static route(s) failed to verify",
                    new.name
                );
            }
        }
    }

    // (4) Remove explicit old-zone owned rows. Removing a zone is operator
    // intent (full cleanup); a changed zone retires exactly its old intents,
    // and a replacement row on the same prefix is never deleted.
    //
    // 08D1 §19.1: any exact cleanup/retirement failure aborts the transaction.
    // The config, matcher and the ownership evidence stay as they were, and
    // the caller never sees a successful reload for a half-retired state.
    for change in &changes {
        if let ZoneChange::Removed(old) = change {
            tracing::info!(zone = old.name, "Removing zone and cleaning up routes");
            handler_guard
                .cleanup_zone(&old.name)
                .await
                .with_context(|| {
                    format!(
                        "removing zone '{}' failed; reload aborted before the config swap",
                        old.name
                    )
                })?;
        }
    }
    for intents in &old_intents {
        handler_guard
            .retire_zone_intents(intents)
            .await
            .with_context(|| {
                "retiring the previous zone routes failed; reload aborted before the config swap"
            })?;
    }

    // (5)+(6) Swap config/matcher; the DNS cache is cleared with it.
    handler_guard
        .update_config(new_config.clone(), new_matcher)
        .await?;

    // Static routes for added zones (and a re-assert of unchanged ones, free
    // through registry dedupe).
    let failures = handler_guard.apply_static_routes().await;
    if failures > 0 && handler_guard.has_static_routes() {
        let handler_retry = Arc::clone(handler);
        tokio::spawn(async move {
            retry_static_routes(handler_retry).await;
        });
    }

    // (7) Dirty exactly the affected zones and reconcile them. Ordinary
    // reload never emits a full-kernel invalidation (§19.2).
    handler_guard
        .reconcile_routes_after_reload(&affected_zones)
        .await;

    tracing::info!(
        changes = changes.len(),
        total_zones = new_config.zones.len(),
        "Configuration applied successfully"
    );
    Ok(())
}

/// Fields that define `RouteManager` construction cannot be hot-reloaded
/// (08D1 §19.1). The cutover orchestrator intentionally writes them while
/// Leshy is stopped and then restarts the process.
fn routing_manager_restart_required(old: &ServerConfig, new: &ServerConfig) -> bool {
    old.routing_backend != new.routing_backend
        || old.kikimora_socket != new.kikimora_socket
        || old.route_aggregation_prefix != new.route_aggregation_prefix
        || old.max_dynamic_routes != new.max_dynamic_routes
}

/// Retry applying static routes every 10 seconds until all succeed.
/// Handles the case where VPN device files don't exist yet at startup.
async fn retry_static_routes(handler: Arc<RwLock<DnsHandler>>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        let handler_guard = handler.read().await;
        let failures = handler_guard.apply_static_routes().await;
        if failures == 0 {
            tracing::info!("All static routes applied successfully");
            break;
        }
        tracing::debug!(
            pending = failures,
            "Some static routes still pending, will retry"
        );
    }
}
