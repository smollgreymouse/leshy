use crate::config::Config;
use crate::dns::{DnsHandler, DnsServer};
use crate::reload::{diff_zones, ConfigWatcher, ZoneChange};
use crate::zones::ZoneMatcher;
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

    // (1) Build and validate the new matcher first: a broken config must
    // never retire the old routes.
    let new_matcher = ZoneMatcher::new(new_config.zones.clone())?;
    let changes = diff_zones(&old_config.zones, &new_config.zones);

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
    for change in &changes {
        if let ZoneChange::Removed(old) = change {
            tracing::info!(zone = old.name, "Removing zone and cleaning up routes");
            if let Err(e) = handler_guard.cleanup_zone(&old.name).await {
                tracing::error!(zone = old.name, error = %e, "Failed to cleanup zone");
            }
        }
    }
    for intents in &old_intents {
        handler_guard.retire_zone_intents(intents).await;
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

    // (7) Mark affected registry entries dirty and run one reconcile.
    handler_guard.reconcile_routes_after_reload().await;

    tracing::info!(
        changes = changes.len(),
        total_zones = new_config.zones.len(),
        "Configuration applied successfully"
    );
    Ok(())
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
