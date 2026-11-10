use crate::service::coordinator::{
    LifecycleCoordinator, LifecycleState, StatusReport, StatusSink, StopReason,
    GRACEFUL_STOP_TIMEOUT,
};
use anyhow::{Context, Result};
use std::os::raw::c_void;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;
use tracing_subscriber::EnvFilter;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceDependency, ServiceErrorControl,
    ServiceExitCode, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, SC_ACTION, SC_ACTION_RESTART, SERVICE_CONFIG_FAILURE_ACTIONS,
    SERVICE_FAILURE_ACTIONSW,
};

const SERVICE_DESCRIPTION: &str = "DNS-driven split-tunnel router";
/// Restart the service 5 seconds after a failure, matching the Linux unit's
/// `Restart=on-failure` / `RestartSec=5s`.
const FAILURE_DELAY_MS: u32 = 5000;
/// 0xFFFFFFFF = never reset the failure counter.
const FAILURE_RESET_PERIOD_INFINITE: u32 = 0xFFFF_FFFF;
/// Marker argument the Service Control Manager launch uses; checked before
/// clap parsing in main.
pub const SERVICE_LAUNCH_FLAG: &str = "--service";

/// Handoff to [`dispatch_service`] because the SCM entry point receives no
/// closure context.
static SERVICE_NAME: OnceLock<String> = OnceLock::new();
static SERVICE_CONFIG: OnceLock<Option<PathBuf>> = OnceLock::new();

fn build_service_info(
    name: &str,
    binary: &Path,
    config: &Path,
    depend_on: Option<&str>,
) -> ServiceInfo {
    ServiceInfo {
        name: name.into(),
        display_name: format!("Leshy ({name})").into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: binary.to_path_buf(),
        // Parsed by main.rs when the SCM launches the binary.
        launch_arguments: vec![
            SERVICE_LAUNCH_FLAG.into(),
            name.into(),
            config.as_os_str().to_os_string(),
        ],
        // None = run as LocalSystem, which holds the rights to install routes.
        account_name: None,
        account_password: None,
        // SCM dependency on the Kikimora core service (08D1 В§31.3): the SCM
        // does not start this service until the dependency reports Running
        // after application readiness.
        dependencies: dependencies_for(depend_on),
    }
}

/// Maps the requested dependency name onto SCM service dependencies. Tests
/// assert the mapping; the real SCM effect is a release-VM contract.
fn dependencies_for(depend_on: Option<&str>) -> Vec<ServiceDependency> {
    match depend_on {
        Some(name) if !name.trim().is_empty() => vec![ServiceDependency::Service(name.into())],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod dependency_tests {
    use super::*;

    #[test]
    fn empty_dependency_is_none() {
        assert!(dependencies_for(None).is_empty());
        assert!(dependencies_for(Some("")).is_empty());
        assert!(dependencies_for(Some("  ")).is_empty());
    }

    #[test]
    fn dependency_name_maps_to_service_dependency() {
        let deps = dependencies_for(Some("KikimoraCore"));
        assert_eq!(
            deps,
            vec![ServiceDependency::Service("KikimoraCore".into())]
        );
    }
}

/// Configure restart-on-failure via `ChangeServiceConfig2W`; the windows-service
/// crate only exposes failure-action reads, not writes.
fn set_failure_recovery(raw_handle: windows_sys::Win32::System::Services::SC_HANDLE) -> Result<()> {
    let mut action = SC_ACTION {
        Type: SC_ACTION_RESTART,
        Delay: FAILURE_DELAY_MS,
    };
    let failures = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: FAILURE_RESET_PERIOD_INFINITE,
        lpRebootMsg: std::ptr::null_mut(),
        lpCommand: std::ptr::null_mut(),
        cActions: 1,
        lpsaActions: &mut action,
    };
    // SAFETY: raw_handle is a live SC_HANDLE from create_service; the failures
    // struct outlives the call.
    let ok = unsafe {
        ChangeServiceConfig2W(
            raw_handle,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            &failures as *const _ as *const c_void,
        )
    };
    if ok == 0 {
        // SAFETY: GetLastError is valid immediately after the failed call.
        let error = unsafe { GetLastError() };
        anyhow::bail!("ChangeServiceConfig2W failed with error {error}");
    }
    Ok(())
}

pub fn install(name: &str, binary: &Path, config: &Path, depend_on: Option<&str>) -> Result<()> {
    if !config.exists() {
        anyhow::bail!(
            "Config file {} does not exist. Create it first (see config.example.toml).",
            config.display()
        );
    }

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("failed to connect to the service manager (run as Administrator)")?;

    let service = manager
        .create_service(
            &build_service_info(name, binary, config, depend_on),
            ServiceAccess::CHANGE_CONFIG,
        )
        .context("failed to create the service (run as Administrator)")?;

    service
        .set_description(SERVICE_DESCRIPTION)
        .context("failed to set the service description")?;

    if let Err(e) = set_failure_recovery(service.raw_handle()) {
        // Best-effort: the service works without recovery configuration.
        eprintln!("Warning: could not configure restart-on-failure: {e}");
    }

    println!(
        "Service {name} installed (auto-start, restart on failure). Start it with: sc.exe start {name}"
    );
    Ok(())
}

pub fn uninstall(name: &str) -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("failed to connect to the service manager (run as Administrator)")?;

    let service = manager
        .open_service(name, ServiceAccess::STOP | ServiceAccess::DELETE)
        .with_context(|| format!("service '{name}' not found or not accessible"))?;

    // Best-effort stop; a stopped service deletes cleanly, and a running one
    // is still marked for deletion.
    if let Err(e) = service.stop() {
        eprintln!("Note: could not stop service (may already be stopped): {e}");
    }

    service
        .delete()
        .with_context(|| format!("failed to delete service '{name}'"))?;

    println!("Service {name} uninstalled");
    Ok(())
}

// --- Service runtime -------------------------------------------------------
//
// A process launched by the Service Control Manager must answer the SCM
// handshake within ~30 seconds or it is killed with error 1053, must not
// report Running before it can serve, and must answer a stop request
// gracefully (08D1 Production Plan C4).
//
// The state machine itself lives in `crate::service::coordinator`, where it is
// unit-tested on every platform; this module only maps the SCM events onto it:
// dispatch -> StartPending -> (config, lease, static routes, DNS bind) ->
// Running -> stop request -> StopPending -> graceful drain -> Stopped.

windows_service::define_windows_service!(ffi_service_main, leshy_service_main);

/// Wait hint reported while starting: the SCM's own start window.
const START_PENDING_WAIT_HINT: Duration = Duration::from_secs(30);

/// Entry point for SCM launches: `leshy.exe --service <name> <config>`.
/// Blocks until the service stops.
pub fn dispatch_service(service_name: &str, config: Option<PathBuf>) -> Result<()> {
    let _ = SERVICE_NAME.set(service_name.to_string());
    let _ = SERVICE_CONFIG.set(config);
    service_dispatcher::start(service_name, ffi_service_main)
        .context("failed to start the service dispatcher")
}

fn leshy_service_main(_arguments: Vec<std::ffi::OsString>) {
    // The name and config were stashed by dispatch_service; the generated
    // wrapper only guarantees the SCM handshake.
    if let Err(e) = run_service() {
        eprintln!("Leshy service failed: {e}");
    }
}

/// Maps the coordinator's reports onto `SERVICE_STATUS` records.
struct ScmStatusSink {
    handle: windows_service::service_control_handler::ServiceStatusHandle,
}

impl StatusSink for ScmStatusSink {
    fn report(&mut self, report: StatusReport) -> Result<()> {
        let (state, controls, wait_hint) = match report.state {
            LifecycleState::StartPending => (
                ServiceState::StartPending,
                ServiceControlAccept::empty(),
                START_PENDING_WAIT_HINT,
            ),
            LifecycleState::Running => (
                ServiceState::Running,
                ServiceControlAccept::STOP,
                Duration::from_secs(5),
            ),
            // The wait hint is this process's own grace window, not the SCM's
            // 30 s default: the decision to abort or to finish belongs here.
            LifecycleState::StopPending => (
                ServiceState::StopPending,
                ServiceControlAccept::empty(),
                GRACEFUL_STOP_TIMEOUT,
            ),
            LifecycleState::Stopped => (
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                Duration::from_secs(0),
            ),
        };
        let exit_code = if report.exit_code == 0 {
            ServiceExitCode::NO_ERROR
        } else {
            ServiceExitCode::ServiceSpecific(report.exit_code)
        };
        self.handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: controls,
                exit_code,
                checkpoint: report.checkpoint,
                wait_hint,
                process_id: None,
            })
            .context("failed to report the service status")
    }
}

/// Describe how the server task ended, for the failure log and the SCM record.
fn describe_join(
    result: std::result::Result<anyhow::Result<()>, tokio::task::JoinError>,
) -> String {
    match result {
        Ok(Ok(())) => "server returned without a stop request".to_string(),
        Ok(Err(e)) => format!("{e:#}"),
        Err(e) => format!("server task failed: {e}"),
    }
}

fn run_service() -> Result<()> {
    let service_name = SERVICE_NAME
        .get()
        .cloned()
        .unwrap_or_else(|| "leshy".to_string());
    let config_path = SERVICE_CONFIG.get().cloned().flatten();

    // Stop requests are stateful: a stop that arrives before the server has
    // installed its shutdown future is still observed when the future runs.
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let stop_from_scm = stop_tx.clone();
    let event_handler = move |control_event: ServiceControl| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                let _ = stop_from_scm.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(&service_name, event_handler)
        .context("failed to register the service control handler")?;
    let mut lifecycle = LifecycleCoordinator::start_pending(ScmStatusSink {
        handle: status_handle,
    })?;
    // Subscribed immediately so no stop request can fall between the handler
    // registration and the running phase.
    let mut stop_wait = stop_tx.subscribe();

    // stdout/stderr are invisible under the SCM, so service logs go to a
    // rolling file next to the config (C:\ProgramData\leshy\logs by default).
    let _log_guard = init_service_logging(config_path.as_deref());

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build the tokio runtime")?;

    let (ready_tx, mut ready_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = runtime.spawn(async move {
        let shutdown = async move {
            let mut stop = stop_rx;
            while !*stop.borrow() {
                if stop.changed().await.is_err() {
                    break;
                }
            }
        };
        let ready = move || {
            // A readiness notification that arrives after the SCM gave up is
            // harmless: the receiving side is gone, the state machine decides.
            let _ = ready_tx.send(());
        };
        crate::server::run_server_until_with_ready(config_path, shutdown, ready).await
    });

    let outcome: Result<()> = runtime.block_on(async move {
        let mut server_task = server_task;
        // StartPending until config, writer lease, static routes and the DNS
        // socket are done. A server that dies here never reports Running.
        let became_ready = tokio::select! {
            ready = &mut ready_rx => ready.is_ok(),
            early = &mut server_task => {
                let detail = describe_join(early);
                lifecycle.finish(StopReason::FailedBeforeReady)?;
                anyhow::bail!("Leshy exited before readiness: {detail}");
            }
        };
        if !became_ready {
            // Readiness sender dropped without a notification: the server is
            // already unwinding, and it never served a query.
            let early = (&mut server_task).await;
            let detail = describe_join(early);
            lifecycle.finish(StopReason::FailedBeforeReady)?;
            anyhow::bail!("Leshy exited before readiness: {detail}");
        }
        lifecycle.mark_ready()?;
        tracing::info!("Leshy service is ready; reporting Running to the SCM");

        // Running until a stop request or an unexpected server exit.
        if !*stop_wait.borrow() {
            tokio::select! {
                _ = stop_wait.changed() => {}
                early = &mut server_task => {
                    let detail = describe_join(early);
                    lifecycle.finish(StopReason::EarlyExit)?;
                    anyhow::bail!("Leshy server exited while running: {detail}");
                }
            }
        }

        lifecycle.begin_stop()?;
        tracing::info!(
            timeout_s = GRACEFUL_STOP_TIMEOUT.as_secs(),
            "Stop requested; draining the Leshy server"
        );

        match tokio::time::timeout(GRACEFUL_STOP_TIMEOUT, &mut server_task).await {
            Ok(Ok(Ok(()))) => {
                tracing::info!("Leshy server stopped cleanly");
                lifecycle.finish(StopReason::Graceful)?;
                Ok(())
            }
            Ok(Ok(Err(e))) => {
                tracing::error!(error = %e, "Leshy server reported an error while stopping");
                lifecycle.finish(StopReason::GracefulWithError)?;
                Err(e)
            }
            Ok(Err(join_error)) => {
                tracing::error!(error = %join_error, "Leshy server task failed while stopping");
                lifecycle.finish(StopReason::GracefulWithError)?;
                Err(anyhow::anyhow!("Leshy server task failed: {join_error}"))
            }
            Err(_) => {
                // Production Plan C4: the grace window owns the outcome. The
                // task is aborted only after the bounded graceful attempt.
                tracing::error!(
                    timeout_s = GRACEFUL_STOP_TIMEOUT.as_secs(),
                    "Grace window expired; aborting the Leshy server"
                );
                server_task.abort();
                let _ = server_task.await;
                lifecycle.finish(StopReason::ForcedAbort)?;
                anyhow::bail!(
                    "Leshy did not stop within {}s; forced abort",
                    GRACEFUL_STOP_TIMEOUT.as_secs()
                )
            }
        }
    });

    // The service log is the only visible channel under the SCM; record the
    // failure while the file writer is still alive. A start that fails before
    // readiness must leave a diagnosable reason in the log.
    if let Err(e) = &outcome {
        tracing::error!(error = %format!("{e:#}"), "Leshy service failed");
    }
    drop(runtime);
    outcome
}

/// Install a file-based tracing subscriber for service mode and return the
/// non-blocking writer guard, which must live as long as the service does.
fn init_service_logging(config_path: Option<&Path>) -> tracing_appender::non_blocking::WorkerGuard {
    let log_dir = config_path
        .and_then(|p| p.parent().map(|d| d.join("logs")))
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\leshy\logs"));
    let _ = std::fs::create_dir_all(&log_dir);

    let appender = tracing_appender::rolling::daily(&log_dir, "leshy.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_ansi(false)
        .with_writer(writer)
        .init();
    guard
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::path::PathBuf;

    fn os(value: &str) -> OsString {
        value.into()
    }

    #[test]
    fn service_info_uses_local_system_and_auto_start() {
        let info = build_service_info(
            "leshy",
            Path::new(r"C:\Program Files\leshy\leshy.exe"),
            Path::new(r"C:\ProgramData\leshy\config.toml"),
            None,
        );

        assert_eq!(info.name, os("leshy"));
        assert_eq!(info.display_name, os("Leshy (leshy)"));
        assert_eq!(info.start_type, ServiceStartType::AutoStart);
        assert_eq!(info.service_type, ServiceType::OWN_PROCESS);
        assert_eq!(info.account_name, None);
        assert_eq!(info.account_password, None);
        assert_eq!(info.dependencies, Vec::new());
        assert_eq!(
            info.executable_path,
            PathBuf::from(r"C:\Program Files\leshy\leshy.exe")
        );
        assert_eq!(
            info.launch_arguments,
            vec![
                os("--service"),
                os("leshy"),
                os(r"C:\ProgramData\leshy\config.toml")
            ]
        );
    }

    #[test]
    fn custom_name_in_display_name() {
        let info = build_service_info(
            "leshy-corp",
            Path::new("leshy.exe"),
            Path::new("corp.toml"),
            None,
        );
        assert_eq!(info.display_name, os("Leshy (leshy-corp)"));
    }

    #[test]
    fn failure_constants_are_stable() {
        // Guard against accidental contract drift in the FFI constants.
        assert_eq!(FAILURE_DELAY_MS, 5000);
        assert_eq!(FAILURE_RESET_PERIOD_INFINITE, 0xFFFF_FFFF);
        assert_eq!(SC_ACTION_RESTART, 1);
        assert_eq!(SERVICE_CONFIG_FAILURE_ACTIONS, 2);
    }

    #[test]
    fn service_launch_flag_is_stable() {
        assert_eq!(SERVICE_LAUNCH_FLAG, "--service");
    }
}
