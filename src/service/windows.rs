use anyhow::{Context, Result};
use std::os::raw::c_void;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;
use tracing_subscriber::EnvFilter;
use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
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

fn build_service_info(name: &str, binary: &Path, config: &Path) -> ServiceInfo {
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
        dependencies: Vec::new(),
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

pub fn install(name: &str, binary: &Path, config: &Path) -> Result<()> {
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
            &build_service_info(name, binary, config),
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
// handshake within ~30 seconds or it is killed with error 1053. The block
// below wires leshy into that contract: dispatch -> StartPending -> run the
// DNS server -> Running -> stop request -> Stopped.

windows_service::define_windows_service!(ffi_service_main, leshy_service_main);

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

fn run_service() -> Result<()> {
    let service_name = SERVICE_NAME
        .get()
        .cloned()
        .unwrap_or_else(|| "leshy".to_string());
    let config_path = SERVICE_CONFIG.get().cloned().flatten();

    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let event_handler = move |control_event: ServiceControl| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let status_handle = service_control_handler::register(&service_name, event_handler)
        .context("failed to register the service control handler")?;

    report_status(&status_handle, ServiceState::StartPending, 1)?;

    // stdout/stderr are invisible under the SCM, so service logs go to a
    // rolling file next to the config (C:\ProgramData\leshy\logs by default).
    let _log_guard = init_service_logging(config_path.as_deref());

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to build the tokio runtime")?;
    let server_task = runtime.spawn(async move {
        if let Err(e) = crate::server::run_server(config_path).await {
            tracing::error!(error = %e, "Leshy server exited with an error");
        }
    });

    report_status(&status_handle, ServiceState::Running, 0)?;

    // Wait for a stop request or an unexpected server exit.
    loop {
        match stop_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(()) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if server_task.is_finished() {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    report_status(&status_handle, ServiceState::StopPending, 1)?;
    server_task.abort();
    // Abort cancels at the next await point inside the server; kernel routes
    // installed so far persist, matching the Linux/macOS stop behavior.
    let _ = runtime.block_on(server_task);
    report_status(&status_handle, ServiceState::Stopped, 0)?;
    Ok(())
}

fn report_status(
    handle: &windows_service::service_control_handler::ServiceStatusHandle,
    state: ServiceState,
    checkpoint: u32,
) -> Result<()> {
    let (controls, wait_hint) = match state {
        ServiceState::Running => (ServiceControlAccept::STOP, Duration::from_secs(5)),
        ServiceState::Stopped => (ServiceControlAccept::empty(), Duration::from_secs(0)),
        _ => (ServiceControlAccept::empty(), Duration::from_secs(30)),
    };
    handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: controls,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint,
            wait_hint,
            process_id: None,
        })
        .context("failed to report the service status")
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
        let info = build_service_info("leshy-corp", Path::new("leshy.exe"), Path::new("corp.toml"));
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
