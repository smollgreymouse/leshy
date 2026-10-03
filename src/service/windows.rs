use anyhow::{Context, Result};
use std::os::raw::c_void;
use std::path::Path;
use windows_service::service::{
    ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceType,
};
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

fn build_service_info(name: &str, binary: &Path, config: &Path) -> ServiceInfo {
    ServiceInfo {
        name: name.into(),
        display_name: format!("Leshy ({name})").into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: binary.to_path_buf(),
        launch_arguments: vec![config.as_os_str().to_os_string()],
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
            vec![os(r"C:\ProgramData\leshy\config.toml")]
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
}
