#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

// The lifecycle coordinator is platform-independent so the SCM contract can
// be unit-tested on every CI runner (Production Plan C4). It is compiled for
// the Windows service and for test builds everywhere; a Linux release build
// has no consumer for it.
#[cfg(any(target_os = "windows", test))]
mod coordinator;

#[cfg(target_os = "windows")]
pub use windows::{dispatch_service, SERVICE_LAUNCH_FLAG};

use anyhow::Result;
use std::path::{Path, PathBuf};

#[cfg(target_os = "windows")]
const DEFAULT_CONFIG: &str = r"C:\ProgramData\leshy\config.toml";
#[cfg(not(target_os = "windows"))]
const DEFAULT_CONFIG: &str = "/etc/leshy/config.toml";
const DEFAULT_NAME: &str = "leshy";
#[cfg(target_os = "windows")]
const FALLBACK_BINARY: &str = r"C:\Program Files\leshy\leshy.exe";
#[cfg(not(target_os = "windows"))]
const FALLBACK_BINARY: &str = "/usr/local/bin/leshy";

fn detect_binary() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .unwrap_or_else(|| PathBuf::from(FALLBACK_BINARY))
}

pub fn default_config() -> &'static str {
    DEFAULT_CONFIG
}

pub fn default_name() -> &'static str {
    DEFAULT_NAME
}

pub fn install(name: Option<&str>, config: Option<&Path>, depend_on: Option<&str>) -> Result<()> {
    let name = name.unwrap_or(DEFAULT_NAME);
    let config = config.unwrap_or_else(|| Path::new(DEFAULT_CONFIG));
    let binary = detect_binary();

    println!(
        "Installing service '{name}' (binary: {}, config: {})",
        binary.display(),
        config.display()
    );

    #[cfg(target_os = "linux")]
    linux::install(name, &binary, config)?;

    #[cfg(target_os = "macos")]
    macos::install(name, &binary, config)?;

    // The SCM dependency is a Windows contract (08D1 В§31.3); other platforms
    // gate the flag explicitly so the argument is never silently dropped.
    #[cfg(not(target_os = "windows"))]
    if depend_on.is_some() {
        anyhow::bail!("--depend-on is only supported on windows");
    }

    #[cfg(target_os = "windows")]
    windows::install(name, &binary, config, depend_on)?;

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    anyhow::bail!("service install is not supported on this platform");

    Ok(())
}

pub fn uninstall(name: Option<&str>) -> Result<()> {
    let name = name.unwrap_or(DEFAULT_NAME);

    println!("Uninstalling service '{name}'");

    #[cfg(target_os = "linux")]
    linux::uninstall(name)?;

    #[cfg(target_os = "macos")]
    macos::uninstall(name)?;

    #[cfg(target_os = "windows")]
    windows::uninstall(name)?;

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    anyhow::bail!("service uninstall is not supported on this platform");

    Ok(())
}
