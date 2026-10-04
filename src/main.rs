mod config;
mod dns;
mod error;
mod reload;
mod routing;
mod server;
mod service;
mod zones;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "leshy", about = "DNS-driven split-tunnel router", version)]
struct Cli {
    /// Path to configuration file
    #[arg(global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Manage system service installation
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Install as a system service (systemd on Linux, launchd on macOS)
    Install {
        /// Path to configuration file for the service
        #[arg(long, default_value = service::default_config())]
        config: PathBuf,

        /// Service name (allows running multiple instances)
        #[arg(long, default_value = service::default_name())]
        name: String,
    },
    /// Remove the system service
    Uninstall {
        /// Service name to uninstall
        #[arg(long, default_value = service::default_name())]
        name: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Service Control Manager launch: leshy.exe --service <name> <config>.
    // Checked before Cli::parse so the extra arguments never hit clap.
    #[cfg(target_os = "windows")]
    {
        let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
        if args.len() > 1 && args[1] == service::SERVICE_LAUNCH_FLAG {
            let name = args
                .get(2)
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| service::default_name().to_string());
            let config = args.get(3).map(PathBuf::from);
            service::dispatch_service(&name, config)?;
            return Ok(());
        }
    }

    let cli = Cli::parse();

    match cli.command {
        Some(Command::Service { action }) => match action {
            ServiceAction::Install { config, name } => {
                service::install(Some(&name), Some(&config))?;
            }
            ServiceAction::Uninstall { name } => {
                service::uninstall(Some(&name))?;
            }
        },
        None => {
            server::init_console_tracing();
            server::run_server(cli.config).await?
        }
    }

    Ok(())
}
