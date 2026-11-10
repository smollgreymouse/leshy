mod config;
mod dns;
mod error;
mod lease;
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

#[derive(Subcommand, Debug)]
enum Command {
    /// Manage system service installation
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Print the managed-routing capabilities this build supports
    Capabilities {
        /// Machine-readable JSON (stable sorted array)
        #[arg(long)]
        json: bool,
    },
}

/// Every managed-routing capability this build advertises (08D1 §31.5).
///
/// Stable, sorted and side-effect free: the command performs no config load,
/// socket connect, DNS bind or route mutation.
pub const SUPPORTED_CAPABILITIES: [&str; 4] = [
    "af_unix_control",
    "managed_selected_routes_v1",
    "managed_selected_routes_v2",
    "privileged_control_auth_v1",
];

/// The exact JSON body of `leshy capabilities --json`.
pub fn capabilities_json() -> String {
    let mut out = String::from("[");
    for (index, capability) in SUPPORTED_CAPABILITIES.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(capability);
        out.push('"');
    }
    out.push(']');
    out
}

#[derive(Subcommand, Debug)]
enum ServiceAction {
    /// Install as a system service (systemd on Linux, launchd on macOS)
    Install {
        /// Path to configuration file for the service
        #[arg(long, default_value = service::default_config())]
        config: PathBuf,

        /// Service name (allows running multiple instances)
        #[arg(long, default_value = service::default_name())]
        name: String,

        /// Windows: SCM service this installation depends on (08D1 §31.3).
        /// The packaged Kikimora pairing passes its core service name so a
        /// partial core startup never leaves Leshy running against it.
        #[arg(long)]
        depend_on: Option<String>,
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
            ServiceAction::Install {
                config,
                name,
                depend_on,
            } => {
                service::install(Some(&name), Some(&config), depend_on.as_deref())?;
            }
            ServiceAction::Uninstall { name } => {
                service::uninstall(Some(&name))?;
            }
        },
        Some(Command::Capabilities { json }) => {
            // No config load, no socket, no DNS bind, no route mutation.
            if json {
                println!("{}", capabilities_json());
            } else {
                for capability in SUPPORTED_CAPABILITIES {
                    println!("{capability}");
                }
            }
            return Ok(());
        }
        None => {
            server::init_console_tracing();
            server::run_server(cli.config).await?
        }
    }

    Ok(())
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn capabilities_subcommand_parses_with_json() {
        let cli = Cli::try_parse_from(["leshy", "capabilities", "--json"]).expect("parse");
        match cli.command {
            Some(Command::Capabilities { json }) => assert!(json),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn capabilities_json_is_stable_and_sorted() {
        assert_eq!(
            capabilities_json(),
            r#"["af_unix_control","managed_selected_routes_v1","managed_selected_routes_v2","privileged_control_auth_v1"]"#
        );
    }

    #[test]
    fn default_invocation_has_no_command() {
        let cli = Cli::try_parse_from(["leshy"]).unwrap();
        assert!(cli.command.is_none());
        assert!(cli.config.is_none());
    }

    #[test]
    fn config_is_a_positional_argument() {
        let cli = Cli::try_parse_from(["leshy", "/etc/leshy/c.toml"]).unwrap();
        assert_eq!(
            cli.config.as_deref(),
            Some(std::path::Path::new("/etc/leshy/c.toml"))
        );
        assert!(cli.command.is_none());
    }

    #[test]
    fn service_install_has_its_own_config_flag() {
        let cli = Cli::try_parse_from([
            "leshy",
            "service",
            "install",
            "--config",
            "/etc/leshy/c.toml",
            "--name",
            "leshy-corp",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Service {
                action: ServiceAction::Install { config, name, .. },
            }) => {
                assert_eq!(config, PathBuf::from("/etc/leshy/c.toml"));
                assert_eq!(name, "leshy-corp");
            }
            other => panic!("expected service install, got {other:?}"),
        }
    }

    #[test]
    fn service_uninstall_parses_the_name() {
        let cli =
            Cli::try_parse_from(["leshy", "service", "uninstall", "--name", "leshy-corp"]).unwrap();
        match cli.command {
            Some(Command::Service {
                action: ServiceAction::Uninstall { name },
            }) => {
                assert_eq!(name, "leshy-corp");
            }
            other => panic!("expected service uninstall, got {other:?}"),
        }
    }

    #[test]
    fn a_bare_word_is_a_config_path_not_a_subcommand() {
        // The positional config means unknown words never become
        // subcommands: "frobnicate" is a config path that will then fail to
        // load, which is the documented behavior.
        let cli = Cli::try_parse_from(["leshy", "frobnicate"]).unwrap();
        assert!(cli.command.is_none());
        assert_eq!(
            cli.config.as_deref(),
            Some(std::path::Path::new("frobnicate"))
        );
    }
}
