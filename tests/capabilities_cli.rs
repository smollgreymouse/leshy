//! `leshy capabilities --json` contract (Production Plan C5).
//!
//! The command is side-effect free: it must succeed with a nonexistent
//! config path, never bind DNS, never connect a socket and never touch the
//! forwarding table.

use std::process::Command;

#[test]
fn capabilities_json_is_side_effect_free_and_exact() {
    let binary = env!("CARGO_BIN_EXE_leshy");
    let output = Command::new(binary)
        .args([
            "C:/definitely/missing/leshy-capabilities.toml",
            "capabilities",
            "--json",
        ])
        .output()
        .expect("run leshy capabilities --json");

    assert!(
        output.status.success(),
        "capabilities must not depend on config: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "[\"af_unix_control\",\"managed_selected_routes_v1\",\"managed_selected_routes_v2\",\"privileged_control_auth_v1\"]"
    );
}

#[test]
fn capabilities_plain_output_is_sorted_lines() {
    let binary = env!("CARGO_BIN_EXE_leshy");
    let output = Command::new(binary)
        .args(["capabilities"])
        .output()
        .expect("run leshy capabilities");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines,
        vec![
            "af_unix_control",
            "managed_selected_routes_v1",
            "managed_selected_routes_v2",
            "privileged_control_auth_v1",
        ]
    );
}
