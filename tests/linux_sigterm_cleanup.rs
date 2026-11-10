// Linux SIGTERM privileged acceptance (Production Plan C3).
//
// The gate runs the real `leshy` binary inside a disposable network namespace,
// so the kernel rows it owns are the ordinary product rows and the host
// workspace is never touched:
//
//   start local Leshy
//   install exact owned test rows (v4 + v6 static routes)
//   install a same-prefix foreign fixture (same prefix, different metric)
//   SIGTERM
//   wait for a clean exit
//   owned exact rows gone
//   foreign fixture byte-identical
//
// Run through `tests/linux-sigterm-netns.sh`, which creates the namespace and
// passes the absolute binary paths. The test is `#[ignore]` so an unprivileged
// `cargo test` never tries to mutate a real FIB.

#![cfg(target_os = "linux")]

use std::io::Write;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const V4_OWNED: &str = "10.66.7.7/32";
const V6_OWNED: &str = "fd00:66::7/128";
const V4_FOREIGN_METRIC: &str = "500";

fn env_required(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} must be set (see tests/linux-sigterm-netns.sh)"))
}

fn absolute_existing(name: &str) -> PathBuf {
    let raw = env_required(name);
    let path = PathBuf::from(&raw);
    assert!(path.is_absolute(), "{name} must be absolute, got {raw}");
    assert!(path.exists(), "{name} does not exist: {raw}");
    path
}

fn ip(args: &[&str]) -> String {
    let output = Command::new("ip")
        .args(args)
        .output()
        .expect("run iproute2");
    assert!(
        output.status.success(),
        "ip {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn ip_try(args: &[&str]) -> bool {
    Command::new("ip")
        .args(args)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Sorted route lines of one address family, so two snapshots compare as
/// exact sets: no row added, removed or rewritten.
fn table(family: &str) -> Vec<String> {
    let mut lines: Vec<String> = ip(&[family, "route", "show", "table", "main"])
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    lines.sort();
    lines
}

fn prefix_rows(family: &str, prefix: &str) -> Vec<String> {
    let mut lines: Vec<String> = ip(&[family, "route", "show", prefix])
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    lines.sort();
    lines
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

/// tracing writes ANSI colours even into a redirected file, so the assertions
/// compare plain text.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for next in chars.by_ref() {
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(ch);
    }
    out
}

fn wait_until(deadline: Duration, mut check: impl FnMut() -> bool) -> bool {
    let started = Instant::now();
    while started.elapsed() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn write_config(dir: &Path, dev_file: &Path, port: u16) -> PathBuf {
    let path = dir.join("leshy-sigterm.toml");
    let body = format!(
        r#"[server]
listen_address = "127.0.0.1:{port}"
default_upstream = ["192.0.2.1:53"]
route_failure_mode = "fallback"
auto_reload = false

[[zones]]
name = "sigterm-gate"
route_type = "dev"
route_target = "{dev_file}"
domains = ["sigterm.invalid"]
ipv6 = true
static_routes = ["{V4_OWNED}", "{V6_OWNED}"]
"#,
        dev_file = dev_file.display()
    );
    std::fs::write(&path, body).expect("write config");
    path
}

#[test]
#[ignore = "privileged netns acceptance; run tests/linux-sigterm-netns.sh"]
fn sigterm_removes_only_exact_owned_rows_and_preserves_the_foreign_fixture() {
    let leshy = absolute_existing("LESHY_BIN");
    let dev = env_required("LESHY_NETNS_DEV");
    assert!(
        ip_try(&["link", "show", &dev]),
        "device {dev} must exist in this namespace"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let dev_file = dir.path().join("gate.dev");
    std::fs::write(&dev_file, format!("{dev}\n")).expect("write device file");
    let config = write_config(dir.path(), &dev_file, free_udp_port());

    let before = (table("-4"), table("-6"));

    let log_path = dir.path().join("leshy.log");
    let log = std::fs::File::create(&log_path).expect("create log");
    let log_err = log.try_clone().expect("clone log");

    let mut child = Command::new(&leshy)
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("spawn leshy");

    // Ordinary startup: the two static rows must appear before we may claim
    // the product installed them.
    let installed = wait_until(Duration::from_secs(20), || {
        !prefix_rows("-4", V4_OWNED).is_empty() && !prefix_rows("-6", V6_OWNED).is_empty()
    });
    if !installed {
        let _ = child.kill();
        let _ = child.wait();
        let tail = std::fs::read_to_string(&log_path).unwrap_or_default();
        panic!("static rows were not installed by the product:\n{tail}");
    }

    // The rows the product installed, captured before any foreign row exists:
    // they are the only lines the cleanup is allowed to remove.
    let owned_v4 = prefix_rows("-4", V4_OWNED);
    let owned_v6 = prefix_rows("-6", V6_OWNED);
    assert_eq!(owned_v4.len(), 1, "one owned v4 row:\n{owned_v4:#?}");
    assert_eq!(owned_v6.len(), 1, "one owned v6 row:\n{owned_v6:#?}");

    // A foreign row on the *same prefix*, distinguished only by its metric:
    // the exact owned rows must be the ones deleted, never these.
    ip(&[
        "route",
        "add",
        V4_OWNED,
        "dev",
        &dev,
        "metric",
        V4_FOREIGN_METRIC,
    ]);
    ip(&[
        "-6",
        "route",
        "add",
        V6_OWNED,
        "dev",
        &dev,
        "metric",
        V4_FOREIGN_METRIC,
    ]);

    let with_foreign = (table("-4"), table("-6"));
    let foreign_v4 = prefix_rows("-4", V4_OWNED);
    let foreign_v6 = prefix_rows("-6", V6_OWNED);
    assert_eq!(
        foreign_v4.len(),
        2,
        "owned + foreign v4 rows:\n{foreign_v4:#?}"
    );
    assert_eq!(
        foreign_v6.len(),
        2,
        "owned + foreign v6 rows:\n{foreign_v6:#?}"
    );

    // SIGTERM: the product's own shutdown signal, not a SIGKILL.
    let pid = child.id() as i32;
    // SAFETY: the pid belongs to the child we just spawned.
    let sent = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(
        sent,
        0,
        "SIGTERM delivery failed: {}",
        std::io::Error::last_os_error()
    );

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait());
    });
    let status = rx
        .recv_timeout(Duration::from_secs(25))
        .expect("leshy did not exit within 25s of SIGTERM")
        .expect("wait for leshy");
    assert!(
        status.success(),
        "SIGTERM must produce a clean exit, got {status:?}"
    );

    // Only the owned rows are gone: the whole table equals the pre-SIGTERM
    // snapshot with exactly the rows the product installed removed.
    let after = (table("-4"), table("-6"));
    let expected_v4: Vec<String> = with_foreign
        .0
        .iter()
        .filter(|row| !owned_v4.contains(row))
        .cloned()
        .collect();
    let expected_v6: Vec<String> = with_foreign
        .1
        .iter()
        .filter(|row| !owned_v6.contains(row))
        .cloned()
        .collect();
    assert_eq!(
        after.0, expected_v4,
        "IPv4 table changed beyond the owned rows\nafter:\n{after:#?}"
    );
    assert_eq!(
        after.1, expected_v6,
        "IPv6 table changed beyond the owned rows\nafter:\n{after:#?}"
    );
    // The foreign rows are the fixture snapshot minus the owned rows (the
    // IPv6 owned row also prints its metric, so the metric text is not a
    // marker of foreign ownership).
    let foreign_only_v4: Vec<String> = foreign_v4
        .iter()
        .filter(|row| !owned_v4.contains(row))
        .cloned()
        .collect();
    let foreign_only_v6: Vec<String> = foreign_v6
        .iter()
        .filter(|row| !owned_v6.contains(row))
        .cloned()
        .collect();
    assert_eq!(foreign_only_v4.len(), 1, "one foreign v4 fixture");
    assert_eq!(foreign_only_v6.len(), 1, "one foreign v6 fixture");

    let surviving_v4 = prefix_rows("-4", V4_OWNED);
    let surviving_v6 = prefix_rows("-6", V6_OWNED);
    assert_eq!(
        surviving_v4, foreign_only_v4,
        "the foreign same-prefix IPv4 row must survive unchanged"
    );
    assert_eq!(
        surviving_v6, foreign_only_v6,
        "the foreign same-prefix IPv6 row must survive unchanged"
    );

    let raw_log = std::fs::read_to_string(&log_path).unwrap_or_default();
    let log_text = strip_ansi(&raw_log);
    assert!(
        log_text.contains("Shutdown route cleanup complete"),
        "the product shutdown path must log the exact cleanup:\n{log_text}"
    );
    assert!(
        log_text.contains("removed=2") || log_text.contains("removed: 2"),
        "both owned rows must be reported removed:\n{log_text}"
    );
    assert!(
        !log_text.contains("exact delete left the owned route"),
        "the read-back must confirm the exact delete:\n{log_text}"
    );

    // Harness cleanup restores the pre-run table exactly.
    ip_try(&[
        "route",
        "del",
        V4_OWNED,
        "dev",
        &dev,
        "metric",
        V4_FOREIGN_METRIC,
    ]);
    ip_try(&[
        "-6",
        "route",
        "del",
        V6_OWNED,
        "dev",
        &dev,
        "metric",
        V4_FOREIGN_METRIC,
    ]);
    let restored = (table("-4"), table("-6"));
    assert_eq!(
        restored, before,
        "harness cleanup must restore the namespace"
    );

    // Keep the log for the gate archive.
    let archive = std::env::var("LESHY_SIGTERM_LOG").unwrap_or_default();
    if !archive.is_empty() {
        let mut out = std::fs::File::create(&archive).expect("create archived log");
        let _ = writeln!(out, "{}", raw_log);
        let _ = writeln!(
            out,
            "--- owned v4 rows after exit ---\n{:#?}",
            prefix_rows("-4", V4_OWNED)
        );
        let _ = writeln!(
            out,
            "--- owned v6 rows after exit ---\n{:#?}",
            prefix_rows("-6", V6_OWNED)
        );
    }
}
