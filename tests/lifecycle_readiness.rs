// Readiness hook contract (Production Plan C4).
//
// The Windows service reports Running only after the server invokes the
// readiness callback, which must happen after the DNS socket is bound. These
// tests exercise the same public entry point the SCM wrapper uses, without a
// service manager and without touching routes.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use leshy::server::run_server_until_with_ready;

fn free_udp_port() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral");
    socket.local_addr().expect("local addr").port()
}

fn write_config(dir: &std::path::Path, port: u16) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    let body = format!(
        r#"
[server]
listen_address = "127.0.0.1:{port}"
default_upstream = ["192.0.2.1:53"]
route_failure_mode = "fallback"
auto_reload = false
"#
    );
    std::fs::write(&path, body).expect("write config");
    path
}

#[tokio::test]
async fn readiness_fires_once_after_the_dns_socket_is_bound() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let port = free_udp_port();
    let config_path = write_config(dir.path(), port);

    let ready_fired = Arc::new(AtomicBool::new(false));
    let ready_flag = ready_fired.clone();
    let ready_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls = ready_calls.clone();

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        run_server_until_with_ready(
            Some(config_path),
            async move {
                let _ = shutdown_rx.await;
            },
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
                ready_flag.store(true, Ordering::SeqCst);
                let _ = ready_tx.send(());
            },
        )
        .await
    });

    ready_rx.await.expect("readiness is reported");
    assert!(ready_fired.load(Ordering::SeqCst));

    // The callback fires only after the socket exists: an unbound port would
    // still be bindable here.
    let rebound = std::net::UdpSocket::bind(("127.0.0.1", port));
    assert!(
        rebound.is_err(),
        "DNS socket must already be bound when readiness fires"
    );

    shutdown_tx.send(()).expect("request shutdown");
    // Callback signature is `FnOnce`, so the count can never exceed one.
    let result = server.await.expect("join");
    result.expect("clean server exit");
    assert_eq!(ready_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn readiness_is_not_reported_when_the_config_cannot_be_loaded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("missing.toml");

    let ready_fired = Arc::new(AtomicBool::new(false));
    let ready_flag = ready_fired.clone();

    let result = run_server_until_with_ready(Some(missing), async {}, move || {
        ready_flag.store(true, Ordering::SeqCst);
    })
    .await;

    assert!(result.is_err(), "a missing config must fail the startup");
    assert!(
        !ready_fired.load(Ordering::SeqCst),
        "readiness must not be reported for a server that never started"
    );
}
