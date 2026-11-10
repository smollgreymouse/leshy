//! Platform-independent service lifecycle coordinator (Production Plan C4).
//!
//! The Windows Service Control Manager hands a process a short window to
//! answer the start handshake and expects an honest status: a service must
//! not be advertised as `Running` before it can actually serve, and a stop
//! request must be answered gracefully instead of aborting the server task
//! and leaving its cleanup unexecuted.
//!
//! Both rules are pure state transitions over "readiness" and "stop" events,
//! so they live here and are unit-tested on every platform. The Windows
//! wrapper only maps these reports onto `SERVICE_STATUS` records.

use anyhow::Result;
use std::time::Duration;

/// Grace window for a stop request. The SCM's own wait hint is 30 s; the
/// process keeps a shorter bound so it decides the outcome, and the forced
/// abort happens before the SCM loses patience with the service.
pub const GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(15);

/// Exit code recorded when the grace window expired and the server task had
/// to be aborted: a non-clean stop that failure recovery may act on.
pub const FORCED_STOP_EXIT_CODE: u32 = 1;

/// Exit code recorded when the server ended on its own while running.
pub const EARLY_EXIT_CODE: u32 = 2;

/// Exit code recorded when the server never reached readiness.
pub const FAILED_BEFORE_READY_EXIT_CODE: u32 = 3;

/// Exit code recorded when a requested stop finished but the server reported
/// an error from its own shutdown path.
pub const STOP_ERROR_EXIT_CODE: u32 = 4;

/// Lifecycle states a Windows service can be in while it runs here. Mirrors
/// `SERVICE_START_PENDING` … `SERVICE_STOPPED` without depending on the SCM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    StartPending,
    Running,
    StopPending,
    Stopped,
}

impl LifecycleState {
    /// Stable label for logs and test assertions.
    pub fn as_str(self) -> &'static str {
        match self {
            LifecycleState::StartPending => "start_pending",
            LifecycleState::Running => "running",
            LifecycleState::StopPending => "stop_pending",
            LifecycleState::Stopped => "stopped",
        }
    }
}

/// One status report towards the service manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusReport {
    pub state: LifecycleState,
    /// Monotonic checkpoint for the pending states.
    pub checkpoint: u32,
    /// Clean (0) or non-clean exit code, meaningful when `state` is Stopped.
    pub exit_code: u32,
}

/// Destination of the lifecycle reports: the SCM in production, a vector in
/// tests.
pub trait StatusSink {
    fn report(&mut self, report: StatusReport) -> Result<()>;
}

/// Why the server stopped; each reason maps to the recorded exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    /// A stop request was answered inside the grace window.
    Graceful,
    /// A stop request finished, but the server's own shutdown returned an error.
    GracefulWithError,
    /// The grace window expired and the server task was aborted.
    ForcedAbort,
    /// The server ended on its own while it was running.
    EarlyExit,
    /// The server ended (or failed) before it ever became ready.
    FailedBeforeReady,
}

impl StopReason {
    pub fn exit_code(self) -> u32 {
        match self {
            StopReason::Graceful => 0,
            StopReason::GracefulWithError => STOP_ERROR_EXIT_CODE,
            StopReason::ForcedAbort => FORCED_STOP_EXIT_CODE,
            StopReason::EarlyExit => EARLY_EXIT_CODE,
            StopReason::FailedBeforeReady => FAILED_BEFORE_READY_EXIT_CODE,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            StopReason::Graceful => "graceful",
            StopReason::GracefulWithError => "graceful_with_error",
            StopReason::ForcedAbort => "forced_abort",
            StopReason::EarlyExit => "early_exit",
            StopReason::FailedBeforeReady => "failed_before_ready",
        }
    }
}

/// Owns the reported state so the SCM never sees an out-of-order transition.
///
/// Invariants enforced here:
///
/// * `Running` is reported only from `StartPending`, and only once;
/// * a server that ends before readiness is reported `Stopped` without ever
///   reporting `Running`;
/// * `Stopped` is terminal and reported exactly once, with the exit code of
///   the reason it was reached.
#[derive(Debug)]
pub struct LifecycleCoordinator<S: StatusSink> {
    sink: S,
    state: LifecycleState,
    checkpoint: u32,
}

impl<S: StatusSink> LifecycleCoordinator<S> {
    /// Report StartPending before the server work begins.
    pub fn start_pending(sink: S) -> Result<Self> {
        let mut coordinator = Self {
            sink,
            state: LifecycleState::StartPending,
            checkpoint: 0,
        };
        coordinator.report(0)?;
        Ok(coordinator)
    }

    /// Report Running. Returns `false` (and reports nothing) when the service
    /// already left StartPending — a stop request or an early exit wins over a
    /// late readiness notification.
    pub fn mark_ready(&mut self) -> Result<bool> {
        if self.state != LifecycleState::StartPending {
            return Ok(false);
        }
        self.state = LifecycleState::Running;
        self.report(0)?;
        Ok(true)
    }

    /// Report StopPending. Idempotent and terminal-safe: a repeated stop
    /// request, or one that arrives after the server already ended, reports
    /// nothing new.
    pub fn begin_stop(&mut self) -> Result<bool> {
        if matches!(
            self.state,
            LifecycleState::StopPending | LifecycleState::Stopped
        ) {
            return Ok(false);
        }
        self.state = LifecycleState::StopPending;
        self.report(0)?;
        Ok(true)
    }

    /// Report the final Stopped status with the exit code of `reason`.
    /// Reporting Stopped twice is a no-op.
    pub fn finish(&mut self, reason: StopReason) -> Result<()> {
        if self.state == LifecycleState::Stopped {
            return Ok(());
        }
        self.state = LifecycleState::Stopped;
        tracing::debug!(
            state = self.state.as_str(),
            reason = reason.as_str(),
            exit_code = reason.exit_code(),
            "service lifecycle transition"
        );
        self.report(reason.exit_code())
    }

    fn report(&mut self, exit_code: u32) -> Result<()> {
        if matches!(
            self.state,
            LifecycleState::StartPending | LifecycleState::StopPending
        ) {
            self.checkpoint = self.checkpoint.wrapping_add(1);
        }
        self.sink.report(StatusReport {
            state: self.state,
            checkpoint: self.checkpoint,
            exit_code,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Records every report so tests can assert the exact SCM-visible order.
    #[derive(Clone, Default)]
    struct RecordingSink {
        reports: Arc<Mutex<Vec<StatusReport>>>,
    }

    impl RecordingSink {
        fn reports(&self) -> Vec<StatusReport> {
            self.reports.lock().expect("reports lock").clone()
        }
    }

    impl StatusSink for RecordingSink {
        fn report(&mut self, report: StatusReport) -> Result<()> {
            self.reports.lock().expect("reports lock").push(report);
            Ok(())
        }
    }

    fn states(reports: &[StatusReport]) -> Vec<LifecycleState> {
        reports.iter().map(|report| report.state).collect()
    }

    #[test]
    fn reports_start_pending_first_with_increasing_checkpoints() {
        let sink = RecordingSink::default();
        let mut coordinator = LifecycleCoordinator::start_pending(sink.clone()).expect("start");

        coordinator.mark_ready().expect("ready");
        coordinator.begin_stop().expect("stop");
        coordinator.finish(StopReason::Graceful).expect("finish");

        let reports = sink.reports();
        assert_eq!(
            states(&reports),
            vec![
                LifecycleState::StartPending,
                LifecycleState::Running,
                LifecycleState::StopPending,
                LifecycleState::Stopped,
            ]
        );
        assert_eq!(reports[0].checkpoint, 1);
        assert_eq!(reports[1].checkpoint, 1);
        assert_eq!(reports[2].checkpoint, 2);
        assert_eq!(reports[3].checkpoint, 2);
        assert!(reports.iter().take(3).all(|report| report.exit_code == 0));
        assert_eq!(reports[3].exit_code, 0);
    }

    #[test]
    fn readiness_is_reported_once() {
        let sink = RecordingSink::default();
        let mut coordinator = LifecycleCoordinator::start_pending(sink.clone()).expect("start");

        assert!(coordinator.mark_ready().expect("ready"));
        assert!(!coordinator.mark_ready().expect("ready again"));

        let running = sink
            .reports()
            .into_iter()
            .filter(|report| report.state == LifecycleState::Running)
            .count();
        assert_eq!(running, 1);
    }

    #[test]
    fn late_readiness_after_a_stop_request_never_reports_running() {
        let sink = RecordingSink::default();
        let mut coordinator = LifecycleCoordinator::start_pending(sink.clone()).expect("start");

        assert!(coordinator.begin_stop().expect("stop"));
        assert!(!coordinator.mark_ready().expect("late ready"));
        coordinator.finish(StopReason::Graceful).expect("finish");

        let states = states(&sink.reports());
        assert!(!states.contains(&LifecycleState::Running));
        assert_eq!(
            states,
            vec![
                LifecycleState::StartPending,
                LifecycleState::StopPending,
                LifecycleState::Stopped
            ]
        );
    }

    #[test]
    fn server_exit_before_readiness_never_reports_running() {
        let sink = RecordingSink::default();
        let mut coordinator = LifecycleCoordinator::start_pending(sink.clone()).expect("start");

        coordinator
            .finish(StopReason::FailedBeforeReady)
            .expect("finish");

        let reports = sink.reports();
        assert_eq!(
            states(&reports),
            vec![LifecycleState::StartPending, LifecycleState::Stopped]
        );
        assert_eq!(reports[1].exit_code, FAILED_BEFORE_READY_EXIT_CODE);
    }

    #[test]
    fn stopped_is_terminal_and_reported_once() {
        let sink = RecordingSink::default();
        let mut coordinator = LifecycleCoordinator::start_pending(sink.clone()).expect("start");
        coordinator.mark_ready().expect("ready");

        coordinator.finish(StopReason::Graceful).expect("finish");
        coordinator
            .finish(StopReason::ForcedAbort)
            .expect("second finish");
        assert!(!coordinator.begin_stop().expect("late stop"));
        assert!(!coordinator.mark_ready().expect("late ready"));

        let reports = sink.reports();
        assert_eq!(
            states(&reports),
            vec![
                LifecycleState::StartPending,
                LifecycleState::Running,
                LifecycleState::Stopped
            ]
        );
        assert_eq!(reports[2].exit_code, 0);
    }

    #[test]
    fn forced_abort_records_a_non_clean_exit_code() {
        let sink = RecordingSink::default();
        let mut coordinator = LifecycleCoordinator::start_pending(sink.clone()).expect("start");
        coordinator.mark_ready().expect("ready");
        coordinator.begin_stop().expect("stop");
        coordinator.finish(StopReason::ForcedAbort).expect("finish");

        let reports = sink.reports();
        assert_eq!(
            reports.last().expect("stopped").exit_code,
            FORCED_STOP_EXIT_CODE
        );
        assert_ne!(FORCED_STOP_EXIT_CODE, 0);
    }

    #[test]
    fn every_reason_has_a_distinct_exit_code() {
        let all = [
            StopReason::Graceful,
            StopReason::GracefulWithError,
            StopReason::ForcedAbort,
            StopReason::EarlyExit,
            StopReason::FailedBeforeReady,
        ];
        let mut codes: Vec<u32> = all.iter().map(|reason| reason.exit_code()).collect();
        let total = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), total);
    }

    #[test]
    fn graceful_stop_bound_is_shorter_than_the_scm_wait_hint() {
        assert_eq!(GRACEFUL_STOP_TIMEOUT, Duration::from_secs(15));
        assert!(GRACEFUL_STOP_TIMEOUT < Duration::from_secs(30));
    }
}
