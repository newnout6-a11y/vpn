//! Registry behaviour: the vectors of the old `operationRegistry.test.ts` (AT-00-003/005/007)
//! ported to typed Rust, plus the vectors the spec added (C-02, history cap, drop = cancel).
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};
use vpnte_base::types::now_ms;
use vpnte_base::{AppError, AppResult, ErrorKind};

use super::*;

/// A future held open until the test releases it (the old tests' `held()` promise).
struct Gate(CancellationToken);

impl Gate {
    fn new() -> Self {
        Self(CancellationToken::new())
    }
    fn wait(&self) -> impl Future<Output = ()> + Send + 'static {
        self.0.clone().cancelled_owned()
    }
    fn open(&self) {
        self.0.cancel();
    }
}

fn owner(owner: Owner) -> RunOpts {
    RunOpts {
        owner,
        ..RunOpts::default()
    }
}

fn on(resource: &'static str) -> RunOpts {
    RunOpts {
        resource: Some(resource.into()),
        ..RunOpts::default()
    }
}

/// Runs `registry.run(..)` on its own task so the test can act while it is in flight.
fn spawn_run<T, F, Fut>(
    reg: &OperationRegistry,
    kind: FeatureKind,
    opts: RunOpts,
    f: F,
) -> JoinHandle<AppResult<T>>
where
    T: Send + 'static,
    F: FnOnce(Lease) -> Fut + Send + 'static,
    Fut: Future<Output = AppResult<T>> + Send + 'static,
{
    let reg = reg.clone();
    tokio::spawn(async move { reg.run(kind, opts, f).await })
}

/// Lets other tasks run until `cond` holds (bounded: a bug fails instead of hanging).
async fn until(cond: impl Fn() -> bool) {
    let waited = timeout(Duration::from_secs(5), async {
        while !cond() {
            sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
    assert!(waited.is_ok(), "condition not reached within 5 s");
}

/// A few scheduler turns, for asserting that something did NOT happen.
async fn turns() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

fn kind<T>(r: &AppResult<T>) -> Option<ErrorKind> {
    r.as_ref().err().map(|e| e.kind)
}

fn statuses(reg: &OperationRegistry) -> Vec<(OpStatus, Option<ErrorKind>)> {
    reg.list().iter().map(|m| (m.status, m.category)).collect()
}

fn status_of(failure: ErrorKind) -> OpStatus {
    if failure == ErrorKind::Cancelled {
        OpStatus::Cancelled
    } else {
        OpStatus::Error
    }
}

const ALL_ERROR_KINDS: [ErrorKind; 7] = [
    ErrorKind::Validation,
    ErrorKind::Permission,
    ErrorKind::Network,
    ErrorKind::Conflict,
    ErrorKind::Internal,
    ErrorKind::Cancelled,
    ErrorKind::Timeout,
];

/// AT-00-003: the managed deadline table of `operation.ts:64-67` and the wire names.
#[test]
fn kinds_have_the_old_deadlines_and_wire_names() {
    let secs: Vec<u64> = FeatureKind::ALL
        .iter()
        .map(|k| k.deadline().as_secs())
        .collect();
    assert_eq!(secs, [120, 600, 120, 120, 120, 600, 60, 60, 9, 60, 60]);
    for k in FeatureKind::ALL {
        let wire = serde_json::to_string(&k).unwrap();
        assert_eq!(wire, format!("\"{}\"", k.as_str()));
        let any = serde_json::to_string(&OpKind::from(k)).unwrap();
        assert_eq!(any, wire, "OpKind keeps the feature wire name");
    }
    assert_eq!(
        serde_json::to_string(&OpKind::Connect).unwrap(),
        "\"connect\""
    );
    assert_eq!(
        serde_json::to_string(&OpStatus::Cancelled).unwrap(),
        "\"cancelled\""
    );
}

/// AT-00-005: provenance source; Electron records said `ipc` for the window.
#[test]
fn source_reads_the_legacy_ipc_name() {
    let s: Source = serde_json::from_str("\"ipc\"").unwrap();
    assert_eq!(s, Source::Ui);
    assert_eq!(serde_json::to_string(&Source::Ui).unwrap(), "\"ui\"");
    assert_eq!(Source::default(), Source::Lifecycle);
    assert_eq!(RunOpts::default().owner, Owner::Manual);
}

/// C-02 (spec §7.13): generated ids keep the UUID v4 bits, so the legacy validator accepts them.
#[test]
fn correlation_ids_carry_uuid_v4_bits() {
    let re = regex::Regex::new(r"^op_[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$").unwrap();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..10_000 {
        let id = CorrelationId::new();
        assert!(re.is_match(id.as_str()), "{id}");
        assert_eq!(CorrelationId::parse(id.as_str()), Some(id.clone()));
        seen.insert(id);
    }
    assert_eq!(seen.len(), 10_000);
    for ok in [
        "ipc_3d49f22af56f4eb795812df333b9aa55",
        "op_3D49F22AF56F4EB795812DF333B9AA55",
    ] {
        assert!(CorrelationId::parse(ok).is_some(), "{ok}");
    }
    for bad in [
        "raw-secret",
        "3d49f22a-f56f-4eb7-9581-2df333b9aa55",
        "OP_3d49f22af56f4eb795812df333b9aa55",
        "op_3d49f22af56f4eb795812df333b9aa55\n",
        "op_3d49f22af56f1eb795812df333b9aa55",
        "op_3d49f22af56f4eb7c5812df333b9aa55",
        "op_3d49f22af56f4eb795812df333b9aa5",
    ] {
        assert!(CorrelationId::parse(bad).is_none(), "{bad:?}");
    }
    let json = serde_json::to_string(&CorrelationId::new()).unwrap();
    assert!(serde_json::from_str::<CorrelationId>(&json).is_ok());
    assert!(serde_json::from_str::<CorrelationId>("\"raw-secret\"").is_err());
}

/// AT-00-004/005: an effect's error (returned, or from a failed commit) is recorded with the
/// matching terminal status and its category; the caller gets the same error; an ended
/// operation cannot be cancelled.
#[tokio::test]
async fn effect_errors_record_the_matching_status() {
    for failure in ALL_ERROR_KINDS {
        for via_commit in [false, true] {
            let reg = OperationRegistry::new();
            let r: AppResult<()> = reg
                .run(
                    FeatureKind::Export,
                    RunOpts::default(),
                    move |lease| async move {
                        if via_commit {
                            lease.commit(|| Err(AppError::new(failure)))
                        } else {
                            Err(AppError::new(failure))
                        }
                    },
                )
                .await;
            assert_eq!(kind(&r), Some(failure));
            assert_eq!(statuses(&reg), [(status_of(failure), Some(failure))]);
            assert!(!reg.cancel(reg.list()[0].id));
            assert!(!reg.is_busy("export"));
        }
    }
}

/// AT-00-005: a success value that carries error data inside is still a success.
#[tokio::test]
async fn success_payload_with_error_inside_is_success() {
    let reg = OperationRegistry::new();
    let r = reg
        .run(FeatureKind::Export, RunOpts::default(), |_| async {
            Ok(Err::<(), _>(AppError::new(ErrorKind::Network)))
        })
        .await;
    assert!(matches!(r, Ok(Err(_))));
    assert_eq!(statuses(&reg), [(OpStatus::Success, None)]);
}

/// AT-00-004: what cannot be classified (a panicking effect) is recorded as internal, never
/// guessed, and the resource is freed.
#[tokio::test]
async fn panicking_effect_is_internal_and_frees_the_resource() {
    let reg = OperationRegistry::new();
    let r: AppResult<()> = reg
        .run(FeatureKind::Import, RunOpts::default(), |_| async {
            panic!("feature bug");
        })
        .await;
    assert_eq!(kind(&r), Some(ErrorKind::Internal));
    assert_eq!(
        statuses(&reg),
        [(OpStatus::Error, Some(ErrorKind::Internal))]
    );
    assert!(!reg.is_busy("import"));
}

/// AT-00-005: a quiet user dismissal is recorded as cancelled, any other refusal as an error.
#[tokio::test]
async fn quiet_user_dismissal_is_cancelled() {
    let reg = OperationRegistry::new();
    let r: AppResult<()> = reg
        .run(FeatureKind::Export, RunOpts::default(), |_| async {
            Err(AppError::cancelled())
        })
        .await;
    assert_eq!(kind(&r), Some(ErrorKind::Cancelled));
    let r: AppResult<()> = reg
        .run(FeatureKind::Export, RunOpts::default(), |_| async {
            Err(AppError::new(ErrorKind::Validation))
        })
        .await;
    assert_eq!(kind(&r), Some(ErrorKind::Validation));
    assert_eq!(
        statuses(&reg),
        [
            (OpStatus::Cancelled, Some(ErrorKind::Cancelled)),
            (OpStatus::Error, Some(ErrorKind::Validation))
        ]
    );
}

/// AT-00-007: a coordinator may expire its own lease: the caller gets a timeout at once while
/// the physical resource stays busy until the effect drains.
#[tokio::test]
async fn coordinator_expire_keeps_the_resource_until_drained() {
    let reg = OperationRegistry::new();
    let gate = Gate::new();
    let (lease_tx, lease_rx) = tokio::sync::oneshot::channel();
    let wait = gate.wait();
    let task = spawn_run(
        &reg,
        FeatureKind::ServerProbe,
        RunOpts::default(),
        |lease| async move {
            let _ = lease_tx.send(lease.clone());
            lease.wait(wait).await
        },
    );
    let lease = lease_rx.await.unwrap();
    assert!(lease.expire());
    assert_eq!(kind(&task.await.unwrap()), Some(ErrorKind::Timeout));
    assert_eq!(
        statuses(&reg),
        [(OpStatus::Error, Some(ErrorKind::Timeout))]
    );
    assert!(reg.is_busy("server-probe"));
    assert!(!lease.expire());
    gate.open();
    reg.close().await;
    assert!(!reg.is_busy("server-probe"));
}

/// AT-00-005: receipts stay distinguishable without any UUID a redactor would collapse; the
/// correlation is preserved and cancellation by id works.
#[tokio::test]
async fn receipts_stay_distinguishable() {
    let reg = OperationRegistry::new();
    let gate = Gate::new();
    let correlation = CorrelationId::new();
    let wait = gate.wait();
    let first_opts = RunOpts {
        correlation: Some(correlation.clone()),
        ..on("first")
    };
    let first = spawn_run(
        &reg,
        FeatureKind::HealthCheck,
        first_opts,
        |lease| async move { lease.wait(wait).await },
    );
    until(|| reg.is_busy("first")).await;
    reg.run(FeatureKind::HealthCheck, on("second"), |_| async { Ok(()) })
        .await
        .unwrap();
    let receipts = reg.list();
    assert_eq!(receipts.len(), 2);
    assert_ne!(receipts[0].id, receipts[1].id);
    assert_ne!(receipts[0].id.to_string(), receipts[1].id.to_string());
    assert!(receipts[0].id.to_string().starts_with("op_"));
    assert_eq!(receipts[0].correlation, correlation);
    let json = serde_json::to_string(&receipts).unwrap();
    let dashed_uuid = regex::Regex::new(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-").unwrap();
    assert!(!dashed_uuid.is_match(&json), "{json}");
    assert!(reg.cancel(receipts[0].id));
    assert_eq!(kind(&first.await.unwrap()), Some(ErrorKind::Cancelled));
    gate.open();
    reg.close().await;
}

/// AT-00-007: only user decision time is paused; afterwards the remaining budget is enforced
/// and the timed-out effect still holds the resource until it drains. (Real time: 700 ms of
/// dialog against a 300 ms budget stands in for the old fake-timer 600 s; the bounds leave
/// 150 ms for scheduling delays on a loaded machine.)
#[tokio::test]
async fn user_wait_pauses_only_decision_time() {
    let reg = OperationRegistry::new();
    let (dialog, work) = (Gate::new(), Gate::new());
    let (d, w) = (dialog.wait(), work.wait());
    let opts = RunOpts {
        timeout: Some(Duration::from_millis(300)),
        ..RunOpts::default()
    };
    let task = spawn_run(&reg, FeatureKind::Export, opts, |lease| async move {
        lease.wait_for_user(d).await?;
        lease.wait(w).await
    });
    until(|| reg.list().first().is_some_and(|m| m.deadline.is_none())).await;
    sleep(Duration::from_millis(700)).await;
    assert_eq!(reg.list()[0].status, OpStatus::Running);
    assert!(!task.is_finished());
    let (released, resumed) = (now_ms(), Instant::now());
    dialog.open();
    until(|| reg.list()[0].deadline.is_some()).await;
    let deadline = reg.list()[0].deadline.unwrap();
    assert!(
        deadline >= released + 150 && deadline <= now_ms() + 300,
        "{deadline} / {released}"
    );
    assert_eq!(kind(&task.await.unwrap()), Some(ErrorKind::Timeout));
    assert!(resumed.elapsed() >= Duration::from_millis(150));
    assert_eq!(
        statuses(&reg),
        [(OpStatus::Error, Some(ErrorKind::Timeout))]
    );
    assert!(reg.is_busy("export"));
    work.open();
    reg.close().await;
    assert!(!reg.is_busy("export"));
}

/// AT-00-007: cancelling during a dialog is prompt; the effect after the dialog never runs and
/// the late dialog completion does not restart the budget.
#[tokio::test]
async fn user_wait_cancellation_is_prompt() {
    let reg = OperationRegistry::new();
    let dialog = Gate::new();
    let d = dialog.wait();
    let after = Arc::new(AtomicUsize::new(0));
    let after2 = after.clone();
    let task = spawn_run(
        &reg,
        FeatureKind::Import,
        RunOpts::default(),
        |lease| async move {
            lease.wait_for_user(d).await?;
            after2.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );
    until(|| reg.list().first().is_some_and(|m| m.deadline.is_none())).await;
    assert!(reg.cancel(reg.list()[0].id));
    assert_eq!(kind(&task.await.unwrap()), Some(ErrorKind::Cancelled));
    dialog.open();
    reg.close().await;
    assert_eq!(after.load(Ordering::SeqCst), 0);
    assert_eq!(reg.list()[0].deadline, None);
    assert_eq!(
        statuses(&reg),
        [(OpStatus::Cancelled, Some(ErrorKind::Cancelled))]
    );
}

/// AT-00-003/007: a synchronous final commit is terminal before a late abort can relabel the
/// persisted success.
#[tokio::test]
async fn commit_wins_over_a_late_abort() {
    let reg = OperationRegistry::new();
    let cancel = CancellationToken::new();
    let persisted = Arc::new(AtomicUsize::new(0));
    let (p, c, reg2) = (persisted.clone(), cancel.clone(), reg.clone());
    let opts = RunOpts {
        cancel: Some(cancel.clone()),
        ..RunOpts::default()
    };
    let r = reg
        .run(FeatureKind::Export, opts, move |lease| async move {
            let saved = lease.commit(|| {
                p.fetch_add(1, Ordering::SeqCst);
                Ok("selected.json")
            })?;
            c.cancel();
            assert!(!reg2.cancel(lease.id()));
            assert!(!lease.cancel());
            Ok(saved)
        })
        .await;
    assert_eq!(r.unwrap(), "selected.json");
    assert_eq!(persisted.load(Ordering::SeqCst), 1);
    assert!(cancel.is_cancelled());
    assert_eq!(statuses(&reg), [(OpStatus::Success, None)]);
    assert!(!reg.cancel(reg.list()[0].id));
}

/// AT-00-007: the final commit is refused while tracked I/O is still physically pending.
#[tokio::test]
async fn commit_is_refused_while_tracked_io_is_pending() {
    let reg = OperationRegistry::new();
    let gate = Gate::new();
    let w = gate.wait();
    let persisted = Arc::new(AtomicUsize::new(0));
    let p = persisted.clone();
    let task = spawn_run(
        &reg,
        FeatureKind::Export,
        RunOpts::default(),
        move |lease| async move {
            let _pending = lease.wait(w);
            lease.commit(|| {
                p.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        },
    );
    until(|| {
        reg.list()
            .first()
            .is_some_and(|m| m.status != OpStatus::Running)
    })
    .await;
    assert_eq!(persisted.load(Ordering::SeqCst), 0);
    assert!(reg.is_busy("export"));
    gate.open();
    assert_eq!(kind(&task.await.unwrap()), Some(ErrorKind::Conflict));
    assert_eq!(
        statuses(&reg),
        [(OpStatus::Error, Some(ErrorKind::Conflict))]
    );
}

/// AT-00-004: a failed final commit is an error with its category, never a persisted success.
#[tokio::test]
async fn failed_commit_records_the_error() {
    let reg = OperationRegistry::new();
    let r: AppResult<()> = reg
        .run(
            FeatureKind::Import,
            RunOpts::default(),
            |lease| async move {
                lease.commit(|| {
                    Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied).into())
                })
            },
        )
        .await;
    assert_eq!(kind(&r), Some(ErrorKind::Permission));
    assert_eq!(
        statuses(&reg),
        [(OpStatus::Error, Some(ErrorKind::Permission))]
    );
}

/// AT-00-007: cancellation from inside the commit (re-entrant observer) is refused and the
/// commit completes.
#[tokio::test]
async fn cancellation_inside_commit_is_refused() {
    let reg = OperationRegistry::new();
    let cancel = CancellationToken::new();
    let steps = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let (s, c, reg2) = (steps.clone(), cancel.clone(), reg.clone());
    let opts = RunOpts {
        cancel: Some(cancel),
        ..RunOpts::default()
    };
    let r = reg
        .run(FeatureKind::Export, opts, move |lease| async move {
            lease.commit(|| {
                s.lock().push("before");
                assert!(!reg2.cancel(lease.id()));
                assert!(!lease.expire());
                c.cancel();
                s.lock().push("after");
                Ok("saved")
            })
        })
        .await;
    assert_eq!(r.unwrap(), "saved");
    assert_eq!(*steps.lock(), ["before", "after"]);
    assert_eq!(statuses(&reg), [(OpStatus::Success, None)]);
}

/// Multi-thread hardening (review): an abort that lands during a commit (another thread can,
/// the old single-threaded registry could not) is refused, but applies right after a failed
/// commit, the first one winning, even when the effect ignores the failure and keeps going.
#[tokio::test]
async fn abort_during_a_failed_commit_applies_after_it() {
    let reg = OperationRegistry::new();
    let reg2 = reg.clone();
    let r: AppResult<()> = reg
        .run(
            FeatureKind::Export,
            RunOpts::default(),
            move |lease| async move {
                let failed = lease.commit(|| {
                    assert!(!lease.expire());
                    assert!(!reg2.cancel(lease.id()));
                    Err::<(), _>(AppError::new(ErrorKind::Permission))
                });
                assert_eq!(kind(&failed), Some(ErrorKind::Permission));
                lease.assert_active()
            },
        )
        .await;
    assert_eq!(kind(&r), Some(ErrorKind::Timeout));
    assert_eq!(
        statuses(&reg),
        [(OpStatus::Error, Some(ErrorKind::Timeout))]
    );
}

/// Review remainder: a panic inside the commit closure lowers the fence like a failed commit,
/// so a caller that catches it still sees the abort that landed meanwhile (before the fix the
/// operation stayed uncancellable and was recorded as a success).
#[tokio::test]
async fn panic_inside_commit_lowers_the_fence() {
    let reg = OperationRegistry::new();
    let reg2 = reg.clone();
    let r: AppResult<()> = reg
        .run(
            FeatureKind::Export,
            RunOpts::default(),
            move |lease| async move {
                let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    lease.commit(|| -> AppResult<()> {
                        assert!(!reg2.cancel(lease.id()));
                        panic!("commit closure fails hard");
                    })
                }));
                assert!(caught.is_err());
                lease.assert_active()
            },
        )
        .await;
    assert_eq!(kind(&r), Some(ErrorKind::Cancelled));
    assert_eq!(
        statuses(&reg),
        [(OpStatus::Cancelled, Some(ErrorKind::Cancelled))]
    );
}

/// Collects formatted log output (DEBUG and up, this thread) while the returned guard lives.
#[derive(Clone, Default)]
struct Capture(Arc<parking_lot::Mutex<Vec<u8>>>);

impl Capture {
    fn install() -> (Self, tracing::subscriber::DefaultGuard) {
        let logs = Self::default();
        let sink = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || sink.clone())
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        (logs, tracing::subscriber::set_default(subscriber))
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock()).into_owned()
    }
}

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// AT-00-005: a failure after the commit does not relabel the committed success; it is logged
/// as a post-commit failure with its category only, never its text. (Rust returns the
/// effect's own result: the committed value cannot be handed back without a second copy.)
#[tokio::test]
async fn failure_after_commit_keeps_success_and_logs_the_category_only() {
    let (logs, _guard) = Capture::install();
    let reg = OperationRegistry::new();
    let r: AppResult<&str> = reg
        .run(
            FeatureKind::Export,
            RunOpts::default(),
            |lease| async move {
                lease.commit(|| Ok("persisted"))?;
                Err(AppError::internal(anyhow::anyhow!("SECRET-DETAIL")))
            },
        )
        .await;
    assert_eq!(kind(&r), Some(ErrorKind::Internal));
    assert_eq!(statuses(&reg), [(OpStatus::Success, None)]);
    let text = logs.text();
    assert!(text.contains("feature post-commit failure"), "{text}");
    assert!(text.contains("Internal"), "{text}");
    assert!(!text.contains("SECRET-DETAIL"), "{text}");
}

/// Storage spec §6.5 / lifecycle §3.4: every registry line and every line the effect logs carry
/// the action's correlation in the `corr` field, the one core-log lifts into a line's
/// correlation slot (it was `correlation_id`, which stayed an ordinary field).
#[tokio::test]
async fn log_lines_carry_the_correlation_as_corr() {
    let (logs, _guard) = Capture::install();
    let reg = OperationRegistry::new();
    let correlation = CorrelationId::new();
    let opts = RunOpts {
        correlation: Some(correlation.clone()),
        ..RunOpts::default()
    };
    reg.run(FeatureKind::Snapshot, opts, |lease| async move {
        tracing::info!("feature step");
        lease.wait_for_user(async {}).await
    })
    .await
    .unwrap();
    let text = logs.text();
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("feature operation") || l.contains("feature step"))
        .collect();
    // Admission, user-wait pause and resume, success, and the effect's own line.
    assert_eq!(lines.len(), 5, "{text}");
    let corr = format!("corr={correlation}");
    assert!(lines.iter().all(|l| l.contains(&corr)), "{text}");
    assert!(!text.contains("correlation_id"), "{text}");
}

/// AT-00-007: the canonical flow (`wait_for_user`, `wait`, then `commit`) succeeds: a settled
/// tracked wait no longer counts as pending I/O, also across worker threads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_after_settled_waits_succeeds() {
    let reg = OperationRegistry::new();
    for _ in 0..50 {
        let r = reg
            .run(
                FeatureKind::Import,
                RunOpts::default(),
                |lease| async move {
                    let picked = lease.wait_for_user(async { "profiles.json" }).await?;
                    let size = lease
                        .wait(async move {
                            tokio::task::yield_now().await;
                            picked.len()
                        })
                        .await?;
                    lease.commit(|| Ok(size))
                },
            )
            .await;
        assert_eq!(r.unwrap(), "profiles.json".len());
    }
    assert!(reg.list().iter().all(|m| m.status == OpStatus::Success));
}

/// AT-00-003/007: cancelling any kind at 10 / 50 / 90 % of its work: the caller learns at once,
/// the lease signal fires, nothing is published late, the resource stays busy (a new run
/// conflicts) until the effect drains, and subscribers see exactly running → cancelled.
#[tokio::test]
async fn cancel_any_kind_at_any_progress() {
    for k in FeatureKind::ALL {
        for progress in [1, 5, 9] {
            let reg = OperationRegistry::new();
            let mut events = reg.subscribe();
            let (gate, entered) = (Gate::new(), Gate::new());
            let (w, entered_tx) = (gate.wait(), entered.0.clone());
            let cancel = CancellationToken::new();
            let published = Arc::new(AtomicUsize::new(0));
            let (pub2, token_slot) = (published.clone(), Arc::new(parking_lot::Mutex::new(None)));
            let slot = token_slot.clone();
            let opts = RunOpts {
                cancel: Some(cancel.clone()),
                ..RunOpts::default()
            };
            let task = spawn_run(&reg, k, opts, move |lease| async move {
                *slot.lock() = Some(lease.token().clone());
                let mut w = Some(w);
                for step in 1..=10 {
                    if step == progress {
                        entered_tx.cancel();
                        if let Some(w) = w.take() {
                            lease.wait(w).await?;
                        }
                    }
                    lease.assert_active()?;
                    pub2.fetch_add(1, Ordering::SeqCst);
                }
                Ok(())
            });
            entered.wait().await;
            turns().await;
            let before = published.load(Ordering::SeqCst);
            cancel.cancel();
            assert_eq!(
                kind(&task.await.unwrap()),
                Some(ErrorKind::Cancelled),
                "{k}"
            );
            assert!(token_slot.lock().as_ref().is_some_and(|t| t.is_cancelled()));
            let list = reg.list();
            assert_eq!(
                (list[0].kind, list[0].status),
                (OpKind::from(k), OpStatus::Cancelled)
            );
            assert!(reg.is_busy(k.as_str()));
            let again = reg.run(k, RunOpts::default(), |_| async { Ok(()) }).await;
            assert_eq!(kind(&again), Some(ErrorKind::Conflict));
            gate.open();
            until(|| !reg.is_busy(k.as_str())).await;
            assert_eq!(published.load(Ordering::SeqCst), before);
            let mut seen = Vec::new();
            while let Ok(meta) = events.try_recv() {
                seen.push(meta.status);
            }
            assert_eq!(
                seen,
                [OpStatus::Running, OpStatus::Cancelled],
                "{k} at {progress}"
            );
        }
    }
}

/// AT-00-003/007: every kind honours a typed deadline while `close()` still waits for the
/// actual late effect; nothing is published late and the closed registry refuses new work.
#[tokio::test]
async fn deadline_per_kind_and_close_waits_for_the_late_effect() {
    let checks = FeatureKind::ALL.map(|k| async move {
        let reg = OperationRegistry::new();
        let gate = Gate::new();
        let w = gate.wait();
        let published = Arc::new(AtomicUsize::new(0));
        let pub2 = published.clone();
        let opts = RunOpts {
            timeout: Some(Duration::from_millis(100)),
            ..RunOpts::default()
        };
        let r = reg
            .run(k, opts, move |lease| async move {
                lease.wait(w).await?;
                pub2.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await;
        assert_eq!(kind(&r), Some(ErrorKind::Timeout), "{k}");
        assert_eq!(
            statuses(&reg),
            [(OpStatus::Error, Some(ErrorKind::Timeout))]
        );
        let reg2 = reg.clone();
        let closing = tokio::spawn(async move { reg2.close().await });
        turns().await;
        assert!(
            !closing.is_finished(),
            "{k}: close must wait for the late effect"
        );
        gate.open();
        closing.await.unwrap();
        assert_eq!(published.load(Ordering::SeqCst), 0);
        let after = reg.run(k, RunOpts::default(), |_| async { Ok(()) }).await;
        assert_eq!(kind(&after), Some(ErrorKind::Conflict));
    });
    futures_util::future::join_all(checks).await;
}

/// AT-00-005: admission assigns the id and the real deadline (the full budget when admitted at
/// once) and keeps the caller's correlation, source and owner; `list()` hands out copies.
#[tokio::test]
async fn admission_assigns_the_metadata() {
    let reg = OperationRegistry::new();
    let correlation = CorrelationId::parse("ipc_3d49f22af56f4eb795812df333b9aa55").unwrap();
    let opts = RunOpts {
        owner: Owner::Schedule,
        source: Source::Ui,
        timeout: Some(Duration::from_millis(2000)),
        correlation: Some(correlation.clone()),
        ..RunOpts::default()
    };
    let reg2 = reg.clone();
    reg.run(FeatureKind::Refresh, opts, move |lease| async move {
        let meta = lease.meta().unwrap();
        assert_eq!(lease.correlation(), &correlation);
        assert_eq!(meta.correlation, correlation);
        assert_eq!((meta.source, meta.owner), (Source::Ui, Owner::Schedule));
        assert_eq!(
            (meta.kind, meta.status, meta.id),
            (OpKind::Refresh, OpStatus::Running, lease.id())
        );
        // The full budget when admitted at once, less any scheduling delay before admission
        // (a Windows quantum is ~16 ms, so an exact equality can fail on a loaded machine).
        let budget = meta.deadline.unwrap() - meta.started_at;
        assert!((1900..=2000).contains(&budget), "{budget}");
        let mut copy = reg2.list().remove(0);
        copy.status = OpStatus::Error;
        assert_eq!(lease.meta().unwrap().status, OpStatus::Running);
        Ok(())
    })
    .await
    .unwrap();
    assert_eq!(statuses(&reg), [(OpStatus::Success, None)]);
}

/// AT-00-003/007: higher-priority work cancels its predecessor but is admitted only after the
/// predecessor drained; an equal or lower owner conflicts.
#[tokio::test]
async fn higher_priority_preempts_after_the_drain() {
    let reg = OperationRegistry::new();
    let gate = Gate::new();
    let w = gate.wait();
    let previous = spawn_run(
        &reg,
        FeatureKind::Refresh,
        owner(Owner::Schedule),
        |lease| async move {
            lease.wait(w).await?;
            Ok(true)
        },
    );
    until(|| reg.is_busy("refresh")).await;
    for same_or_lower in [Owner::Schedule, Owner::Rotation] {
        let r = reg
            .run(FeatureKind::Refresh, owner(same_or_lower), |_| async {
                Ok(false)
            })
            .await;
        assert_eq!(kind(&r), Some(ErrorKind::Conflict));
    }
    let entered = Arc::new(AtomicUsize::new(0));
    let e2 = entered.clone();
    let next = spawn_run(
        &reg,
        FeatureKind::Refresh,
        RunOpts::default(),
        move |_| async move {
            e2.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        },
    );
    assert_eq!(kind(&previous.await.unwrap()), Some(ErrorKind::Cancelled));
    turns().await;
    assert_eq!(entered.load(Ordering::SeqCst), 0);
    gate.open();
    assert!(next.await.unwrap().unwrap());
    let s: Vec<OpStatus> = reg.list().iter().map(|m| m.status).collect();
    assert_eq!(s, [OpStatus::Cancelled, OpStatus::Success]);
}

/// AT-00-003/007: shutdown cancels every resource and refuses new work, including a
/// replacement already waiting for a drain.
#[tokio::test]
async fn close_cancels_everything_and_refuses_a_queued_replacement() {
    let reg = OperationRegistry::new();
    let (first, second) = (Gate::new(), Gate::new());
    let (w1, w2) = (first.wait(), second.wait());
    let a = spawn_run(
        &reg,
        FeatureKind::Refresh,
        owner(Owner::Schedule),
        |lease| async move { lease.wait(w1).await },
    );
    let b = spawn_run(
        &reg,
        FeatureKind::SpeedTest,
        RunOpts::default(),
        |lease| async move { lease.wait(w2).await },
    );
    until(|| reg.is_busy("refresh") && reg.is_busy("speed-test")).await;
    let ran = Arc::new(AtomicUsize::new(0));
    let ran2 = ran.clone();
    let c = spawn_run(
        &reg,
        FeatureKind::Refresh,
        RunOpts::default(),
        move |_| async move {
            ran2.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );
    until(|| reg.list()[0].status == OpStatus::Cancelled).await;
    let reg2 = reg.clone();
    let closing = tokio::spawn(async move { reg2.close().await });
    assert_eq!(kind(&a.await.unwrap()), Some(ErrorKind::Cancelled));
    assert_eq!(kind(&b.await.unwrap()), Some(ErrorKind::Cancelled));
    first.open();
    second.open();
    closing.await.unwrap();
    assert_eq!(kind(&c.await.unwrap()), Some(ErrorKind::Conflict));
    assert_eq!(ran.load(Ordering::SeqCst), 0);
}

/// AT-00-007: a replacement waiting for a drain ends promptly when it is cancelled, runs out
/// of time or the registry closes; the predecessor keeps the resource meanwhile.
#[tokio::test]
async fn queued_replacement_ends_promptly() {
    for expected in [
        ErrorKind::Cancelled,
        ErrorKind::Timeout,
        ErrorKind::Conflict,
    ] {
        let reg = OperationRegistry::new();
        let gate = Gate::new();
        let w = gate.wait();
        let previous = spawn_run(
            &reg,
            FeatureKind::Refresh,
            owner(Owner::Schedule),
            |lease| async move { lease.wait(w).await },
        );
        until(|| reg.is_busy("refresh")).await;
        let cancel = CancellationToken::new();
        let ran = Arc::new(AtomicUsize::new(0));
        let ran2 = ran.clone();
        let opts = RunOpts {
            cancel: Some(cancel.clone()),
            timeout: Some(Duration::from_millis(100)),
            ..RunOpts::default()
        };
        let next = spawn_run(&reg, FeatureKind::Refresh, opts, move |_| async move {
            ran2.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        until(|| reg.list()[0].status == OpStatus::Cancelled).await;
        let mut closing = None;
        match expected {
            ErrorKind::Cancelled => cancel.cancel(),
            ErrorKind::Conflict => {
                let reg2 = reg.clone();
                closing = Some(tokio::spawn(async move { reg2.close().await }));
            }
            _ => {}
        }
        let r = timeout(Duration::from_secs(2), next)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(kind(&r), Some(expected));
        assert!(reg.is_busy("refresh"));
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        gate.open();
        let _ = previous.await;
        if let Some(closing) = closing {
            closing.await.unwrap();
        }
        reg.close().await;
    }
}

/// AT-00-003: the admission wait counts against the newcomer's deadline on the monotonic clock
/// and the published deadline is the real one (fixes the old full-budget display). The
/// calendar-jump half of the old vector holds by construction (`Instant` deadlines); tests
/// never change the system clock.
#[tokio::test]
async fn admission_wait_counts_against_the_deadline() {
    let reg = OperationRegistry::new();
    let (first, second) = (Gate::new(), Gate::new());
    let (w1, w2) = (first.wait(), second.wait());
    let previous = spawn_run(
        &reg,
        FeatureKind::Refresh,
        owner(Owner::Schedule),
        |lease| async move { lease.wait(w1).await },
    );
    until(|| reg.is_busy("refresh")).await;
    let admitted = Arc::new(parking_lot::Mutex::new(None));
    let a2 = admitted.clone();
    let opts = RunOpts {
        timeout: Some(Duration::from_millis(400)),
        ..RunOpts::default()
    };
    let called = Instant::now();
    let next = spawn_run(&reg, FeatureKind::Refresh, opts, move |lease| {
        *a2.lock() = Some(Instant::now());
        async move { lease.wait(w2).await }
    });
    sleep(Duration::from_millis(200)).await;
    first.open();
    let _ = previous.await;
    until(|| admitted.lock().is_some()).await;
    let meta = reg.list()[1].clone();
    assert!(meta.deadline.unwrap() - meta.started_at <= 250, "{meta:?}");
    assert_eq!(kind(&next.await.unwrap()), Some(ErrorKind::Timeout));
    // Admitted after the ~200 ms drain wait, timed out at the original 400 ms budget end: a
    // fresh budget from admission would end at ~600 ms.
    let admitted_at = admitted.lock().unwrap();
    assert!(admitted_at.duration_since(called) >= Duration::from_millis(190));
    let ended = called.elapsed();
    assert!(ended >= Duration::from_millis(390) && ended < Duration::from_millis(560));
    assert!(reg.is_busy("refresh"));
    second.open();
    reg.close().await;
}

/// AT-00-007 / A-06: after a refused quit admission resumes only once old effects drained, and
/// an old queued replacement is never revived.
#[tokio::test]
async fn resume_admission_after_a_refused_quit() {
    let reg = OperationRegistry::new();
    let gate = Gate::new();
    let w = gate.wait();
    let first = spawn_run(
        &reg,
        FeatureKind::Refresh,
        owner(Owner::Schedule),
        |lease| async move { lease.wait(w).await },
    );
    until(|| reg.is_busy("refresh")).await;
    let ran = Arc::new(AtomicUsize::new(0));
    let ran2 = ran.clone();
    let waiting = spawn_run(
        &reg,
        FeatureKind::Refresh,
        RunOpts::default(),
        move |_| async move {
            ran2.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );
    until(|| reg.list()[0].status == OpStatus::Cancelled).await;
    assert!(reg.resume_admission(), "an open registry reports true");
    let reg2 = reg.clone();
    let closing = tokio::spawn(async move { reg2.close().await });
    until(|| waiting.is_finished()).await;
    assert!(!reg.resume_admission());
    gate.open();
    closing.await.unwrap();
    assert!(reg.resume_admission());
    assert_eq!(kind(&first.await.unwrap()), Some(ErrorKind::Cancelled));
    assert_eq!(kind(&waiting.await.unwrap()), Some(ErrorKind::Conflict));
    assert_eq!(ran.load(Ordering::SeqCst), 0);
    let fresh = reg.run(FeatureKind::Refresh, RunOpts::default(), |_| async {
        Ok("fresh")
    });
    assert_eq!(fresh.await.unwrap(), "fresh");
    reg.close().await;
    let r = reg
        .run(FeatureKind::Refresh, RunOpts::default(), |_| async {
            Ok(())
        })
        .await;
    assert_eq!(kind(&r), Some(ErrorKind::Conflict));
}

/// AT-00-007: cancel reaches only the requested live operation; a late failure of its physical
/// effect is absorbed.
#[tokio::test]
async fn cancel_targets_only_the_requested_operation() {
    let reg = OperationRegistry::new();
    let (tx, rx) = tokio::sync::oneshot::channel::<Result<(), &'static str>>();
    let task = spawn_run(
        &reg,
        FeatureKind::Import,
        RunOpts::default(),
        |lease| async move { lease.wait(rx).await.map(|_| ()) },
    );
    until(|| reg.is_busy("import")).await;
    assert!(!reg.cancel(OpId::next()));
    let id = reg.list()[0].id;
    assert!(reg.cancel(id));
    assert!(!reg.cancel(id));
    assert_eq!(kind(&task.await.unwrap()), Some(ErrorKind::Cancelled));
    let _ = tx.send(Err("late native error"));
    reg.close().await;
    assert_eq!(
        statuses(&reg),
        [(OpStatus::Cancelled, Some(ErrorKind::Cancelled))]
    );
}

/// AT-00-007: an invalid work budget is a validation error before admission; nothing recorded.
#[tokio::test]
async fn invalid_timeouts_are_rejected_before_admission() {
    let reg = OperationRegistry::new();
    let too_long = Duration::from_millis(1 << 31);
    for bad in [
        Duration::ZERO,
        Duration::from_micros(999),
        too_long,
        Duration::MAX,
    ] {
        let entered = Arc::new(AtomicUsize::new(0));
        let e2 = entered.clone();
        let opts = RunOpts {
            timeout: Some(bad),
            ..RunOpts::default()
        };
        let r = reg
            .run(FeatureKind::Export, opts, move |_| {
                e2.fetch_add(1, Ordering::SeqCst);
                async { Ok(()) }
            })
            .await;
        assert_eq!(kind(&r), Some(ErrorKind::Validation), "{bad:?}");
        assert_eq!(entered.load(Ordering::SeqCst), 0);
    }
    assert!(reg.list().is_empty());
}

/// AT-00-003: neither a silent subscriber nor a forgotten await strands the lease: the
/// operation stays running until the spawned wait settles, then succeeds and frees the resource.
#[tokio::test]
async fn forgotten_await_still_drains() {
    let reg = OperationRegistry::new();
    let _unread = reg.subscribe();
    let gate = Gate::new();
    let w = gate.wait();
    let task = spawn_run(
        &reg,
        FeatureKind::Export,
        RunOpts::default(),
        |lease| async move {
            let _forgotten = lease.wait(w);
            Ok("done")
        },
    );
    until(|| reg.is_busy("export")).await;
    turns().await;
    assert_eq!(reg.list()[0].status, OpStatus::Running);
    assert!(!task.is_finished());
    gate.open();
    assert_eq!(task.await.unwrap().unwrap(), "done");
    assert!(!reg.is_busy("export"));
    assert_eq!(statuses(&reg), [(OpStatus::Success, None)]);
}

/// AT-00-004/007: the effect's own failure is recorded at once with its category and aborts
/// sibling effects; the caller gets the original error once they drained.
#[tokio::test]
async fn own_failure_aborts_siblings_and_keeps_the_category() {
    let reg = OperationRegistry::new();
    let gate = Gate::new();
    let w = gate.wait();
    let slot = Arc::new(parking_lot::Mutex::new(None));
    let s2 = slot.clone();
    let task = spawn_run(
        &reg,
        FeatureKind::Export,
        RunOpts::default(),
        move |lease| async move {
            *s2.lock() = Some(lease.token().clone());
            let _sibling = lease.wait(w);
            let denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
            Err::<(), _>(AppError::from(denied))
        },
    );
    until(|| {
        reg.list()
            .first()
            .is_some_and(|m| m.status != OpStatus::Running)
    })
    .await;
    assert!(slot.lock().as_ref().is_some_and(|t| t.is_cancelled()));
    assert_eq!(
        statuses(&reg),
        [(OpStatus::Error, Some(ErrorKind::Permission))]
    );
    turns().await;
    assert!(!task.is_finished());
    gate.open();
    assert_eq!(kind(&task.await.unwrap()), Some(ErrorKind::Permission));
}

/// Spec §3.3: the history keeps 1000 records and evicts the oldest finished one, never a live one.
#[tokio::test]
async fn history_is_capped_and_keeps_live_records() {
    use super::state::HISTORY_CAP;
    let reg = OperationRegistry::new();
    let gate = Gate::new();
    let w = gate.wait();
    let live = spawn_run(
        &reg,
        FeatureKind::SpeedTest,
        RunOpts::default(),
        |lease| async move { lease.wait(w).await },
    );
    until(|| reg.is_busy("speed-test")).await;
    let live_id = reg.list()[0].id;
    for _ in 0..HISTORY_CAP + 5 {
        reg.run(FeatureKind::Snapshot, RunOpts::default(), |_| async {
            Ok(())
        })
        .await
        .unwrap();
    }
    let list = reg.list();
    assert_eq!(list.len(), HISTORY_CAP);
    assert_eq!((list[0].id, list[0].status), (live_id, OpStatus::Running));
    assert!(list[1..].iter().all(|m| m.status == OpStatus::Success));
    gate.open();
    live.await.unwrap().unwrap();
}

/// Decision (core-ops): dropping the caller's `run` future cancels the operation (an unmounted
/// UI component); the effect still drains before the resource is free.
#[tokio::test]
async fn dropping_the_caller_cancels_the_operation() {
    let reg = OperationRegistry::new();
    let gate = Gate::new();
    let w = gate.wait();
    let run = reg.run(
        FeatureKind::LeakCheck,
        RunOpts::default(),
        |lease| async move { lease.wait(w).await },
    );
    assert!(timeout(Duration::from_millis(50), run).await.is_err());
    assert_eq!(
        statuses(&reg),
        [(OpStatus::Cancelled, Some(ErrorKind::Cancelled))]
    );
    assert!(reg.is_busy("leak-check"));
    gate.open();
    until(|| !reg.is_busy("leak-check")).await;
}

/// Decrements a counter when dropped (an effect or a tracked task leaving the resource).
struct Inside(Arc<AtomicUsize>);

impl Drop for Inside {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Stress on a multi-thread runtime: concurrent runs of every owner with pre-emption, caller
/// cancels, deadlines and a final close never overlap two operations on one resource (effect
/// or tracked task), never strand the resource, always answer the caller and leave no
/// "running" record behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_runs_keep_single_flight() {
    let reg = OperationRegistry::new();
    let (effects, tracked) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let overlaps = Arc::new(AtomicUsize::new(0));
    let owners = [
        Owner::AdaptiveRetry,
        Owner::Autopilot,
        Owner::Rotation,
        Owner::Schedule,
        Owner::Manual,
        Owner::Recovery,
    ];
    let mut callers = Vec::new();
    for i in 0..300 {
        let (effects, tracked, overlaps) = (effects.clone(), tracked.clone(), overlaps.clone());
        let cancel = CancellationToken::new();
        let opts = RunOpts {
            owner: owners[fastrand::usize(..owners.len())],
            resource: Some("shared".into()),
            timeout: Some(Duration::from_millis(if i % 3 == 0 { 5 } else { 200 })),
            cancel: Some(cancel.clone()),
            ..RunOpts::default()
        };
        let reg = reg.clone();
        callers.push(tokio::spawn(async move {
            if i % 4 == 0 {
                tokio::spawn(async move {
                    sleep(Duration::from_millis(fastrand::u64(0..4))).await;
                    cancel.cancel();
                });
            }
            reg.run(FeatureKind::Refresh, opts, move |lease| async move {
                if effects.fetch_add(1, Ordering::SeqCst) != 0
                    || tracked.load(Ordering::SeqCst) != 0
                {
                    overlaps.fetch_add(1, Ordering::SeqCst);
                }
                let _inside = Inside(effects);
                tracked.fetch_add(1, Ordering::SeqCst);
                let in_task = Inside(tracked);
                lease
                    .wait(async move {
                        let _in_task = in_task;
                        sleep(Duration::from_millis(fastrand::u64(0..3))).await;
                    })
                    .await?;
                lease.assert_active()
            })
            .await
        }));
        if i % 5 == 0 {
            sleep(Duration::from_millis(1)).await;
        }
    }
    sleep(Duration::from_millis(5)).await;
    timeout(Duration::from_secs(10), reg.close())
        .await
        .expect("close drains");
    for caller in callers {
        let answered = timeout(Duration::from_secs(10), caller).await;
        assert!(answered.is_ok(), "a caller never got its answer");
    }
    assert_eq!(overlaps.load(Ordering::SeqCst), 0);
    assert!(!reg.is_busy("shared"));
    let records = reg.list();
    assert!(records.iter().all(|m| m.status != OpStatus::Running));
    for seen in [OpStatus::Success, OpStatus::Cancelled] {
        assert!(
            records.iter().any(|m| m.status == seen),
            "no {seen:?} among {}",
            records.len()
        );
    }
    assert!(reg.resume_admission());
}
