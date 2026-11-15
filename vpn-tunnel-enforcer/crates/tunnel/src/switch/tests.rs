//! Vectors of tunnel-core §7.16 (old `protectedOutboundSwitch.test.ts`), driven by a scripted
//! fake. The fake logs `<op>:<slot>` on entry; `stage` adds the slot to the running set and
//! `stop` removes it. A hold parks one call until the test releases it: after the call's effect
//! for stage / probe / select / confirm, before it for stop.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, ErrorKind};

use super::{SwitchOps, run_protected_switch};
use crate::api::{Slot, SwitchOutcome, SwitchPhase, SwitchReceipt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Stage,
    Probe,
    Select,
    Confirm,
    Stop,
}

impl Op {
    const BOUNDARIES: [Op; 4] = [Op::Stage, Op::Probe, Op::Select, Op::Confirm];

    fn name(self) -> &'static str {
        match self {
            Op::Stage => "stage",
            Op::Probe => "probe",
            Op::Select => "select",
            Op::Confirm => "confirm",
            Op::Stop => "stop",
        }
    }
}

fn name(slot: Slot) -> &'static str {
    match slot {
        Slot::A => "a",
        Slot::B => "b",
    }
}

/// State the test observes and changes while the switch runs.
struct Shared {
    running: Mutex<Vec<Slot>>,
    owner: AtomicBool,
    calls: Mutex<Vec<String>>,
    entered: Notify,
    release: Notify,
}

impl Shared {
    fn running(&self) -> Vec<Slot> {
        let mut v = self.running.lock().clone();
        v.sort_by_key(|s| name(*s));
        v
    }
    fn kill(&self, slot: Slot) {
        self.running.lock().retain(|s| *s != slot);
    }
    fn supersede(&self) {
        self.owner.store(false, Ordering::SeqCst);
    }
    fn calls(&self) -> Vec<String> {
        self.calls.lock().clone()
    }
    fn count(&self, op: Op) -> usize {
        let prefix = format!("{}:", op.name());
        self.calls()
            .iter()
            .filter(|c| c.starts_with(&prefix))
            .count()
    }
}

/// What the fake does besides its plain effect.
#[derive(Default)]
struct Script {
    /// Park the first matching call (`None` slot = any slot).
    hold: Option<(Op, Option<Slot>)>,
    /// Calls that fail before any effect (`None` slot = any slot).
    fail: Vec<(Op, Option<Slot>)>,
    /// `stop` returns `Ok` but the process stays alive (exit not proven).
    stop_keeps_alive: bool,
    /// `confirm(b)` kills this slot.
    kill_on_confirm: Option<Slot>,
}

struct Fake {
    shared: Arc<Shared>,
    script: Script,
}

fn fixture(script: Script) -> (Fake, Arc<Shared>) {
    let shared = Arc::new(Shared {
        running: Mutex::new(vec![Slot::A]),
        owner: AtomicBool::new(true),
        calls: Mutex::new(Vec::new()),
        entered: Notify::new(),
        release: Notify::new(),
    });
    let fake = Fake {
        shared: shared.clone(),
        script,
    };
    (fake, shared)
}

fn matches(rule: &(Op, Option<Slot>), op: Op, slot: Slot) -> bool {
    rule.0 == op && rule.1.is_none_or(|s| s == slot)
}

impl Fake {
    async fn step(&mut self, op: Op, slot: Slot) -> Result<(), AppError> {
        self.shared
            .calls
            .lock()
            .push(format!("{}:{}", op.name(), name(slot)));
        if self.script.fail.iter().any(|r| matches(r, op, slot)) {
            return Err(AppError::new(ErrorKind::Network));
        }
        let hold = self.script.hold.is_some_and(|r| matches(&r, op, slot));
        if hold {
            self.script.hold = None;
        }
        if hold && op == Op::Stop {
            self.park().await;
        }
        match op {
            Op::Stage => self.shared.running.lock().push(slot),
            Op::Stop if !self.script.stop_keeps_alive => self.shared.kill(slot),
            Op::Confirm if slot == Slot::B => {
                if let Some(victim) = self.script.kill_on_confirm {
                    self.shared.kill(victim);
                }
            }
            _ => {}
        }
        if hold && op != Op::Stop {
            self.park().await;
        }
        Ok(())
    }

    async fn park(&self) {
        self.shared.entered.notify_one();
        self.shared.release.notified().await;
    }
}

impl SwitchOps for Fake {
    async fn stage(&mut self, slot: Slot, _cancel: &CancellationToken) -> Result<(), AppError> {
        self.step(Op::Stage, slot).await
    }
    async fn probe(&mut self, slot: Slot, _cancel: &CancellationToken) -> Result<(), AppError> {
        self.step(Op::Probe, slot).await
    }
    async fn select(&mut self, slot: Slot) -> Result<(), AppError> {
        self.step(Op::Select, slot).await
    }
    async fn confirm(&mut self, slot: Slot) -> Result<(), AppError> {
        self.step(Op::Confirm, slot).await
    }
    fn alive(&self, slot: Slot) -> bool {
        self.shared.running.lock().contains(&slot)
    }
    async fn stop(&mut self, slot: Slot) -> Result<(), AppError> {
        self.step(Op::Stop, slot).await
    }
    fn commit(&mut self, slot: Slot) -> Result<(), AppError> {
        self.shared
            .calls
            .lock()
            .push(format!("commit:{}", name(slot)));
        Ok(())
    }
    fn is_owner(&self) -> bool {
        self.shared.owner.load(Ordering::SeqCst)
    }
}

/// Runs A -> B with no outside interference.
async fn run(script: Script) -> (SwitchReceipt, Arc<Shared>) {
    let (mut fake, shared) = fixture(script);
    let receipt =
        run_protected_switch(Slot::A, Slot::B, &mut fake, &CancellationToken::new()).await;
    (receipt, shared)
}

/// Runs A -> B; once the held call is parked, `meddle` runs, then the call is released.
async fn run_held(
    script: Script,
    cancel: CancellationToken,
    meddle: impl FnOnce(&Shared, &CancellationToken),
) -> (SwitchReceipt, Arc<Shared>) {
    let (mut fake, shared) = fixture(script);
    let driver = async {
        shared.entered.notified().await;
        meddle(&shared, &cancel);
        shared.release.notify_one();
    };
    let (receipt, ()) = tokio::join!(
        run_protected_switch(Slot::A, Slot::B, &mut fake, &cancel),
        driver
    );
    (receipt, shared)
}

fn stops(shared: &Shared) -> Vec<String> {
    shared
        .calls()
        .into_iter()
        .filter(|c| c.starts_with("stop:"))
        .collect()
}

/// AT-00-003 / AT-02-002: the old upstream stays alive through the candidate's health and
/// fresh tunnel proof; it is stopped only after the commit.
#[tokio::test]
async fn success_keeps_the_previous_upstream_until_the_commit() {
    let script = Script {
        hold: Some((Op::Confirm, Some(Slot::B))),
        ..Script::default()
    };
    let (receipt, shared) = run_held(script, CancellationToken::new(), |s, _| {
        assert_eq!(s.running(), [Slot::A, Slot::B]);
        assert!(!s.calls().iter().any(|c| c.starts_with("commit")));
        assert_eq!(s.count(Op::Stop), 0);
    })
    .await;
    assert_eq!(receipt.outcome, SwitchOutcome::Success);
    assert!(receipt.committed && receipt.previous_stopped);
    assert_eq!(receipt.active_slot, Some(Slot::B));
    assert!(receipt.failures.is_empty() && receipt.verified());
    assert_eq!(
        shared.calls(),
        [
            "stage:b",
            "probe:b",
            "select:b",
            "confirm:b",
            "commit:b",
            "stop:a"
        ]
    );
}

/// AT-02-011: a cancel at any boundary drains only the candidate and freshly proves the
/// retained upstream.
#[tokio::test]
async fn cancel_at_each_boundary_preserves_the_previous_upstream() {
    for boundary in Op::BOUNDARIES {
        let script = Script {
            hold: Some((boundary, Some(Slot::B))),
            ..Script::default()
        };
        let (receipt, shared) = run_held(script, CancellationToken::new(), |_, cancel| {
            cancel.cancel();
        })
        .await;
        assert_eq!(receipt.outcome, SwitchOutcome::Cancelled, "{boundary:?}");
        assert!(!receipt.committed, "{boundary:?}");
        assert_eq!(receipt.active_slot, Some(Slot::A), "{boundary:?}");
        assert!(
            receipt.previous_preserved && receipt.candidate_stopped,
            "{boundary:?}"
        );
        assert_eq!(stops(&shared), ["stop:b"], "{boundary:?}");
        assert_eq!(shared.calls().last().map(String::as_str), Some("confirm:a"));
        let restored = shared.calls().contains(&"select:a".to_owned());
        assert_eq!(
            restored,
            matches!(boundary, Op::Select | Op::Confirm),
            "{boundary:?}"
        );
        assert!(!shared.calls().contains(&"commit:b".to_owned()));
        assert!(shared.running().contains(&Slot::A));
    }
}

/// AT-02-011: supersession at any boundary prevents further selector writes or publication.
#[tokio::test]
async fn supersession_at_each_boundary_stops_writing() {
    for boundary in Op::BOUNDARIES {
        let script = Script {
            hold: Some((boundary, None)),
            ..Script::default()
        };
        let writes = Arc::new(Mutex::new(0));
        let seen = writes.clone();
        let (receipt, shared) = run_held(script, CancellationToken::new(), move |s, _| {
            *seen.lock() = s.count(Op::Select);
            s.supersede();
        })
        .await;
        assert_eq!(receipt.outcome, SwitchOutcome::Cancelled, "{boundary:?}");
        assert!(
            !receipt.committed && !receipt.previous_preserved,
            "{boundary:?}"
        );
        assert_eq!(receipt.active_slot, None, "{boundary:?}");
        assert!(receipt.candidate_stopped, "{boundary:?}");
        assert_eq!(shared.count(Op::Select), *writes.lock(), "{boundary:?}");
        assert!(!shared.calls().contains(&"commit:b".to_owned()));
        assert_eq!(stops(&shared), ["stop:b"], "{boundary:?}");
        assert!(!receipt.verified());
    }
}

/// A candidate failure at any boundary never stops the original upstream.
#[tokio::test]
async fn candidate_failure_never_stops_the_previous_upstream() {
    for boundary in Op::BOUNDARIES {
        let script = Script {
            fail: vec![(boundary, Some(Slot::B))],
            ..Script::default()
        };
        let (receipt, shared) = run(script).await;
        assert_eq!(receipt.outcome, SwitchOutcome::Failed, "{boundary:?}");
        assert!(!receipt.committed, "{boundary:?}");
        assert!(
            receipt.previous_preserved && receipt.candidate_stopped,
            "{boundary:?}"
        );
        assert_eq!(stops(&shared), ["stop:b"], "{boundary:?}");
        assert!(shared.running().contains(&Slot::A));
        assert!(!shared.calls().contains(&"commit:b".to_owned()));
        assert_eq!(receipt.failures[0].phase, phase_of(boundary));
        assert!(receipt.verified(), "previous preserved = verified");
    }
}

fn phase_of(op: Op) -> SwitchPhase {
    match op {
        Op::Stage => SwitchPhase::Stage,
        Op::Probe => SwitchPhase::Probe,
        Op::Select => SwitchPhase::Select,
        Op::Confirm => SwitchPhase::Confirm,
        Op::Stop => SwitchPhase::StopCandidate,
    }
}

/// A failed selector restoration never claims preservation.
#[tokio::test]
async fn failed_restoration_is_not_preservation() {
    let script = Script {
        fail: vec![(Op::Confirm, Some(Slot::B)), (Op::Select, Some(Slot::A))],
        ..Script::default()
    };
    let (receipt, shared) = run(script).await;
    assert_eq!(receipt.outcome, SwitchOutcome::Failed);
    assert!(!receipt.previous_preserved && receipt.candidate_stopped);
    assert_eq!(receipt.active_slot, None);
    assert_eq!(shared.count(Op::Confirm), 1);
    let phases: Vec<_> = receipt.failures.iter().map(|f| f.phase).collect();
    assert_eq!(phases, [SwitchPhase::Confirm, SwitchPhase::Restore]);
}

/// An unconfirmed candidate exit (still alive, or the stop errs) never claims preservation.
#[tokio::test]
async fn unconfirmed_candidate_exit_is_not_preservation() {
    for throws in [false, true] {
        let mut script = Script {
            fail: vec![(Op::Probe, None)],
            stop_keeps_alive: !throws,
            ..Script::default()
        };
        if throws {
            script.fail.push((Op::Stop, None));
        }
        let (receipt, shared) = run(script).await;
        assert_eq!(receipt.outcome, SwitchOutcome::Failed, "throws={throws}");
        assert!(!receipt.candidate_stopped && !receipt.previous_preserved);
        assert_eq!(receipt.active_slot, None);
        assert_eq!(shared.count(Op::Confirm), 0);
        assert_eq!(receipt.failures[1].phase, SwitchPhase::StopCandidate);
    }
}

/// A failed old exit after the commit keeps the published selection and the old slot owned.
#[tokio::test]
async fn failed_previous_exit_keeps_the_commit() {
    let script = Script {
        fail: vec![(Op::Stop, None)],
        ..Script::default()
    };
    let (receipt, shared) = run(script).await;
    assert_eq!(receipt.outcome, SwitchOutcome::Failed);
    assert!(receipt.committed && !receipt.previous_stopped);
    assert_eq!(receipt.active_slot, Some(Slot::B));
    let phases: Vec<_> = receipt.failures.iter().map(|f| f.phase).collect();
    assert_eq!(phases, [SwitchPhase::StopPrevious]);
    assert_eq!(shared.count(Op::Select), 1);
    assert_eq!(
        shared.calls().iter().filter(|c| *c == "commit:b").count(),
        1
    );
    assert_eq!(shared.running(), [Slot::A, Slot::B]);
}

/// The previous slot dying during the candidate's proof loses preservation; the candidate
/// dying keeps it.
#[tokio::test]
async fn death_during_the_proof() {
    for (victim, preserved) in [(Slot::A, false), (Slot::B, true)] {
        let script = Script {
            kill_on_confirm: Some(victim),
            ..Script::default()
        };
        let (receipt, shared) = run(script).await;
        assert_eq!(receipt.outcome, SwitchOutcome::Failed, "{victim:?}");
        assert!(!receipt.committed);
        assert_eq!(receipt.previous_preserved, preserved, "{victim:?}");
        assert!(!shared.calls().contains(&"commit:b".to_owned()));
    }
}

/// An occupied candidate is never touched; identical slots never reach the selector.
#[tokio::test]
async fn occupied_candidate_and_identical_slots() {
    let (mut fake, shared) = fixture(Script::default());
    shared.running.lock().push(Slot::B);
    let cancel = CancellationToken::new();
    let receipt = run_protected_switch(Slot::A, Slot::B, &mut fake, &cancel).await;
    assert_eq!(receipt.outcome, SwitchOutcome::Failed);
    assert!(!receipt.committed && !receipt.candidate_stopped);
    assert_eq!(shared.count(Op::Stage) + shared.count(Op::Stop), 0);

    let (mut fake, shared) = fixture(Script::default());
    let receipt = run_protected_switch(Slot::A, Slot::A, &mut fake, &cancel).await;
    assert_eq!(receipt.outcome, SwitchOutcome::Failed);
    assert!(!receipt.previous_preserved);
    assert_eq!(shared.count(Op::Select), 0);
}

/// A disconnect that takes ownership during the late re-proof of the previous slot fences it.
#[tokio::test]
async fn late_restoration_proof_is_fenced_by_a_disconnect() {
    let script = Script {
        fail: vec![(Op::Probe, None)],
        hold: Some((Op::Confirm, Some(Slot::A))),
        ..Script::default()
    };
    let (receipt, shared) = run_held(script, CancellationToken::new(), |s, _| s.supersede()).await;
    assert_eq!(receipt.outcome, SwitchOutcome::Cancelled);
    assert!(!receipt.previous_preserved);
    assert_eq!(receipt.active_slot, None);
    assert!(!shared.calls().contains(&"commit:b".to_owned()));
}

/// The committed candidate dying while the old slot is stopped is no success.
#[tokio::test]
async fn committed_candidate_dying_during_cleanup_is_no_success() {
    let script = Script {
        hold: Some((Op::Stop, Some(Slot::A))),
        ..Script::default()
    };
    let (receipt, shared) =
        run_held(script, CancellationToken::new(), |s, _| s.kill(Slot::B)).await;
    assert_eq!(receipt.outcome, SwitchOutcome::Failed);
    assert!(receipt.committed && receipt.previous_stopped);
    assert_eq!(receipt.active_slot, None);
    assert_eq!(receipt.failures[0].phase, SwitchPhase::Ownership);
    assert_eq!(shared.count(Op::Select), 1);
}

/// A disconnect during the old slot's cleanup keeps the commit in the receipt.
#[tokio::test]
async fn disconnect_during_cleanup_keeps_the_commit_receipt() {
    let script = Script {
        hold: Some((Op::Stop, Some(Slot::A))),
        ..Script::default()
    };
    let (receipt, shared) = run_held(script, CancellationToken::new(), |s, _| s.supersede()).await;
    assert_eq!(receipt.outcome, SwitchOutcome::Cancelled);
    assert!(receipt.committed && receipt.previous_stopped);
    assert!(!receipt.previous_preserved);
    assert_eq!(receipt.active_slot, None);
    assert_eq!(shared.count(Op::Select), 1);
    assert_eq!(stops(&shared), ["stop:a"]);
}

/// No work and no selector write once ownership is already lost (or the caller cancelled).
#[tokio::test]
async fn nothing_happens_without_ownership() {
    let (mut fake, shared) = fixture(Script::default());
    shared.supersede();
    let receipt =
        run_protected_switch(Slot::A, Slot::B, &mut fake, &CancellationToken::new()).await;
    assert_eq!(receipt.outcome, SwitchOutcome::Cancelled);
    assert!(!receipt.committed && !receipt.previous_preserved);
    assert!(shared.calls().is_empty());

    let (mut fake, shared) = fixture(Script::default());
    let cancel = CancellationToken::new();
    cancel.cancel();
    let receipt = run_protected_switch(Slot::A, Slot::B, &mut fake, &cancel).await;
    assert_eq!(receipt.outcome, SwitchOutcome::Cancelled);
    assert_eq!(shared.count(Op::Stage) + shared.count(Op::Select), 0);
}
