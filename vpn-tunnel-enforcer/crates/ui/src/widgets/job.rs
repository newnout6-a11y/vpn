//! [`JobSlot`]: one operation per button group, single flight, cancelled with the component that
//! owns the slot, silent on cancellation (ui-pages §6.2; replaces every request-id fence of the
//! old pages).
use std::future::Future;

use dioxus::core::{Runtime, ScopeId, Task, current_scope_id};
use dioxus::prelude::*;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

/// An error ready for display: the category to branch on and the message to render with
/// [`crate::lang::tr`] (kept as a [`Msg`], so a language switch re-renders it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiError {
    pub kind: ErrorKind,
    pub msg: Msg,
}

impl From<&AppError> for UiError {
    fn from(err: &AppError) -> Self {
        Self {
            kind: err.kind,
            msg: err.user_msg(),
        }
    }
}

impl From<AppError> for UiError {
    fn from(err: AppError) -> Self {
        Self::from(&err)
    }
}

/// The run that currently owns the slot.
struct Run {
    id: u64,
    token: CancellationToken,
    task: Task,
}

/// One operation slot: `start` is a no-op while a run is in flight; `cancel` or dropping the
/// owning component cancels the run's token and drops its future, so a late result is never
/// applied; `Err(Cancelled)` changes nothing visible.
///
/// Where a slot lives decides its lifetime: [`use_job`] in a page dies with the page; a slot
/// created in the root component (an `AppJobs` struct in context) survives navigation.
pub struct JobSlot<T: 'static> {
    running: Signal<bool>,
    last: Signal<Option<Result<T, UiError>>>,
    run: Signal<Option<Run>>,
    next_id: Signal<u64>,
    owner: ScopeId,
}

impl<T> Clone for JobSlot<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for JobSlot<T> {}

impl<T> PartialEq for JobSlot<T> {
    fn eq(&self, other: &Self) -> bool {
        self.run == other.run
    }
}

/// A [`JobSlot`] owned by the calling component.
pub fn use_job<T: 'static>() -> JobSlot<T> {
    use_hook(JobSlot::new)
}

impl<T: 'static> JobSlot<T> {
    /// A slot owned by the current component (call inside `use_hook`, or use [`use_job`]).
    #[expect(
        clippy::new_without_default,
        reason = "only valid inside a component: it records the owning scope"
    )]
    pub fn new() -> Self {
        Self {
            running: Signal::new(false),
            last: Signal::new(None),
            run: Signal::new(None),
            next_id: Signal::new(0),
            owner: current_scope_id(),
        }
    }

    /// Starts `f(token)` unless a run is in flight. The future runs in the owner's scope, so it
    /// outlives the clicked component when the slot belongs to an ancestor.
    pub fn start<F>(&self, f: impl FnOnce(CancellationToken) -> F)
    where
        F: Future<Output = AppResult<T>> + 'static,
    {
        if *self.running.peek() {
            return;
        }
        let mut next_id = self.next_id;
        let id = *next_id.peek() + 1;
        next_id.set(id);
        let token = CancellationToken::new();
        let call = f(token.clone());
        let guard = token.clone().drop_guard();
        let slot = *self;
        let run_future = async move {
            // Dropping this future (unmount of the owner, `cancel`) drops the guard, which
            // cancels the backend call; a normal finish disarms it.
            let guard = guard;
            let result = call.await;
            guard.disarm();
            slot.finish(id, result);
        };
        // `spawn` inside the owner's scope registers the task with that scope, so the task dies
        // with it (`Runtime::spawn(scope, …)` alone does not register it and would outlive it).
        let task = Runtime::current().in_scope(self.owner, || spawn(run_future));
        let (mut running, mut run) = (self.running, self.run);
        run.set(Some(Run { id, token, task }));
        running.set(true);
    }

    fn finish(self, id: u64, result: AppResult<T>) {
        let (mut running, mut run, mut last) = (self.running, self.run, self.last);
        if run.peek().as_ref().map(|r| r.id) != Some(id) {
            return;
        }
        run.set(None);
        running.set(false);
        match result {
            Ok(value) => last.set(Some(Ok(value))),
            Err(err) if err.kind == ErrorKind::Cancelled => {}
            Err(err) => {
                tracing::debug!(error = %err, "ui job failed");
                last.set(Some(Err(UiError::from(&err))));
            }
        }
    }

    /// Cancels the run in flight (its token and its future); `last` stays as it was.
    pub fn cancel(&self) {
        let (mut running, mut run) = (self.running, self.run);
        if let Some(current) = run.write().take() {
            current.token.cancel();
            current.task.cancel();
        }
        if *running.peek() {
            running.set(false);
        }
    }

    /// Whether a run is in flight (subscribes the caller).
    pub fn running(&self) -> bool {
        *self.running.read()
    }

    /// The outcome of the last finished run that was not cancelled (subscribes the caller).
    pub fn last(&self) -> Option<Result<T, UiError>>
    where
        T: Clone,
    {
        self.last.read().clone()
    }

    /// Forgets the last outcome (for example when the form it described was edited).
    pub fn clear(&self) {
        let mut last = self.last;
        if last.peek().is_some() {
            last.set(None);
        }
    }
}

#[cfg(test)]
mod tests {
    //! Port of the request-lifetime vectors (ui-pages §7.5 / §7.6 / §7.10, AT-00-003 / AT-00-008):
    //! "token" = the run's `CancellationToken`; "no UI change" = `running` / `last` untouched.
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use dioxus::core::NoOpMutations;
    use tokio::sync::oneshot;

    use super::*;

    type Reply = AppResult<u32>;

    /// Drives and observes the slot from outside the VirtualDom.
    #[derive(Clone, Default)]
    struct Probe {
        root_owns: bool,
        show_child: Rc<Cell<bool>>,
        slot: Rc<RefCell<Option<JobSlot<u32>>>>,
        /// A run the child starts when it mounts.
        child_run: Rc<RefCell<Option<oneshot::Receiver<Reply>>>>,
        token: Rc<RefCell<Option<CancellationToken>>>,
    }

    fn root() -> Element {
        let probe = use_context::<Probe>();
        let own = use_hook(|| probe.root_owns.then(JobSlot::<u32>::new));
        if let Some(slot) = own {
            probe.slot.replace(Some(slot));
        }
        let show = probe.show_child.get();
        rsx! {
            if show {
                Child {}
            }
        }
    }

    #[component]
    fn Child() -> Element {
        let probe = use_context::<Probe>();
        let own = use_hook(|| (!probe.root_owns).then(JobSlot::<u32>::new));
        if let Some(slot) = own {
            probe.slot.replace(Some(slot));
        }
        use_hook(|| {
            let slot = *probe.slot.borrow();
            let run = probe.child_run.borrow_mut().take();
            if let (Some(slot), Some(rx)) = (slot, run) {
                let out = probe.token.clone();
                slot.start(move |token| {
                    out.replace(Some(token));
                    async move { rx.await.unwrap_or_else(|_| Err(AppError::cancelled())) }
                });
            }
        });
        rsx! {}
    }

    fn mount(root_owns: bool, child_run: Option<oneshot::Receiver<Reply>>) -> (VirtualDom, Probe) {
        let probe = Probe {
            root_owns,
            show_child: Rc::new(Cell::new(true)),
            child_run: Rc::new(RefCell::new(child_run)),
            ..Probe::default()
        };
        let mut dom = VirtualDom::new(root).with_root_context(probe.clone());
        dom.rebuild_in_place();
        (dom, probe)
    }

    use crate::test_support::settle;

    fn slot(probe: &Probe) -> JobSlot<u32> {
        probe.slot.borrow().expect("slot mounted")
    }

    /// Starts a run from outside (a click); returns the reply sender. `calls` counts how often
    /// the backend call was actually made.
    fn start(dom: &VirtualDom, probe: &Probe, calls: &Rc<Cell<u32>>) -> oneshot::Sender<Reply> {
        let (tx, rx) = oneshot::channel();
        let (slot, calls, out) = (slot(probe), calls.clone(), probe.token.clone());
        dom.in_runtime(|| {
            slot.start(move |token| {
                calls.set(calls.get() + 1);
                out.replace(Some(token));
                async move { rx.await.unwrap_or_else(|_| Err(AppError::cancelled())) }
            });
        });
        tx
    }

    fn state(dom: &VirtualDom, probe: &Probe) -> (bool, Option<Result<u32, UiError>>) {
        let slot = slot(probe);
        dom.in_runtime(|| (*slot.running.peek(), slot.last.peek().clone()))
    }

    fn token(probe: &Probe) -> CancellationToken {
        probe.token.borrow().clone().expect("a run started")
    }

    /// AT-00-003/008 (§7.10 "Double click → one export"): a second start while running is a no-op.
    #[tokio::test]
    async fn a_second_start_while_running_is_ignored() {
        let (mut dom, probe) = mount(false, None);
        let calls = Rc::new(Cell::new(0));
        let tx = start(&dom, &probe, &calls);
        let _ignored = start(&dom, &probe, &calls);
        assert_eq!(calls.get(), 1);
        assert_eq!(state(&dom, &probe), (true, None));
        tx.send(Ok(7)).expect("run alive");
        settle(&mut dom, 4, 30).await;
        assert_eq!(state(&dom, &probe), (false, Some(Ok(7))));
    }

    /// §7.5 "typed cancellation → no text"; other errors keep the canonical message.
    #[tokio::test]
    async fn cancellation_is_silent_and_errors_are_kept() {
        let (mut dom, probe) = mount(false, None);
        let calls = Rc::new(Cell::new(0));
        start(&dom, &probe, &calls).send(Ok(1)).expect("run alive");
        settle(&mut dom, 4, 30).await;
        start(&dom, &probe, &calls)
            .send(Err(AppError::cancelled()))
            .expect("run alive");
        settle(&mut dom, 4, 30).await;
        assert_eq!(state(&dom, &probe), (false, Some(Ok(1))));
        start(&dom, &probe, &calls)
            .send(Err(AppError::new(ErrorKind::Network)))
            .expect("run alive");
        settle(&mut dom, 4, 30).await;
        let expected = UiError {
            kind: ErrorKind::Network,
            msg: Msg::new("errors.network"),
        };
        assert_eq!(state(&dom, &probe), (false, Some(Err(expected))));
    }

    /// §7.6 "an old reply never clears a newer run": `cancel` cancels the token and drops the
    /// future, so the late reply has nowhere to go; the next run gets a fresh token.
    #[tokio::test]
    async fn cancel_drops_the_run_and_the_next_one_gets_a_new_token() {
        let (mut dom, probe) = mount(false, None);
        let calls = Rc::new(Cell::new(0));
        let late = start(&dom, &probe, &calls);
        settle(&mut dom, 4, 30).await;
        let first = token(&probe);
        let slot = slot(&probe);
        dom.in_runtime(|| slot.cancel());
        assert!(first.is_cancelled());
        assert!(
            late.send(Ok(9)).is_err(),
            "the cancelled run's future is gone"
        );
        settle(&mut dom, 4, 30).await;
        assert_eq!(state(&dom, &probe), (false, None));
        let tx = start(&dom, &probe, &calls);
        let second = token(&probe);
        assert!(!second.is_cancelled());
        tx.send(Ok(5)).expect("run alive");
        settle(&mut dom, 4, 30).await;
        assert_eq!(state(&dom, &probe), (false, Some(Ok(5))));
        assert_eq!(calls.get(), 2);
    }

    /// §7.5 / §7.10 "unmount → cancel with its token; a late result changes nothing".
    #[tokio::test]
    async fn unmounting_the_owner_cancels_the_run() {
        let (tx, rx) = oneshot::channel();
        let (mut dom, probe) = mount(false, Some(rx));
        settle(&mut dom, 4, 30).await;
        let run = token(&probe);
        assert!(!run.is_cancelled());
        probe.show_child.set(false);
        dom.mark_dirty(ScopeId::APP);
        dom.render_immediate(&mut NoOpMutations);
        assert!(run.is_cancelled());
        assert!(
            tx.send(Ok(1)).is_err(),
            "the run's future was dropped with its owner"
        );
    }

    /// ui-pages §6.2: a slot owned by the root keeps running when the page that started it goes.
    #[tokio::test]
    async fn a_root_slot_survives_the_page_that_started_it() {
        let (tx, rx) = oneshot::channel();
        let (mut dom, probe) = mount(true, Some(rx));
        settle(&mut dom, 4, 30).await;
        probe.show_child.set(false);
        dom.mark_dirty(ScopeId::APP);
        dom.render_immediate(&mut NoOpMutations);
        assert!(!token(&probe).is_cancelled());
        tx.send(Ok(3)).expect("run still alive");
        settle(&mut dom, 4, 30).await;
        assert_eq!(state(&dom, &probe), (false, Some(Ok(3))));
    }

    #[test]
    fn ui_errors_carry_the_specific_or_the_canonical_message() {
        let specific = UiError::from(AppError::validation(Msg::new("servers.invalidKey")));
        assert_eq!(specific.msg.key, "servers.invalidKey");
        assert_eq!(UiError::from(AppError::timeout()).msg.key, "errors.timeout");
    }
}
