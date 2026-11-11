//! The Speed test page's run and progress, separate from its markup so the lifecycle rules
//! (ui-pages §7.7) are tested on the code the page runs.
use std::pin::pin;
use std::rc::Rc;

use dioxus::prelude::*;
use futures_util::future::{Either, select};
use tokio::sync::watch;
use vpnte_base::Msg;

use super::SpeedTestApi;
use super::model::{SpeedProgress, SpeedResult, SpeedTestState};
use crate::widgets::JobSlot;

/// The run slot and its live progress (Copy handles owned by the page root).
#[derive(Clone, Copy, PartialEq)]
pub(crate) struct Controller {
    api: CopyValue<Rc<dyn SpeedTestApi>>,
    pub job: JobSlot<SpeedResult>,
    /// Progress of the run in flight (`None` while idle).
    pub progress: Signal<Option<SpeedProgress>>,
}

/// The controller of the calling component (its run dies with it).
pub(crate) fn use_controller(api: Rc<dyn SpeedTestApi>) -> Controller {
    use_hook(move || Controller {
        api: CopyValue::new(api),
        job: JobSlot::new(),
        progress: Signal::new(None),
    })
}

impl Controller {
    /// Starts a test unless one runs. Progress comes through a channel of this run only, so an
    /// event of an older run can never move the bar.
    pub fn start(self) {
        let mut progress = self.progress;
        if self.job.running() {
            return;
        }
        self.job.clear();
        progress.set(Some(SpeedProgress::default()));
        let api = self.api.read().clone();
        self.job.start(move |token| async move {
            let (tx, mut rx) = watch::channel(SpeedProgress::default());
            let pump = async move {
                while rx.changed().await.is_ok() {
                    let next = *rx.borrow_and_update();
                    progress.set(Some(next));
                }
            };
            let run = pin!(api.run(tx, token));
            let result = match select(run, pin!(pump)).await {
                Either::Left((result, _)) => result,
                Either::Right(((), run)) => run.await,
            };
            progress.set(None);
            if let Ok(done) = &result {
                tracing::info!(
                    target: "ui",
                    download = done.download_mbps,
                    upload = ?done.upload_mbps,
                    latency = done.latency_ms,
                    "speed test finished"
                );
            }
            result
        });
    }

    /// Cancels the run in flight: its streams stop, nothing of it reaches the page any more.
    pub fn cancel(self) {
        let mut progress = self.progress;
        self.job.cancel();
        progress.set(None);
    }

    /// The error of the last run (a cancelled run leaves none).
    pub fn error(self) -> Option<Msg> {
        match self.job.last() {
            Some(Err(err)) => Some(err.msg),
            _ => None,
        }
    }

    /// The result in the readouts: this session's last one, else the newest saved one.
    pub fn shown(self, history: &[SpeedResult]) -> Option<SpeedResult> {
        match self.job.last() {
            Some(Ok(result)) => Some(result),
            _ => history.first().cloned(),
        }
    }
}

/// Mirrors the pushed state into a signal (one pump task owned by the page).
pub(crate) fn use_state_pump(api: Rc<dyn SpeedTestApi>) -> Signal<SpeedTestState> {
    let mut state = use_signal(|| api.state().borrow().clone());
    use_future(move || {
        let mut rx = api.state();
        async move {
            loop {
                let next = rx.borrow_and_update().clone();
                if *state.peek() != next {
                    state.set(next);
                }
                if rx.changed().await.is_err() {
                    break;
                }
            }
        }
    });
    state
}

#[cfg(test)]
mod tests {
    //! Port of `SpeedTest.lifecycle.test.tsx` (ui-pages §7.7, AT-00-003 / AT-00-008). Request ids
    //! are gone: each run has its own progress channel and token, so "another request's event"
    //! is an event on a previous run's channel.
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    use dioxus::core::{NoOpMutations, ScopeId};
    use tokio::sync::oneshot;
    use tokio_util::sync::CancellationToken;
    use vpnte_base::{AppError, AppResult, ErrorKind};

    use super::*;
    use crate::speedtest::model::{Egress, SpeedPhase};

    /// The Russian catalog text of `key`.
    fn ru_text(key: &str) -> String {
        crate::test_locales::init_locales();
        vpnte_base::i18n::lookup(vpnte_base::i18n::Lang::Ru, key, &[], None)
    }

    type Run = (watch::Sender<SpeedProgress>, CancellationToken);

    struct Script {
        state: watch::Sender<SpeedTestState>,
        replies: RefCell<VecDeque<oneshot::Receiver<AppResult<SpeedResult>>>>,
        runs: RefCell<Vec<Run>>,
    }

    #[async_trait::async_trait(?Send)]
    impl SpeedTestApi for Script {
        fn state(&self) -> watch::Receiver<SpeedTestState> {
            self.state.subscribe()
        }
        async fn run(
            &self,
            progress: watch::Sender<SpeedProgress>,
            cancel: CancellationToken,
        ) -> AppResult<SpeedResult> {
            self.runs.borrow_mut().push((progress, cancel));
            let rx = self.replies.borrow_mut().pop_front();
            match rx {
                Some(rx) => rx.await.unwrap_or_else(|_| Err(AppError::cancelled())),
                None => Err(AppError::new(ErrorKind::Internal)),
            }
        }
    }

    impl Script {
        fn reply(&self) -> oneshot::Sender<AppResult<SpeedResult>> {
            let (tx, rx) = oneshot::channel();
            self.replies.borrow_mut().push_back(rx);
            tx
        }
        fn run(&self, i: usize) -> Run {
            self.runs.borrow()[i].clone()
        }
    }

    #[derive(Clone)]
    struct Probe {
        api: Rc<Script>,
        show: Rc<Cell<bool>>,
        ctl: Rc<Cell<Option<Controller>>>,
    }

    fn root() -> Element {
        let show = use_context::<Probe>().show.get();
        rsx! {
            if show {
                PageStandIn {}
            }
        }
    }

    /// The page's hooks without its markup.
    #[component]
    fn PageStandIn() -> Element {
        let probe = use_context::<Probe>();
        let ctl = use_controller(probe.api.clone());
        probe.ctl.set(Some(ctl));
        rsx! {}
    }

    fn mount() -> (VirtualDom, Probe) {
        let api = Rc::new(Script {
            state: watch::Sender::new(SpeedTestState {
                tunnel_running: true,
                ..Default::default()
            }),
            replies: RefCell::default(),
            runs: RefCell::default(),
        });
        let probe = Probe {
            api,
            show: Rc::new(Cell::new(true)),
            ctl: Rc::default(),
        };
        let mut dom = VirtualDom::new(root).with_root_context(probe.clone());
        dom.rebuild_in_place();
        (dom, probe)
    }

    use crate::test_support::settle;

    fn ctl(probe: &Probe) -> Controller {
        probe.ctl.get().expect("page mounted")
    }

    fn progress(dom: &VirtualDom, ctl: Controller) -> Option<SpeedProgress> {
        dom.in_runtime(|| *ctl.progress.peek())
    }

    fn result(download: f64) -> SpeedResult {
        SpeedResult {
            id: "r".into(),
            timestamp: 1,
            download_mbps: download,
            upload_mbps: Some(10.0),
            latency_ms: 40,
            server_name: "Cloudflare".into(),
            profile_used: "Test".into(),
            egress: Egress::Match,
            plain_http: false,
        }
    }

    /// §7.7 "owns a request before progress": the previous run's late event is ignored, the own
    /// event moves the bar; Cancel cancels; a cancelled run shows no text and frees the button.
    #[tokio::test]
    async fn only_the_own_run_moves_the_bar_and_cancel_is_silent() {
        let (mut dom, probe) = mount();
        let ctl = ctl(&probe);
        let _first = probe.api.reply();
        dom.in_runtime(|| ctl.start());
        settle(&mut dom, 4, 30).await;
        assert_eq!(progress(&dom, ctl), Some(SpeedProgress::default()));
        dom.in_runtime(|| ctl.cancel());
        let (old_tx, old_token) = probe.api.run(0);
        assert!(old_token.is_cancelled());
        let _second = probe.api.reply();
        dom.in_runtime(|| ctl.start());
        settle(&mut dom, 4, 30).await;
        let late = SpeedProgress {
            percent: 77,
            phase: SpeedPhase::Upload,
        };
        assert!(
            old_tx.send(late).is_err(),
            "the cancelled run's channel is closed"
        );
        let (tx, token) = probe.api.run(1);
        let own = SpeedProgress {
            percent: 45,
            phase: SpeedPhase::Download,
        };
        tx.send(own).expect("own run alive");
        settle(&mut dom, 4, 30).await;
        assert_eq!(progress(&dom, ctl), Some(own));
        dom.in_runtime(|| ctl.cancel());
        settle(&mut dom, 4, 30).await;
        assert!(token.is_cancelled());
        dom.in_runtime(|| {
            assert!(!ctl.job.running());
            assert_eq!(ctl.error(), None);
            assert_eq!(*ctl.progress.peek(), None);
        });
    }

    /// §7.7 "cancels on unmount before first progress"; the late result goes nowhere.
    #[tokio::test]
    async fn unmount_cancels_the_run_before_any_progress() {
        let (mut dom, probe) = mount();
        let reply = probe.api.reply();
        let ctl = ctl(&probe);
        dom.in_runtime(|| ctl.start());
        settle(&mut dom, 4, 30).await;
        let (_, token) = probe.api.run(0);
        probe.show.set(false);
        dom.mark_dirty(ScopeId::APP);
        dom.render_immediate(&mut NoOpMutations);
        assert!(token.is_cancelled());
        assert!(
            reply.send(Ok(result(99.0))).is_err(),
            "the run's future was dropped"
        );
    }

    /// §7.7 "finishes the run without waiting for the history refresh" and a failed run shows
    /// its text, after which a new run starts with a new token.
    #[tokio::test]
    async fn results_and_failures_are_shown_and_a_retry_is_possible() {
        let (mut dom, probe) = mount();
        let ctl = ctl(&probe);
        let no_tunnel = AppError::conflict(Msg::new("speedTest.vpnNotConnected"));
        probe.api.reply().send(Err(no_tunnel)).expect("queued");
        dom.in_runtime(|| ctl.start());
        settle(&mut dom, 4, 30).await;
        let text = "VPN не подключён. Подключите VPN перед запуском теста скорости.";
        dom.in_runtime(|| {
            let msg = ctl.error().expect("an error");
            assert_eq!(ru_text(&msg.key), text);
            assert_eq!(*ctl.progress.peek(), None);
        });
        probe.api.reply().send(Ok(result(87.4))).expect("queued");
        dom.in_runtime(|| ctl.start());
        settle(&mut dom, 4, 30).await;
        assert_ne!(probe.api.run(0).1, probe.api.run(1).1);
        dom.in_runtime(|| {
            assert_eq!(ctl.error(), None);
            let shown = ctl.shown(&[result(1.0)]).map(|r| r.download_mbps);
            assert_eq!(shown, Some(87.4));
        });
    }

    /// The readouts fall back to the newest saved result before any run of this session.
    #[tokio::test]
    async fn readouts_fall_back_to_the_newest_saved_result() {
        let (dom, probe) = mount();
        let ctl = ctl(&probe);
        dom.in_runtime(|| {
            assert_eq!(ctl.shown(&[]), None);
            let shown = ctl
                .shown(&[result(12.5), result(3.0)])
                .map(|r| r.download_mbps);
            assert_eq!(shown, Some(12.5));
        });
    }
}
