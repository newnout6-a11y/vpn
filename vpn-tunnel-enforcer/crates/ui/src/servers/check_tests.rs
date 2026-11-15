//! p-check-live on the page: each row tells its key's stage in numbers as it happens, the strip
//! sums the run up with «Отменить», and a stop keeps what landed and marks the rest.
//! p-fix-checklive: one check of the servers at a time, an ended strip keeps its numbers, the
//! countdowns read the clock, a refused start leaves no strip, a stage for a key the row no
//! longer holds is dropped, the request's time stands once it ended, the countdown stays out of
//! the live region, and the wait reads as the app's own pacing.
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;

use dioxus::prelude::*;
use vpnte_base::i18n::Lang;
use vpnte_base::types::{Engine, now_ms};
use vpnte_base::{AppError, Msg};

use super::actions::Actions;
use super::check::{CheckStrip, Totals, stage_text, strip_line, totals};
use super::check_model::{CheckAnswer, CheckKey, CheckStage};
use super::model::{KeyHealth, KeyHealthReason, ServerView, ServersView};
use super::row::ServerRow;
use super::state::{RowCheck, RowRt, RunKey, RunState, Store};
use super::tests::{FakeApi, alive, fake, hold_check_all, hold_check_group};
use crate::lang::{LANG, translate_now};
use crate::test_support::Shown;
use crate::widgets::ToastKind;

const IDS: [&str; 3] = ["s1", "s2", "s3"];

fn server(id: &str) -> ServerView {
    ServerView {
        id: id.into(),
        name: format!("Server {id}"),
        host: format!("{id}.example.net"),
        port: 443,
        protocol: "vless".into(),
        ..ServerView::default()
    }
}

/// Three rows, the list's strip and group g's strip over the page's state and a [`FakeApi`].
fn root() -> Element {
    let api = use_context::<Rc<FakeApi>>();
    let slot = use_context::<Rc<RefCell<Option<Actions>>>>();
    let toasts = crate::widgets::Toasts::use_provider();
    let scope = dioxus::core::current_scope_id();
    let view = ServersView {
        servers: IDS.iter().map(|id| server(id)).collect(),
        ..ServersView::default()
    };
    let store = use_hook(|| Store::new(scope, view, Vec::new()));
    let actions = use_context_provider(|| Actions {
        store,
        api: api.clone(),
        toasts,
    });
    slot.replace(Some(actions));
    rsx! {
        CheckStrip { run: RunKey::List }
        CheckStrip { run: RunKey::Group("g".into()) }
        for id in IDS {
            ServerRow { key: "{id}", server: server(id), group: None }
        }
    }
}

/// The page under test with its actions and what it showed so far.
async fn page(api: &Rc<FakeApi>) -> (VirtualDom, Actions, Shown) {
    crate::lang::init_locales(&[]);
    let slot: Rc<RefCell<Option<Actions>>> = Rc::default();
    let mut dom = VirtualDom::new(root)
        .with_root_context(api.clone())
        .with_root_context(slot.clone());
    let mut seen = Shown::default();
    dom.rebuild(&mut seen);
    let actions = slot.borrow().clone().expect("page actions");
    (dom, actions, seen)
}

/// Lets the tree's tasks run a few rounds, recording what it shows.
async fn rounds(dom: &mut VirtualDom, seen: &mut Shown) {
    for _ in 0..8 {
        tokio::select! {
            () = dom.wait_for_work() => {}
            () = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
        dom.render_immediate(seen);
    }
}

fn dead(at: i64) -> KeyHealth {
    KeyHealth {
        online: false,
        latency_ms: None,
        reason: Some(KeyHealthReason::HandshakeFailed),
        checked_at: at,
    }
}

fn text(key: &str, vars: &[(&str, &str)]) -> String {
    let vars: Vec<(&str, String)> = vars.iter().map(|(k, v)| (*k, (*v).to_owned())).collect();
    translate_now(key, &vars)
}

fn http(ms: u32) -> CheckStage {
    CheckStage::Done(CheckAnswer::Http { status: 200, ms })
}

/// A running list check in numbers: the HTTP answer, the countdown to a key's next connection,
/// a failed handshake, and the strip's totals with «Отменить»; the countdown is a node of its
/// own outside the announced totals (b6); a stop keeps what landed, marks the rest «не
/// проверено», says the check stopped and shows no toast.
#[tokio::test]
async fn rows_tell_their_stage_and_the_strip_sums_up() {
    let api = fake();
    let (mut dom, actions, mut seen) = page(&api).await;
    let stage = |id: &str, stage| (id.to_owned(), stage);
    let failed = CheckAnswer::Failed(KeyHealthReason::HandshakeFailed);
    // Stamped on the wall clock when sent, as the app's feed does.
    let until = now_ms() + 41_000;
    let stages = vec![
        stage("s1", CheckStage::Queued),
        stage("s2", CheckStage::Queued),
        stage("s3", CheckStage::Queued),
        stage("s2", CheckStage::Waiting { until }),
        stage(
            "s1",
            CheckStage::Starting {
                engine: Engine::SingBox,
            },
        ),
        stage("s1", http(312)),
        stage("s3", CheckStage::Done(failed)),
    ];
    let results = vec![("s1".to_owned(), alive(1)), ("s3".to_owned(), dead(1))];
    let _held = hold_check_all(&api, stages, results);
    dom.in_runtime(|| actions.check_all());
    rounds(&mut dom, &mut seen).await;
    let (expect, live) = dom.in_runtime(|| {
        let totals = text("ui.servers.check.totals", &[("done", "2"), ("total", "3")]);
        let waiting = text("ui.servers.check.waitingTotal", &[("count", "1")]);
        let live = format!("{totals} · {waiting}");
        let expect = [
            text("ui.servers.check.http", &[("status", "200"), ("ms", "312")]),
            text("ui.servers.check.waiting", &[("seconds", "41")]),
            text("ui.servers.check.failed.handshake", &[]),
            live.clone(),
            text("ui.servers.check.waitLeft", &[("seconds", "41")]),
            format!(
                " · {}",
                text("ui.servers.check.failedTotal", &[("count", "1")])
            ),
            text("ui.servers.check.stop", &[]),
        ];
        (expect, live)
    });
    for line in &expect {
        assert!(seen.shows(line), "{line:?} in {:?}", seen.texts);
    }
    let left = &expect[4];
    assert!(
        !seen
            .texts
            .iter()
            .any(|t| t.contains(&live) && t.contains(left.as_str())),
        "the countdown is not in the announced totals: {:?}",
        seen.texts
    );
    assert!(seen.has("data-stage", "waiting") && seen.has("data-stage", "done"));

    dom.in_runtime(|| actions.check_all());
    rounds(&mut dom, &mut seen).await;
    let (stopped, failed_total, not_checked) = dom.in_runtime(|| {
        (
            text("ui.servers.check.stopped", &[("done", "2"), ("total", "3")]),
            format!(
                " · {}",
                text("ui.servers.check.failedTotal", &[("count", "1")])
            ),
            text("ui.servers.check.notChecked", &[]),
        )
    });
    assert!(seen.shows(&stopped), "{stopped:?} in {:?}", seen.texts);
    assert!(seen.shows(&failed_total), "{:?}", seen.texts);
    assert!(seen.shows(&not_checked), "{:?}", seen.texts);
    let (s1, s2, state) = dom.in_runtime(|| {
        let rows = actions.store.rows.peek();
        let s1 = rows.get("s1").and_then(|r| r.health.clone());
        let s2 = rows
            .get("s2")
            .and_then(|r| r.check.clone())
            .map(|c| c.stage);
        let checks = actions.store.checks.peek();
        (s1, s2, checks.get(&RunKey::List).map(|c| c.state))
    });
    assert_eq!(s1, Some(alive(1)), "the landed result stays");
    assert_eq!(s2, Some(CheckStage::NotChecked));
    assert_eq!(state, Some(RunState::Ended { stopped: true }));
    assert!(dom.in_runtime(|| actions.toasts.list()).is_empty());
}

/// The owner's example, in Russian (b7: the wait is the app's own pacing of new connections to
/// one server): the strip while a long list runs and after «Отменить», and the rows' lines in
/// plain words; only rows of the run that hold the key it was about count (b2).
#[test]
fn the_strip_reads_like_the_owners_example() {
    crate::lang::init_locales(&[]);
    let dom = VirtualDom::new(|| rsx! {});
    dom.in_runtime(|| {
        *LANG.write() = Lang::Ru;
        let running = Totals {
            total: 23,
            done: 21,
            waiting: 2,
            wait_secs: 41,
            failed: 2,
            not_checked: 0,
        };
        let line = strip_line(&running, RunState::Running);
        assert_eq!(
            line.text(),
            "Проверено 21 из 23 · 2 ждут очереди к серверу, ещё 41 с · 2 сбоя"
        );
        assert_eq!(
            line.left.as_deref(),
            Some(", ещё 41 с"),
            "the countdown apart"
        );
        assert!(!line.totals.contains("41") && !line.rest.contains("41"));
        let stopped = Totals {
            waiting: 0,
            failed: 0,
            ..running
        };
        let ended = RunState::Ended { stopped: true };
        assert_eq!(
            strip_line(&stopped, ended).text(),
            "Проверка остановлена: 21 из 23"
        );
        let line = |stage| stage_text(&stage, 1_000).0;
        let requesting = CheckStage::Requesting {
            engine: Engine::Xray,
            engine_ms: 840,
            since: 0,
        };
        assert_eq!(
            line(CheckStage::Waiting { until: 42_000 }),
            "следующее соединение с сервером через 41 с"
        );
        assert_eq!(
            line(requesting),
            "Xray за 840 мс · рукопожатие и тестовый запрос, 1 с"
        );
        assert_eq!(
            line(CheckStage::Done(CheckAnswer::Silent { ms: 10_000 })),
            "нет ответа за 10 с"
        );
        let refused = KeyHealthReason::from_code("connection-refused");
        assert_eq!(
            line(CheckStage::Done(CheckAnswer::Failed(refused))),
            "соединение отклонено"
        );
        assert!(!stage_text(&http(5), 0).1);

        *LANG.write() = Lang::En;
        assert_eq!(
            strip_line(&running, RunState::Running).text(),
            "Checked 21 of 23 · 2 waiting for the server queue, 41 s left · 2 failed"
        );
        assert_eq!(
            line(CheckStage::Waiting { until: 42_000 }),
            "next connection to this server in 41 s"
        );
    });
    let row = |run: RunKey, tag: u64, stage| RowRt {
        check: Some(RowCheck { run, tag, stage }),
        ..RowRt::default()
    };
    let stalled = CheckStage::Done(CheckAnswer::Stalled { bytes: 16_384 });
    let rows = HashMap::from([
        (
            "a".to_owned(),
            row(RunKey::List, 1, CheckStage::Waiting { until: 5_500 }),
        ),
        ("b".to_owned(), row(RunKey::List, 2, stalled)),
        (
            "c".to_owned(),
            row(RunKey::Group("g".into()), 3, CheckStage::Queued),
        ),
        // Re-keyed by a refresh while the check ran, and a row deleted meanwhile.
        ("d".to_owned(), row(RunKey::List, 4, http(9))),
        ("e".to_owned(), row(RunKey::List, 5, http(9))),
    ]);
    let tags = HashMap::from([("a", 1), ("b", 2), ("c", 3), ("d", 40)]);
    let t = totals(&rows, &tags, &RunKey::List, 1_000);
    assert_eq!(
        (t.total, t.done, t.failed, t.waiting, t.wait_secs),
        (2, 1, 1, 1, 5)
    );
}

/// a1 / b1: one check of the servers at a time. While a group's check runs, «Проверить работу»
/// starts nothing (and stops nothing); a group's «Проверить» starts nothing while the list check
/// runs; an ended strip keeps the numbers it ended with when a later check takes its rows.
#[tokio::test]
async fn one_check_at_a_time_and_an_ended_strip_keeps_its_numbers() {
    let api = fake();
    let (mut dom, actions, mut seen) = page(&api).await;
    let group = RunKey::Group("g".into());
    let failed = CheckStage::Done(CheckAnswer::Failed(KeyHealthReason::HandshakeFailed));
    let done = hold_check_group(&api, vec![("s1".into(), http(312)), ("s2".into(), failed)]);
    dom.in_runtime(|| actions.check_health("g", "G"));
    rounds(&mut dom, &mut seen).await;
    let _list = hold_check_all(&api, vec![("s1".into(), CheckStage::Queued)], Vec::new());
    dom.in_runtime(|| actions.check_all());
    rounds(&mut dom, &mut seen).await;
    assert!(api.list_check_waiting(), "the list check did not start");
    assert_eq!(
        dom.in_runtime(|| actions.store.current_run()),
        Some(group.clone())
    );
    let report = super::model::HealthReport {
        results: Vec::new(),
        not_checked: 0,
    };
    done.send(Ok(report)).expect("group check pending");
    rounds(&mut dom, &mut seen).await;
    let frozen = || {
        let checks = actions.store.checks.peek();
        checks.get(&group).and_then(|c| c.totals)
    };
    let ended = dom.in_runtime(frozen);
    assert_eq!(ended.map(|t| (t.total, t.done, t.failed)), Some((2, 2, 1)));

    // The list check now runs and takes s1: the group's strip still reads 2 of 2.
    dom.in_runtime(|| actions.check_all());
    let mut later = Shown::default();
    rounds(&mut dom, &mut later).await;
    assert_eq!(
        dom.in_runtime(|| actions.store.current_run()),
        Some(RunKey::List)
    );
    dom.in_runtime(|| actions.check_health("g", "G"));
    rounds(&mut dom, &mut later).await;
    assert_eq!(
        api.group_checks(),
        1,
        "no second group check while the list runs"
    );
    assert_eq!(
        dom.in_runtime(frozen),
        ended,
        "an ended strip never changes"
    );
    let shrunk =
        dom.in_runtime(|| text("ui.servers.check.totals", &[("done", "1"), ("total", "1")]));
    assert!(!later.shows(&shrunk), "{:?}", later.texts);
}

/// a4 + a1: a start refused before any stage (another check of the servers runs, say the
/// Maintenance page's) leaves no strip and no line behind and says so calmly; the previous
/// strip and row lines stay as they were.
#[tokio::test]
async fn a_refused_start_leaves_no_strip_and_says_so_calmly() {
    let api = fake();
    let (mut dom, actions, mut seen) = page(&api).await;
    let first = hold_check_all(&api, vec![("s1".into(), http(312))], Vec::new());
    dom.in_runtime(|| actions.check_all());
    rounds(&mut dom, &mut seen).await;
    let report = super::model::HealthReport {
        results: Vec::new(),
        not_checked: 0,
    };
    first.send(Ok(report)).expect("list check pending");
    rounds(&mut dom, &mut seen).await;
    let before = dom.in_runtime(|| {
        let checks = actions.store.checks.peek();
        checks.get(&RunKey::List).map(|c| (c.state, c.totals))
    });
    assert!(before.is_some());
    let toasts_before = dom.in_runtime(|| actions.toasts.list()).len();

    let refused = hold_check_all(&api, Vec::new(), Vec::new());
    let busy = AppError::conflict(Msg::new("app.servers.checkRunning"));
    refused.send(Err(busy)).expect("held");
    dom.in_runtime(|| actions.check_all());
    rounds(&mut dom, &mut seen).await;
    let after = dom.in_runtime(|| {
        let checks = actions.store.checks.peek();
        checks.get(&RunKey::List).map(|c| (c.state, c.totals))
    });
    assert_eq!(after, before, "the previous strip stays as it was");
    assert_eq!(dom.in_runtime(|| actions.store.current_run()), None);
    let line = dom.in_runtime(|| {
        let rows = actions.store.rows.peek();
        rows.get("s1")
            .and_then(|r| r.check.clone())
            .map(|c| c.stage)
    });
    assert_eq!(line, Some(http(312)));
    let toasts = dom.in_runtime(|| actions.toasts.list());
    assert_eq!(toasts.len(), toasts_before + 1);
    assert_eq!(toasts.last().map(|t| t.kind), Some(ToastKind::Info));

    // A run that fails before its first stage leaves nothing either.
    let gone = hold_check_group(&api, Vec::new());
    drop(gone);
    dom.in_runtime(|| actions.check_health("g", "G"));
    rounds(&mut dom, &mut seen).await;
    let group = dom.in_runtime(|| {
        let checks = actions.store.checks.peek();
        checks.contains_key(&RunKey::Group("g".into()))
    });
    assert!(!group, "no strip for a run that never started");
}

/// a2 / b3: a countdown reads the clock when it renders: a tick left from hours ago (the page
/// open since the morning, or hidden during the wait) never shows as a wait of hours.
#[tokio::test]
async fn a_countdown_reads_the_clock_from_its_first_frame() {
    let api = fake();
    let (mut dom, actions, mut seen) = page(&api).await;
    dom.in_runtime(|| {
        let mut tick = actions.store.tick;
        tick.set(now_ms() - 2 * 3_600_000);
    });
    let until = now_ms() + 41_000;
    let waiting = vec![("s2".to_owned(), CheckStage::Waiting { until })];
    let _held = hold_check_all(&api, waiting, Vec::new());
    dom.in_runtime(|| actions.check_all());
    rounds(&mut dom, &mut seen).await;
    let (row, strip) = dom.in_runtime(|| {
        (
            text("ui.servers.check.waiting", &[("seconds", "41")]),
            text("ui.servers.check.waitLeft", &[("seconds", "41")]),
        )
    });
    assert!(seen.shows(&row), "{row:?} in {:?}", seen.texts);
    assert!(seen.shows(&strip), "{strip:?} in {:?}", seen.texts);
}

/// b2: a stage or a result about a key its row no longer holds (a refresh re-keyed the row
/// while the check ran) or about a row that is gone is dropped: no line, no verdict, not
/// counted; a row re-keyed after its stage landed stops counting too.
#[tokio::test]
async fn a_stage_for_a_key_the_row_no_longer_holds_is_dropped() {
    let api = fake();
    let (dom, actions, _) = page(&api).await;
    let store = actions.store;
    dom.in_runtime(|| {
        store.run_started(RunKey::List, tokio_util::sync::CancellationToken::new());
        let other = CheckKey {
            id: "s1".into(),
            tag: 9,
        };
        let gone = CheckKey {
            id: "zz".into(),
            tag: 0,
        };
        let mine = CheckKey {
            id: "s2".into(),
            tag: 0,
        };
        store.staged(&RunKey::List, &other, http(5));
        store.health_landed(&other, alive(1));
        store.staged(&RunKey::List, &gone, http(5));
        store.staged(&RunKey::List, &mine, http(7));
        let rows = store.rows.peek();
        let s1 = rows.get("s1");
        assert!(s1.is_none_or(|r| r.check.is_none() && r.health.is_none()));
        assert!(!rows.contains_key("zz"));
        assert!(rows.get("s2").is_some_and(|r| r.check.is_some()));
    });
    dom.in_runtime(|| {
        let mut view = store.view;
        view.write().servers[1].key_tag = 7;
        store.run_ended(&RunKey::List);
        let checks = store.checks.peek();
        let counted = checks.get(&RunKey::List).and_then(|c| c.totals);
        assert_eq!(counted.map(|t| t.total), Some(0));
    });
}

/// b4: once the request ended its time stands while the engine stops and the reach probe runs
/// before the answer: the line does not go on counting.
#[test]
fn the_request_time_stands_once_it_ended() {
    crate::lang::init_locales(&[]);
    let dom = VirtualDom::new(|| rsx! {});
    dom.in_runtime(|| {
        *LANG.write() = Lang::Ru;
        let asked = CheckStage::Asked {
            engine: Engine::SingBox,
            engine_ms: 800,
            asked_ms: 10_000,
        };
        let at = |now| stage_text(&asked, now).0;
        assert_eq!(
            at(0),
            "sing-box за 800 мс · рукопожатие и тестовый запрос, 10 с"
        );
        assert_eq!(at(13_000), at(0));
    });
}
