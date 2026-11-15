//! p-check-live: a probe tells its stages in numbers (the real engine to the scripted far side),
//! and a stopped list check ends the probe engines in flight.
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::AppResult;
use vpnte_base::types::{ClientDevice, EnginePref};
use vpnte_profiles::model::Profile;
use vpnte_profiles::uri::parse_uri;

use super::super::list::run_chains;
use super::super::{KeyCheck, ProbeCtx, Started, probe_with, start_probe_engine};
use super::*;
use crate::discipline::Limits;
use crate::discipline::far_side::{Answer, download, far_side, trace};
use crate::live::wire::Wire;
use crate::ping::NetPath;
use crate::test_support::resources;

const FAST: Limits = Limits {
    first_byte: Duration::from_secs(3),
    gap: Duration::from_millis(500),
    deadline: Duration::from_secs(10),
};

/// sing-box from `resources/` (tunnel down); `None` when it is not bundled here.
fn ctx() -> Option<ProbeCtx> {
    let ctx = ProbeCtx {
        singbox_exe: resources().join("sing-box.exe"),
        xray_exe: resources().join("xray.exe"),
        engine_pref: EnginePref::Auto,
        device: ClientDevice::Pc,
        net: NetPath::default(),
        dns_bootstrap_in: None,
    };
    ctx.singbox_exe.exists().then_some(ctx)
}

/// The scripted far side as a SOCKS key on loopback (no handshake budget: a local proxy).
async fn far_key(answers: Vec<Answer>) -> (Profile, tokio::task::JoinHandle<()>) {
    let (inbound, task) = far_side(answers).await;
    let key = parse_uri(&format!("socks://127.0.0.1:{}#S", inbound.port)).unwrap();
    (key, task)
}

/// One probe to the far side with its stages collected in order.
async fn staged(ctx: &ProbeCtx, answers: Vec<Answer>) -> (AppResult<KeyCheck>, Vec<KeyStage>) {
    let (key, task) = far_key(answers).await;
    let (stages, mut told) = Stages::channel();
    let cancel = CancellationToken::new();
    let out = probe_with(&key, ctx, &Wire::plain(), FAST, &cancel, &stages).await;
    task.abort();
    drop(stages);
    let mut seen = Vec::new();
    while let Some(stage) = told.recv().await {
        seen.push(stage);
    }
    (out, seen)
}

/// The engine starting, the engine ready after how long with the request running, the request's
/// end with its time, then the HTTP answer and its time (the key's round trip); a server whose
/// data stops says how far it came, one that never answers how long it was given.
#[tokio::test]
async fn a_probe_tells_each_stage_in_numbers() {
    let Some(ctx) = ctx() else {
        return;
    };
    let whole = vec![trace(), Answer::Send(download(64 * 1024))];
    let (check, stages) = staged(&ctx, whole).await;
    let check = check.unwrap();
    let engine = check.health.engine.unwrap();
    let rtt = check.health.rtt_ms;
    assert!(
        matches!(stages.as_slice(), [
            KeyStage::Starting { engine: e1 },
            KeyStage::Requesting { engine: e2, engine_ms },
            KeyStage::Asked { engine: e3, engine_ms: asked_engine, .. },
            KeyStage::Done(KeyAnswer::Http { status: 200, ms }),
        ] if *e1 == engine && *e2 == engine && *e3 == engine && *engine_ms > 0
            && asked_engine == engine_ms && Some(*ms) == rtt),
        "{stages:?}"
    );

    let frozen = vec![trace(), Answer::SendThenHang(download(16 * 1024))];
    let (_, stages) = staged(&ctx, frozen).await;
    assert!(
        matches!(stages.last(), Some(KeyStage::Done(KeyAnswer::Stalled { bytes })) if *bytes >= 16 * 1024),
        "{stages:?}"
    );

    let (_, stages) = staged(&ctx, vec![Answer::Hang]).await;
    assert!(
        matches!(stages.last(), Some(KeyStage::Done(KeyAnswer::Silent { ms })) if *ms >= 2_900),
        "{stages:?}"
    );
}

/// p-fix-checklive b4: a key that never answers tells the end of its request (with the time it
/// was given) before the log settles, the engine stops and the server's reach is probed, so the
/// row's request counter stops at the request's end, not seconds later at the verdict.
#[tokio::test]
async fn a_silent_key_tells_the_end_of_its_request_before_the_verdict() {
    let Some(ctx) = ctx() else {
        return;
    };
    let (key, task) = far_key(vec![Answer::Hang]).await;
    let (stages, mut told) = Stages::channel();
    let probe = tokio::spawn({
        let ctx = ctx.clone();
        async move {
            let cancel = CancellationToken::new();
            probe_with(&key, &ctx, &Wire::plain(), FAST, &cancel, &stages).await
        }
    });
    let (mut asked, mut answered) = (None, false);
    while let Some(stage) = told.recv().await {
        if let KeyStage::Asked { asked_ms, .. } = stage {
            asked = Some((asked_ms, Instant::now()));
        }
        if let KeyStage::Done(answer) = stage {
            let (asked_ms, at) = asked.expect("the request's end is told before the answer");
            assert_eq!(answer, KeyAnswer::Silent { ms: asked_ms });
            assert!(asked_ms >= 2_900, "{asked_ms}");
            // The settle, the engine stop and the reach probe come after the request's end.
            assert!(
                at.elapsed() >= Duration::from_millis(100),
                "{:?}",
                at.elapsed()
            );
            answered = true;
        }
    }
    assert!(answered, "the answer is told");
    probe.await.unwrap().unwrap();
    task.abort();
}

/// A stop ends the run at once: the result that landed is kept, the probe in flight is dropped
/// and its engine process ends with it (its local port stops answering); nothing else is stopped.
#[tokio::test]
async fn a_stop_keeps_landed_results_and_ends_the_engine_in_flight() {
    let Some(ctx) = ctx() else {
        return;
    };
    let (quick, quick_far) = far_key(vec![trace(), Answer::Send(download(64 * 1024))]).await;
    let (slow, slow_far) = far_key(vec![Answer::Hang]).await;
    let (ports_tx, mut ports) = mpsc::unbounded_channel();
    let (ctx, ports_tx) = (&ctx, &ports_tx);
    // The slow key's engine comes up and is held until the run drops it.
    let check = |key: &String, p: Profile, cancel: CancellationToken, stages: Stages| {
        let hold = key == "slow";
        let probe: std::pin::Pin<Box<dyn Future<Output = AppResult<KeyCheck>> + Send + '_>> =
            Box::pin(async move {
                if !hold {
                    return probe_with(&p, ctx, &Wire::plain(), FAST, &cancel, &stages).await;
                }
                let Started::Ready(engine) = start_probe_engine(&p, ctx, &cancel).await? else {
                    panic!("the slow key's engine did not start");
                };
                let _ = ports_tx.send(engine.socks().port);
                let _held = engine;
                std::future::pending().await
            });
        probe
    };
    let (landed_tx, mut landed) = mpsc::unbounded_channel();
    let on_result = |k: &String, _: &KeyCheck| {
        let _ = landed_tx.send(k.clone());
    };
    let items = vec![
        ("quick".to_owned(), Some(quick)),
        ("slow".to_owned(), Some(slow)),
    ];
    let stop = CancellationToken::new();
    let until = Instant::now() + Duration::from_secs(60);
    let run = run_chains(items, until, &stop, on_result, |_, _| {}, check);
    let stopper = async {
        let port = ports.recv().await.unwrap();
        assert_eq!(landed.recv().await.as_deref(), Some("quick"));
        stop.cancel();
        port
    };
    let ((done, error), port) = tokio::join!(run, stopper);
    let ids: Vec<&str> = done.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(ids, ["quick"], "the landed result is kept");
    assert!(error.is_none(), "a stop is no reason: {error:?}");
    let gone = Instant::now() + Duration::from_secs(5);
    while tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .is_ok()
    {
        assert!(
            Instant::now() < gone,
            "the probe engine still serves its port"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    quick_far.abort();
    slow_far.abort();
}
