//! p-check-live: «Отменить» on a running list check over a real list and real probe engines
//! (loopback SOCKS servers of the test: nothing leaves this PC). The result that landed is stored
//! and answered, the key still in its probe is not checked, and the page heard each key's stages
//! with the key they are about. p-fix-checklive a1: while it runs, no other check of the servers
//! starts (a group's, the Maintenance page's, the list's again): each is refused calmly.
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::ClientDevice;
use vpnte_ui::servers::{AddTarget, CheckStage, CheckWatch, ServersApi, SubscriptionRequest};

use super::super::ServersBackend;
use super::backend::{Env, until};
use super::locales;

/// A SOCKS5 server on loopback: it accepts the CONNECT, then closes (a quick failure) or stays
/// silent with the connection open (`hang`: a probe that would wait for its time limit).
async fn far_side(hang: bool) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(serve(stream, hang));
        }
    });
    (port, task)
}

async fn serve(mut s: TcpStream, hang: bool) -> std::io::Result<()> {
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting).await?;
    let mut methods = vec![0u8; usize::from(greeting[1])];
    s.read_exact(&mut methods).await?;
    s.write_all(&[5, 0]).await?;
    let mut request = [0u8; 4];
    s.read_exact(&mut request).await?;
    let len = match request[3] {
        1 => 4,
        4 => 16,
        _ => usize::from(s.read_u8().await?),
    };
    let mut rest = vec![0u8; len + 2];
    s.read_exact(&mut rest).await?;
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    if hang {
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
    Ok(())
}

#[tokio::test]
async fn a_stop_keeps_and_stores_what_landed() {
    locales();
    let env = Env::new("stop");
    if !env.tunnel.use_engines() {
        return;
    }
    let api = ServersBackend::start(env.backend.clone());
    let ((quick, quick_far), (slow, slow_far)) = (far_side(false).await, far_side(true).await);
    let keys = format!("socks://127.0.0.1:{quick}#quick\nsocks://127.0.0.1:{slow}#slow");
    let (pc, request) = (ClientDevice::Pc, SubscriptionRequest::default());
    api.add(keys, AddTarget::Auto, pc, request).await.unwrap();
    let mut state = api.state();
    let view = until(&mut state, |v| v.servers.len() == 2).await;
    let id = |name: &str| {
        let row = view.servers.iter().find(|s| s.name == name);
        row.map(|s| s.id.clone()).unwrap()
    };
    let (quick_id, slow_id) = (id("quick"), id("slow"));
    let tag = |id: &str| view.servers.iter().find(|s| s.id == id).map(|s| s.key_tag);
    let group = view.groups[0].id.clone();
    let (results, mut landed) = mpsc::unbounded_channel();
    let (stages, mut staged) = mpsc::unbounded_channel();
    let stop = CancellationToken::new();
    let watch = CheckWatch {
        results,
        stages,
        stop: stop.clone(),
    };
    let mut slow_stages = Vec::new();
    let stopper = async {
        let (mut quick_landed, mut slow_asking) = (false, false);
        while !(quick_landed && slow_asking) {
            tokio::select! {
                Some((key, _)) = landed.recv() => if key.id == quick_id {
                    assert_eq!(Some(key.tag), tag(&quick_id), "the key the row holds");
                    quick_landed = true;
                },
                Some((key, stage)) = staged.recv() => if key.id == slow_id {
                    slow_asking |= matches!(stage, CheckStage::Requesting { .. });
                    slow_stages.push(stage);
                },
            }
        }
        let refused = api.check_group_health(&group).await.unwrap_err();
        assert_eq!(refused.user_msg().key, "app.servers.checkRunning");
        let (results, stages) = (mpsc::unbounded_channel().0, mpsc::unbounded_channel().0);
        let again = CheckWatch {
            results,
            stages,
            stop: CancellationToken::new(),
        };
        let refused = api.check_all_health_watched(again).await.unwrap_err();
        assert_eq!(refused.user_msg().key, "app.servers.checkRunning");
        stop.cancel();
    };
    let run = async { tokio::join!(api.check_all_health_watched(watch), stopper).0 };
    let report = tokio::time::timeout(Duration::from_secs(20), run).await;
    let report = report.expect("the stop answers at once").unwrap();
    let checked: Vec<&str> = report.results.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(
        checked,
        [quick_id.as_str()],
        "the landed result is answered"
    );
    assert_eq!(report.not_checked, 1);
    assert!(matches!(
        slow_stages[..],
        [CheckStage::Queued, CheckStage::Starting { .. }, ..]
    ));
    // Stored like a finished run's results; the key the stop caught keeps its old state.
    let stored = |v: &vpnte_ui::servers::ServersView, id: &str| {
        v.servers.iter().any(|s| s.id == id && s.health.is_some())
    };
    let view = until(&mut state, |v| stored(v, &quick_id)).await;
    assert!(!stored(&view, &slow_id));
    quick_far.abort();
    slow_far.abort();
}
