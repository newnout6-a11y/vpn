//! «Тест скорости»: one run at a time as the registry's `speed-test` operation (the probes'
//! `run`: latency, multi-stream download and upload bound to the TUN address, the egress check),
//! its progress copied into the page's own channel, the result committed to the history before
//! the answer. A Soft session is refused: the probes' measurement binds to the TUN and has no
//! proxy route, so it would time the direct line and call it the VPN.
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;

use futures_util::future::BoxFuture;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::ops::{RunOpts, Source};
use vpnte_probes::public_ip::{Family, IpReader, IpRoute, WAVE_BUDGET};
use vpnte_probes::speedtest::{
    self as probe, Connection, EgressRef, EgressSource, IpFamily, Plan, SpeedEnv,
};
use vpnte_tunnel::lifecycle::SessionView;
use vpnte_ui::speedtest::{SpeedProgress, SpeedResult};
use vpnte_winnet::adapters::TUN_V4;

use super::{Session, Shared, project};
use crate::services::TunnelOps;

/// Runs one test through the running TUN session. No session = `Conflict`
/// `probes.speed.notConnected`; Soft = `Conflict` `app.tools.speed.softUnavailable`.
pub(super) async fn run(
    shared: &Arc<Shared>,
    progress: watch::Sender<SpeedProgress>,
    cancel: CancellationToken,
) -> AppResult<SpeedResult> {
    let tunnel = shared.backend.tunnel()?.clone();
    let profile = match Session::of(&tunnel.runtime_status().borrow()) {
        Session::Off => {
            return Err(AppError::conflict(Msg::new("probes.speed.notConnected")));
        }
        Session::Proxy { .. } => {
            return Err(AppError::conflict(Msg::new(
                "app.tools.speed.softUnavailable",
            )));
        }
        Session::Tun { profile, .. } => profile,
    };
    let env = SpeedEnv {
        connection: Some(Connection {
            tun_v4: Some(TUN_V4.addr()),
            profile,
        }),
        egress: Some(Arc::new(ExitCheck {
            tunnel: tunnel.clone(),
            reader: shared.reader.clone(),
        })),
        plan: Plan::standard(),
    };
    let opts = RunOpts {
        source: Source::Ui,
        cancel: Some(cancel),
        ..RunOpts::default()
    };
    let (frames, seen) = watch::channel(probe::SpeedProgress::default());
    let work = probe::run(
        &shared.backend.ops,
        shared.speed_tests.clone(),
        env,
        server_switched(tunnel.session()),
        frames,
        opts,
    );
    let result = forward(work, seen, &progress).await?;
    shared.publish();
    Ok(project::speed_result(&result))
}

/// Awaits `work` while copying its progress frames into the page's channel.
pub(super) async fn forward<T>(
    work: impl Future<Output = AppResult<T>>,
    mut frames: watch::Receiver<probe::SpeedProgress>,
    page: &watch::Sender<SpeedProgress>,
) -> AppResult<T> {
    let copy = |frame: probe::SpeedProgress| {
        if let Some(next) = project::speed_progress(frame) {
            page.send_if_modified(|now| project::replace(now, next));
        }
    };
    let mut work = std::pin::pin!(work);
    loop {
        tokio::select! {
            biased;
            done = &mut work => {
                // The last frame (Complete) may land together with the answer.
                copy(*frames.borrow());
                return done;
            }
            changed = frames.changed() => match changed {
                Ok(()) => copy(*frames.borrow_and_update()),
                // Every sender is gone: only the answer is left.
                Err(_) => return work.await,
            },
        }
    }
}

/// Resolves when the session moves to another server while the test runs (B-ST-5: the figures
/// would mix two servers). An engine restart on the same server does not count; a closed
/// channel never resolves.
pub(super) fn server_switched(
    mut session: watch::Receiver<Option<SessionView>>,
) -> impl Future<Output = ()> + Send + 'static {
    let start = server(&session.borrow_and_update());
    async move {
        while session.changed().await.is_ok() {
            let now = server(&session.borrow_and_update());
            if now.is_some() && now != start {
                return;
            }
        }
        std::future::pending().await
    }
}

fn server(session: &Option<SessionView>) -> Option<String> {
    session.as_ref().map(|s| s.profile_id.clone())
}

/// The exit-IP check of a run: the references come from the session's IP monitor, the samples
/// are reads bound to the TUN address (the monitor's own state is not touched).
struct ExitCheck {
    tunnel: Arc<dyn TunnelOps>,
    reader: Arc<IpReader>,
}

impl EgressSource for ExitCheck {
    fn reference(&self) -> EgressRef {
        let evidence = self.tunnel.ip_evidence();
        let evidence = evidence.borrow();
        EgressRef {
            baseline: evidence.baseline,
            real_ip: evidence.real_ip,
        }
    }

    fn sample(&self, family: IpFamily) -> BoxFuture<'_, Option<IpAddr>> {
        Box::pin(async move {
            let route = IpRoute::Tun {
                v4: TUN_V4.addr(),
                v6: None,
            };
            let family = match family {
                IpFamily::V4 => Family::V4,
                IpFamily::V6 => Family::V6,
            };
            // The run bounds the read and drops it with itself; nothing else cancels it.
            let sample = self
                .reader
                .wave(&route, family, WAVE_BUDGET, &CancellationToken::new())
                .await?;
            Some(sample.ip)
        })
    }
}
