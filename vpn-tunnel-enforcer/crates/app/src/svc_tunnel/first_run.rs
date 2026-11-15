//! Lab live-11 L11-5: the first execution of an engine binary new to this Windows (image load,
//! Defender's first scan) cost ~0.8 s of the first connect after an install. This process's own
//! engines (Proxy mode; Tunnel mode too when the app runs elevated without the service) run
//! their `version` once ahead of it, while the app is idle.
use std::time::Duration;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::Engine;
use vpnte_engine::pin::first_run;
use vpnte_tunnel::api::TunStatus;
use vpnte_tunnel::runtime::EngineExes;

/// After the app's own start-up work, which the runs must not slow down.
const AFTER: Duration = Duration::from_secs(10);

/// [`AFTER`] after the start, unless a session is up (its engines ran already), each engine runs
/// its `version` once (`pin::first_run` logs «engine first run» with its ms). `true` = they ran.
pub(super) async fn first_runs(
    exes: watch::Receiver<EngineExes>,
    status: watch::Receiver<TunStatus>,
    stop: CancellationToken,
) -> bool {
    tokio::select! {
        () = stop.cancelled() => return false,
        () = tokio::time::sleep(AFTER) => {}
    }
    if status.borrow().running {
        return false;
    }
    let exes = exes.borrow().clone();
    let runs = async {
        first_run(Engine::SingBox, &exes.singbox).await;
        first_run(Engine::Xray, &exes.xray).await;
    };
    tokio::select! {
        () = stop.cancelled() => false,
        () = runs => true,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tokio::time::Instant;

    use super::*;

    /// Relative paths: `first_run` refuses them without spawning anything, so paused time
    /// never races a real process.
    fn exes() -> watch::Receiver<EngineExes> {
        let exes = EngineExes {
            singbox: PathBuf::from("sing-box.exe"),
            xray: PathBuf::from("xray.exe"),
        };
        watch::channel(exes).1
    }

    fn status(running: bool) -> watch::Receiver<TunStatus> {
        let status = TunStatus {
            running,
            ..TunStatus::default()
        };
        watch::channel(status).1
    }

    /// Lab live-11 L11-5: the engines run once [`AFTER`] the start while nothing runs; a session
    /// already up skips them; the app's end stops the wait at once.
    #[tokio::test(start_paused = true)]
    async fn the_engines_run_once_after_the_start_while_idle() {
        let start = Instant::now();
        let ended = CancellationToken::new();
        ended.cancel();
        assert!(!first_runs(exes(), status(false), ended).await);
        assert_eq!(start.elapsed(), Duration::ZERO);
        assert!(!first_runs(exes(), status(true), CancellationToken::new()).await);
        assert_eq!(start.elapsed(), AFTER);
        assert!(first_runs(exes(), status(false), CancellationToken::new()).await);
        assert_eq!(start.elapsed(), AFTER * 2);
    }
}
