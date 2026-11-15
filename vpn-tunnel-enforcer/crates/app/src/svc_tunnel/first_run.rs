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
pub(super) const AFTER: Duration = Duration::from_secs(10);

/// `after` the start ([`AFTER`]), unless a session is up (its engines ran already), each engine
/// runs its `version` once (`pin::first_run` logs «engine first run» with its ms). `true` = both
/// answered (review tunready-a4: not merely that the wait ended).
pub(super) async fn first_runs(
    exes: watch::Receiver<EngineExes>,
    status: watch::Receiver<TunStatus>,
    after: Duration,
    stop: CancellationToken,
) -> bool {
    tokio::select! {
        () = stop.cancelled() => return false,
        () = tokio::time::sleep(after) => {}
    }
    if status.borrow().running {
        return false;
    }
    let exes = exes.borrow().clone();
    let runs = async {
        let singbox = first_run(Engine::SingBox, &exes.singbox).await;
        let xray = first_run(Engine::Xray, &exes.xray).await;
        singbox && xray
    };
    tokio::select! {
        () = stop.cancelled() => false,
        ran = runs => ran,
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use tokio::time::Instant;

    use super::*;

    fn exes_in(dir: &Path) -> watch::Receiver<EngineExes> {
        let exes = EngineExes {
            singbox: dir.join("sing-box.exe"),
            xray: dir.join("xray.exe"),
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
    /// already up skips them; the app's end stops the wait at once. Relative paths are refused
    /// without a spawn (paused time never races a real process), and that is what it reports.
    #[tokio::test(start_paused = true)]
    async fn the_engines_run_once_after_the_start_while_idle() {
        let relative = || exes_in(Path::new(""));
        let start = Instant::now();
        let ended = CancellationToken::new();
        ended.cancel();
        assert!(!first_runs(relative(), status(false), AFTER, ended).await);
        assert_eq!(start.elapsed(), Duration::ZERO);
        let token = CancellationToken::new();
        assert!(!first_runs(relative(), status(true), AFTER, token.clone()).await);
        assert_eq!(start.elapsed(), AFTER);
        assert!(!first_runs(relative(), status(false), AFTER, token).await);
        assert_eq!(start.elapsed(), AFTER * 2);
    }

    /// Review tunready-a4: `first_runs` reports what the runs answered. The bundled engines
    /// (absolute paths) answer; a missing one does not (skipped quietly without `resources/`).
    #[tokio::test]
    async fn the_first_runs_report_what_the_engines_answered() {
        let bundled = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources"));
        if !(bundled.join("sing-box.exe").is_file() && bundled.join("xray.exe").is_file()) {
            return;
        }
        let token = CancellationToken::new();
        let idle = || status(false);
        let ran = first_runs(exes_in(&bundled), idle(), Duration::ZERO, token.clone()).await;
        assert!(ran);
        let missing = bundled.join("missing-engines");
        assert!(!first_runs(exes_in(&missing), idle(), Duration::ZERO, token).await);
    }
}
