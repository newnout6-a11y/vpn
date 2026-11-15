//! Lab live-13 L13-2: a connect whose exit proof waits for the server name's handshake slot says
//! so. RU networks freeze a name after ~3 new TLS handshakes a minute, so switches and checks a
//! minute before can leave a fresh connect waiting up to a minute (the lab saw 26 s) behind a
//! bare «Проверяем выход…». The proof keeps that discipline; the status carries the moment the
//! slot comes, and the start page counts down to it.
use std::future::Future;
use std::time::Duration;

use tokio::sync::watch;
use vpnte_base::types::{UnixMs, now_ms};

use crate::api::TunStatus;

/// Runs `proof`, which first waits `wait` for its handshake slot (zero: none). Meanwhile the
/// status carries the moment the slot comes, until it comes or the proof ends or is dropped (the
/// session's own traffic proved the start first).
pub(super) async fn shown<T>(
    status: &watch::Sender<TunStatus>,
    wait: Duration,
    proof: impl Future<Output = T>,
) -> T {
    if wait.is_zero() {
        return proof.await;
    }
    let until = now_ms().saturating_add(UnixMs::try_from(wait.as_millis()).unwrap_or(UnixMs::MAX));
    status.send_modify(|s| s.proof_waits_until = Some(until));
    let _gone = Cleared(status);
    tokio::pin!(proof);
    tokio::select! {
        out = &mut proof => out,
        () = tokio::time::sleep(wait) => {
            clear(status);
            proof.await
        }
    }
}

/// Clears the wait when dropped.
struct Cleared<'a>(&'a watch::Sender<TunStatus>);

impl Drop for Cleared<'_> {
    fn drop(&mut self) {
        clear(self.0);
    }
}

fn clear(status: &watch::Sender<TunStatus>) {
    status.send_if_modified(|s| s.proof_waits_until.take().is_some());
}
