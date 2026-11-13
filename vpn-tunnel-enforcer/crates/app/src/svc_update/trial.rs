//! The trial of a freshly installed engine (research §4.7 step 6): while it is on trial, every
//! start that runs its file counts — one that reaches «подключено» ends the trial, three that
//! end in an error in a row switch back by themselves (`EngineStore::record_start`), said in
//! one line. What counts is what the tunnel's runtime started (`TunnelOps::engine_starts`), not
//! what a start was meant to run: an in-place server switch keeps the running engines, Tunnel
//! mode through the helper service runs the service's own, and a process that keeps its engines
//! runs those of the app start (fix-follow: pfollow-a2, pfollow-b1).
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_tunnel::fsm::{TunnelSnapshot, TunnelState};
use vpnte_tunnel::runtime::EngineStarts;
use vpnte_update::policy::{SINGBOX, XRAY};
use vpnte_update::store::{Choice, Origin};

use super::Updates;
use super::actions::engine_name;

/// Watches the tunnel for as long as the app runs: any install may start a trial.
pub(super) fn spawn(u: &Arc<Updates>) {
    let Ok(tunnel) = u.backend.tunnel() else {
        return;
    };
    let Some(starts) = tunnel.engine_starts() else {
        return;
    };
    let this = u.clone();
    let count = move |id: &'static str, exe: &Path, ok: bool| this.count(id, exe, ok);
    let cancel = u.backend.shutdown.child_token();
    tokio::spawn(watch_starts(tunnel.snapshot(), starts, count, cancel));
}

/// Each time the tunnel settles, the engine files its runtime started since the last settle
/// count: for «подключено», or against it after an error. A start the user cancelled or
/// stopped says nothing about the engine.
async fn watch_starts(
    mut snapshot: watch::Receiver<TunnelSnapshot>,
    mut starts: watch::Receiver<EngineStarts>,
    count: impl Fn(&'static str, &Path, bool),
    cancel: CancellationToken,
) {
    let mut seen = starts.borrow_and_update().clone();
    loop {
        tokio::select! {
            changed = snapshot.changed() => if changed.is_err() { return },
            () = cancel.cancelled() => return,
        }
        let (transition, state) = {
            let snap = snapshot.borrow_and_update();
            (snap.transition, snap.state)
        };
        if transition.is_some() {
            continue;
        }
        let now = starts.borrow_and_update().clone();
        let ran = ran_since(&seen, &now);
        seen = now;
        let ok = match state {
            TunnelState::Connected => true,
            TunnelState::Error => false,
            _ => continue,
        };
        for (id, exe) in &ran {
            count(id, exe, ok);
        }
    }
}

/// The engines whose files started between two reads, each with the file of its last start.
fn ran_since(before: &EngineStarts, now: &EngineStarts) -> Vec<(&'static str, PathBuf)> {
    [
        (SINGBOX, &before.singbox, &now.singbox),
        (XRAY, &before.xray, &now.xray),
    ]
    .into_iter()
    .filter(|(_, before, now)| now.count > before.count)
    .filter_map(|(id, _, now)| Some((id, now.exe.clone()?)))
    .collect()
}

/// Two spellings of one file: the runtime starts the canonical install path.
fn same_file(a: &Path, b: &Path) -> bool {
    a == b
        || matches!(
            (std::fs::canonicalize(a), std::fs::canonicalize(b)),
            (Ok(a), Ok(b)) if a == b
        )
}

impl Updates {
    /// One start that ran `exe` of engine `id`: it counts while that file is the active
    /// downloaded version on trial (installed again or switched back meanwhile: that version's
    /// trial is its own; `record_start` ignores a version whose trial is over).
    fn count(&self, id: &str, exe: &Path, ok: bool) {
        let active = self.store.resolve(id);
        if !matches!(active.origin, Origin::Downloaded { .. }) || !same_file(&active.exe, exe) {
            return;
        }
        match self.store.record_start(id, ok) {
            Ok(Some(rolled)) => {
                let to = match rolled.to {
                    Choice::Downloaded(v) => v.to_string(),
                    Choice::Bundled => vpnte_update::policy::bundled_version(id)
                        .map(|v| v.to_string())
                        .unwrap_or_default(),
                };
                // Engines that follow the update channel run the version switched back to from
                // the next start on; otherwise it waits for the app's restart.
                let key = if self.apply_engines() {
                    "app.update.trialRolledBack"
                } else {
                    "app.update.trialFailed"
                };
                let msg = Msg::new(key)
                    .arg("name", engine_name(id))
                    .arg("from", rolled.from)
                    .arg("to", to);
                self.note(msg, true);
            }
            Ok(None) => {}
            Err(err) => tracing::warn!(engine = id, %err, "engine trial not recorded"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use parking_lot::Mutex;
    use vpnte_tunnel::fsm::Transition;

    use super::*;

    type Counted = Vec<(&'static str, PathBuf, bool)>;

    /// The tunnel as the trial sees it: the lifecycle's snapshot and the runtime's engine starts.
    struct Tunnel {
        snapshot: watch::Sender<TunnelSnapshot>,
        starts: watch::Sender<EngineStarts>,
        counted: Arc<Mutex<Counted>>,
    }

    fn tunnel() -> Tunnel {
        let snapshot = watch::Sender::new(TunnelSnapshot::default());
        let starts = watch::Sender::new(EngineStarts::default());
        let counted = Arc::new(Mutex::new(Counted::new()));
        let sink = counted.clone();
        let count = move |id, exe: &Path, ok| sink.lock().push((id, exe.to_path_buf(), ok));
        let (rx, starts_rx) = (snapshot.subscribe(), starts.subscribe());
        tokio::spawn(watch_starts(rx, starts_rx, count, CancellationToken::new()));
        Tunnel {
            snapshot,
            starts,
            counted,
        }
    }

    impl Tunnel {
        /// One transition: the engine files the runtime started for it, then where it ended.
        async fn run(&self, transition: Transition, spawned: &[(&str, &str)], end: TunnelState) {
            self.snapshot
                .send_modify(|s| s.transition = Some(transition));
            settle().await;
            for &(id, file) in spawned {
                self.starts.send_modify(|s| {
                    let started = if id == XRAY {
                        &mut s.xray
                    } else {
                        &mut s.singbox
                    };
                    started.count += 1;
                    started.exe = Some(PathBuf::from(file));
                });
            }
            self.snapshot.send_modify(|s| {
                s.transition = None;
                s.state = end;
            });
            settle().await;
        }

        fn take(&self) -> Counted {
            std::mem::take(&mut self.counted.lock())
        }
    }

    /// Lets the watcher handle everything sent so far (time is paused: it moves on only once
    /// every task waits).
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    /// pfollow-b1 / a2: a start counts for an engine only when the runtime started that
    /// engine's file for it — passed at «подключено», failed at an error, with the file it ran.
    #[tokio::test(start_paused = true)]
    async fn a_start_counts_the_files_it_ran() {
        let t = tunnel();
        let new = r"C:\engines\sing-box\1.14.5\sing-box.exe";
        t.run(
            Transition::Connecting,
            &[(SINGBOX, new)],
            TunnelState::Connected,
        )
        .await;
        assert_eq!(t.take(), [(SINGBOX, PathBuf::from(new), true)]);

        let xray = r"C:\engines\xray\26.11.20\xray.exe";
        let spawned = [(XRAY, xray), (SINGBOX, new)];
        t.run(Transition::Reconnecting, &spawned, TunnelState::Error)
            .await;
        let failed = t.take();
        assert!(
            failed.contains(&(SINGBOX, PathBuf::from(new), false)),
            "{failed:?}"
        );
        assert!(
            failed.contains(&(XRAY, PathBuf::from(xray), false)),
            "{failed:?}"
        );
    }

    /// pfollow-b1: an in-place server switch or rotation keeps the running engines, and a
    /// Tunnel-mode start through the helper service (pfollow-a2) runs none of this process:
    /// neither counts, whatever is on trial. A cancelled start's files are not carried over.
    #[tokio::test(start_paused = true)]
    async fn starts_that_ran_no_file_here_count_nothing() {
        let t = tunnel();
        t.run(Transition::Reconnecting, &[], TunnelState::Connected)
            .await;
        t.run(Transition::Connecting, &[], TunnelState::Error).await;
        let file = r"C:\engines\sing-box\1.14.5\sing-box.exe";
        t.run(
            Transition::Connecting,
            &[(SINGBOX, file)],
            TunnelState::Disconnected,
        )
        .await;
        t.run(Transition::Reconnecting, &[], TunnelState::Connected)
            .await;
        assert_eq!(t.take(), []);
    }

    #[test]
    fn one_file_in_two_spellings_is_the_same() {
        let here = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let dotted = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/../Cargo.toml");
        assert!(same_file(&here, &dotted));
        assert!(!same_file(&here, &here.with_file_name("build.rs")));
    }
}
