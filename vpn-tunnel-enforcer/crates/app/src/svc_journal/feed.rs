//! The journal's feeds besides the notifier: session starts (the lifecycle's open session),
//! session ends with their outcome (new rows of the history) and the runtime's warnings (a
//! message the start page shows that nothing recorded).
use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::now_ms;
use vpnte_tunnel::api::TunStatus;
use vpnte_tunnel::history::History;
use vpnte_tunnel::lifecycle::SessionView;

use super::Journal;
use super::record::{NewRecord, Tone, Topic, session_end, session_up};
use crate::services::Backend;

/// Starts the feeds under `backend.shutdown` (inside the tokio runtime, after the tunnel is set).
pub fn spawn(journal: Arc<Journal>, backend: &Arc<Backend>) {
    let shutdown = backend.shutdown.clone();
    tokio::spawn(ends(
        journal.clone(),
        backend.history.clone(),
        shutdown.clone(),
    ));
    if let Ok(tunnel) = backend.tunnel() {
        tokio::spawn(starts(journal.clone(), tunnel.session(), shutdown.clone()));
        tokio::spawn(warnings(journal, tunnel.runtime_status(), shutdown));
    }
}

/// Every row the history gains is a session end (or a failed start).
pub(super) async fn ends(journal: Arc<Journal>, history: History, shutdown: CancellationToken) {
    let mut changes = history.subscribe();
    let mut known: HashSet<String> = history.list().into_iter().map(|e| e.id).collect();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            changed = changes.changed() => if changed.is_err() { break },
        }
        let entries = history.list();
        let mut new: Vec<_> = entries.iter().filter(|e| !known.contains(&e.id)).collect();
        new.sort_by_key(|e| e.ended_at);
        journal.append(new.into_iter().map(session_end));
        // A clear or the ring's cap drops rows: only the current ones need remembering.
        known = entries.into_iter().map(|e| e.id).collect();
    }
}

/// Every session that comes up, once (a session taken over after a restart of the app was
/// already written by the run that started it).
pub(super) async fn starts(
    journal: Arc<Journal>,
    mut session: watch::Receiver<Option<SessionView>>,
    shutdown: CancellationToken,
) {
    loop {
        let view = session.borrow_and_update().clone();
        if let Some(view) = view
            && !journal.has_start(view.started_at)
        {
            let engine = view.engine.as_ref().map(|e| e.kind);
            let up = session_up(view.started_at, &view.profile_name, view.mode, engine);
            journal.append([up]);
        }
        tokio::select! {
            () = shutdown.cancelled() => break,
            changed = session.changed() => if changed.is_err() { break },
        }
    }
}

/// A new runtime warning (restarts, an unreachable proxy, ...) as a warning event.
pub(super) async fn warnings(
    journal: Arc<Journal>,
    mut status: watch::Receiver<TunStatus>,
    shutdown: CancellationToken,
) {
    let mut last: Option<Msg> = status.borrow_and_update().warning.clone();
    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            changed = status.changed() => if changed.is_err() { break },
        }
        let warning = status.borrow_and_update().warning.clone();
        if warning == last {
            continue;
        }
        if let Some(title) = &warning {
            journal.append([NewRecord {
                at: now_ms(),
                topic: Topic::Connection,
                tone: Tone::Warn,
                title: title.clone(),
                body: None,
                session: None,
            }]);
        }
        last = warning;
    }
}
