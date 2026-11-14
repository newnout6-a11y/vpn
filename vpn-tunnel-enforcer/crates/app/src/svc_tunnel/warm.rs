//! speed3 S3-09 (b): the selected server's name resolved before the click, so a connect plans
//! its upstream without a lookup (lab: «upstream planned» 108-314 ms, ~490 ms on the first
//! connect after install). Restricted by the security review: only the server the user selected,
//! only over the foreign IP-literal DoH resolvers (`resolve::resolve_ahead`), at most once per
//! name per 10 min, at app start, on a selection change and on a network change; never while
//! browsing the list. The answer serves a Proxy start in this process (the resolver's memory)
//! and travels as the hints of a Tunnel start to the helper service (H2), for that start only.
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_core::resolve;
use vpnte_servers::store::{Servers, ServersEvent};
use vpnte_tunnel::api::{MAX_HINT_ADDRS, NameHint};
use vpnte_winnet::adapters::{self, NetChange};

/// Debounce of the network-change watch (a Wi-Fi join flaps several times).
const NET_SETTLE: Duration = Duration::from_millis(1500);

/// The selected server's names resolved ahead, with when.
#[derive(Default)]
pub(crate) struct Ahead {
    answers: Mutex<HashMap<String, (Vec<IpAddr>, Instant)>>,
}

impl Ahead {
    /// The hint for `name` while its answer is at most 10 min old.
    pub(crate) fn hint(&self, name: &str) -> Option<NameHint> {
        let name = name.trim().to_ascii_lowercase();
        let answers = self.answers.lock();
        let (addrs, at) = answers.get(&name)?;
        (at.elapsed() < resolve::RECENT_FOR).then(|| NameHint {
            addrs: addrs.iter().copied().take(MAX_HINT_ADDRS).collect(),
            name,
        })
    }

    /// A start that carried the hint for `name` failed: it goes (S3-09 (e)); the next start
    /// asks the resolvers.
    pub(crate) fn forget(&self, name: &str) {
        self.answers
            .lock()
            .remove(&name.trim().to_ascii_lowercase());
    }

    /// Resolves the selected server's name unless it was within 10 min.
    async fn selected(&self, servers: &Servers) {
        let Some(active) = servers.active().filter(|a| !a.fallback) else {
            return;
        };
        let name = active.row.server.trim().to_ascii_lowercase();
        if self.hint(&name).is_some() {
            return;
        }
        let asked = std::time::Instant::now();
        match resolve::resolve_ahead(&name).await {
            Ok(addrs) => {
                let ms = u64::try_from(asked.elapsed().as_millis()).unwrap_or(u64::MAX);
                tracing::info!(ms, "selected server resolved ahead");
                resolve::remember(&name, addrs.clone());
                self.answers.lock().insert(name, (addrs, Instant::now()));
            }
            Err(err) => tracing::debug!(%err, "selected server not resolved ahead"),
        }
    }
}

/// Resolves ahead at once, then after every selection change and network change, until
/// `cancel`.
pub(crate) fn spawn(ahead: Arc<Ahead>, servers: Arc<Servers>, cancel: CancellationToken) {
    tokio::spawn(async move {
        let mut events = servers.subscribe();
        let mut changes = adapters::watch_network(NET_SETTLE, cancel.clone()).ok();
        ahead.selected(&servers).await;
        loop {
            let again = tokio::select! {
                () = cancel.cancelled() => return,
                event = events.recv() => match event {
                    Ok(ServersEvent::ActiveChanged(_)) | Err(RecvError::Lagged(_)) => true,
                    Ok(_) => false,
                    Err(RecvError::Closed) => return,
                },
                Some(_) = next_change(&mut changes) => true,
            };
            if again {
                ahead.selected(&servers).await;
            }
        }
    });
}

async fn next_change(changes: &mut Option<mpsc::Receiver<NetChange>>) -> Option<NetChange> {
    match changes {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S3-09 (b): a hint is the answer of at most 10 min ago, lower case, at most
    /// `MAX_HINT_ADDRS` addresses; a failed start forgets it.
    #[tokio::test(start_paused = true)]
    async fn a_hint_lives_ten_minutes_and_goes_with_a_failed_start() {
        let ahead = Ahead::default();
        let addrs: Vec<IpAddr> = (1..=10).map(|i| IpAddr::from([203, 0, 113, i])).collect();
        let at = Instant::now();
        ahead
            .answers
            .lock()
            .insert("vpn.example".into(), (addrs, at));
        let hint = ahead.hint(" VPN.example ").expect("fresh");
        assert_eq!(
            (hint.name.as_str(), hint.addrs.len()),
            ("vpn.example", MAX_HINT_ADDRS)
        );
        ahead.forget("vpn.example");
        assert!(ahead.hint("vpn.example").is_none());
        let addrs = vec![IpAddr::from([203, 0, 113, 9])];
        ahead
            .answers
            .lock()
            .insert("vpn.example".into(), (addrs, at));
        tokio::time::advance(resolve::RECENT_FOR).await;
        assert!(ahead.hint("vpn.example").is_none());
    }
}
