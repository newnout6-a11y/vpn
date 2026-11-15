//! speed3 S3-09 (b): the selected server's name resolved before the click, so a connect plans
//! its upstream without a lookup (lab: «upstream planned» 108-314 ms, ~490 ms on the first
//! connect after install). Lab L11-4: a switch resolved its candidate inside the switch
//! (336-370 ms in Proxy, 129-149 in Tunnel), so the names of the rows a user is likely to pick
//! next are resolved as well: the selected server's group's checked healthy rows, the fastest
//! [`LIKELY`]. Restricted by the security review: only over the foreign IP-literal DoH resolvers
//! (`resolve::resolve_ahead`), at most once per name per 10 min, at app start, on a selection
//! change, after the rows changed (a check wrote its results) and on a network change; never
//! while browsing the list. The answer serves a Proxy start or switch in this process (the
//! resolver's memory) and travels as the hints of a Tunnel start to the helper service (H2), for
//! that start only.
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
use vpnte_servers::model::ServerRow;
use vpnte_servers::store::{Servers, ServersEvent};
use vpnte_tunnel::api::{MAX_HINT_ADDRS, NameHint};
use vpnte_winnet::adapters::{self, NetChange};

use crate::svc_auto::likely_picks;

/// Debounce of the network-change watch (a Wi-Fi join flaps several times) and of row changes
/// (a group check writes its results one by one).
const NET_SETTLE: Duration = Duration::from_millis(1500);
/// How many names of the selected server's group are resolved ahead besides its own (lab L11-4).
const LIKELY: usize = 4;

/// Server names resolved ahead (the selected server's and its likely picks'), with when.
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

    /// Resolves the selected server's name and its likely picks' ([`likely_names`]), each
    /// unless it was within 10 min.
    async fn likely(&self, servers: &Servers) {
        let Some(active) = servers.active().filter(|a| !a.fallback) else {
            return;
        };
        let names = servers.read(|doc| likely_names(&active.row, &doc.profiles));
        for (name, selected) in names {
            self.ahead(name, selected).await;
        }
    }

    /// One name ahead unless it was within 10 min (`resolve_ahead` remembers the answer).
    async fn ahead(&self, name: String, selected: bool) {
        if self.hint(&name).is_some() {
            return;
        }
        let asked = std::time::Instant::now();
        match resolve::resolve_ahead(&name).await {
            Ok(addrs) => {
                let ms = u64::try_from(asked.elapsed().as_millis()).unwrap_or(u64::MAX);
                if selected {
                    tracing::info!(ms, "selected server resolved ahead");
                } else {
                    tracing::info!(ms, "likely server resolved ahead");
                }
                self.answers.lock().insert(name, (addrs, Instant::now()));
            }
            Err(err) => tracing::debug!(%err, "server not resolved ahead"),
        }
    }
}

/// The names to resolve ahead: the selected row's (`true`), then those of its group's likely
/// picks ([`likely_picks`]) up to [`LIKELY`] more; host names only, lower case, each once.
fn likely_names(selected: &ServerRow, rows: &[ServerRow]) -> Vec<(String, bool)> {
    let picks = likely_picks(rows, selected).into_iter();
    let hosts = std::iter::once((selected, true)).chain(picks.map(|r| (r, false)));
    let mut names: Vec<(String, bool)> = Vec::new();
    for (row, selected) in hosts {
        let name = row.server.trim().to_ascii_lowercase();
        let literal = name.trim_matches(['[', ']']).parse::<IpAddr>().is_ok();
        if !literal && !name.is_empty() && names.iter().all(|(n, _)| *n != name) {
            names.push((name, selected));
        }
        if names.iter().filter(|(_, s)| !s).count() == LIKELY {
            break;
        }
    }
    names
}

/// Resolves ahead at once, then after every selection change, network change and settled row
/// change, until `cancel`.
pub(crate) fn spawn(ahead: Arc<Ahead>, servers: Arc<Servers>, cancel: CancellationToken) {
    tokio::spawn(async move {
        let mut events = servers.subscribe();
        let mut changes = adapters::watch_network(NET_SETTLE, cancel.clone()).ok();
        // The rows changed: once they stop changing for a moment (a check's results).
        let mut settled: Option<Instant> = None;
        ahead.likely(&servers).await;
        loop {
            let again = tokio::select! {
                () = cancel.cancelled() => return,
                event = events.recv() => match event {
                    Ok(ServersEvent::ActiveChanged(_)) | Err(RecvError::Lagged(_)) => true,
                    Ok(ServersEvent::Changed) => {
                        settled = Some(Instant::now() + NET_SETTLE);
                        false
                    }
                    Ok(_) => false,
                    Err(RecvError::Closed) => return,
                },
                Some(_) = next_change(&mut changes) => true,
                () = until(settled) => true,
            };
            if again {
                settled = None;
                ahead.likely(&servers).await;
            }
        }
    });
}

async fn until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
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

    /// A row of group `group` dialling `host`, a check found healthy with `rtt_ms` (`None`:
    /// never checked).
    fn row(id: &str, group: &str, host: &str, rtt_ms: Option<u32>) -> ServerRow {
        use vpnte_servers::model::{GroupId, HealthRecord, Origin, ProfileId};
        let uri = format!(
            "vless://00000000-0000-4000-8000-000000000001@{host}:443?security=tls&sni=a.test&type=tcp#{id}"
        );
        let profile = vpnte_profiles::uri::parse_uri(&uri).expect("fake key parses");
        let device = vpnte_base::types::ClientDevice::Pc;
        let mut row =
            ServerRow::new(&profile, GroupId::from(group), Origin::Manual, device, 1).expect("row");
        row.id = ProfileId::from(id);
        row.health = rtt_ms.map(|ms| HealthRecord {
            online: true,
            at: 10,
            rtt_ms: Some(ms),
            reason: None,
            egress_ip: None,
        });
        row
    }

    /// Lab L11-4: the selected server's name first, then `LIKELY` names of its group's checked
    /// healthy rows, the fastest first; literals, other groups, unchecked rows and a name twice
    /// are left out.
    #[test]
    fn the_likely_names_are_the_selected_groups_fastest_checked_rows() {
        let selected = row("sel", "g", "Sel.Example", Some(500));
        let mut rows = vec![selected.clone()];
        for (i, ms) in [400, 90, 300, 200, 100, 50].into_iter().enumerate() {
            rows.push(row(
                &format!("r{i}"),
                "g",
                &format!("r{i}.example"),
                Some(ms),
            ));
        }
        rows.push(row("dup", "g", "sel.example", Some(10)));
        rows.push(row("literal", "g", "203.0.113.4", Some(5)));
        rows.push(row("unchecked", "g", "new.example", None));
        rows.push(row("elsewhere", "h", "other.example", Some(1)));
        let names = likely_names(&selected, &rows);
        let want = [
            ("sel.example", true),
            ("r5.example", false),
            ("r1.example", false),
            ("r4.example", false),
            ("r3.example", false),
        ];
        let got: Vec<_> = names.iter().map(|(n, s)| (n.as_str(), *s)).collect();
        assert_eq!(got, want);
    }
}
