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
//! that start only. Lab L12-5: the first Tunnel start after install looked up the graph names
//! the hint missed for 951 ms, so every host name of the selected server's graph is resolved
//! ahead (together), and a start joins the lookups still in flight at the click for [`JOIN`].
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::join_all;
use parking_lot::Mutex;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::ClientDevice;
use vpnte_core::resolve;
use vpnte_profiles::model::Profile;
use vpnte_servers::model::ServerRow;
use vpnte_servers::store::{Servers, ServersEvent};
use vpnte_tunnel::api::{MAX_HINT_ADDRS, MAX_HINT_NAMES, NameHint};
use vpnte_winnet::adapters::{self, NetChange};

use crate::svc_auto::likely_picks;

/// Debounce of the network-change watch (a Wi-Fi join flaps several times) and of row changes
/// (a group check writes its results one by one).
const NET_SETTLE: Duration = Duration::from_millis(1500);
/// How many names of the selected server's group are resolved ahead besides its own (lab L11-4).
const LIKELY: usize = 4;
/// How long a Tunnel start waits for lookups ahead still in flight at the click (lab L12-5: the
/// service's own cold lookup of a graph's names took 951 ms).
const JOIN: Duration = Duration::from_secs(1);

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
        (at.elapsed() < resolve::RECENT_FOR).then(|| hint_of(name, addrs))
    }

    /// The hints for `names` (at most [`MAX_HINT_NAMES`]): each answer of at most 10 min ago,
    /// else what its lookup ahead still in flight brings within [`JOIN`] (joined, never asked
    /// again: no new lookup at the click).
    pub(crate) async fn hints(&self, names: &[String]) -> Vec<NameHint> {
        let until = Instant::now() + JOIN;
        let each = names.iter().take(MAX_HINT_NAMES).map(|name| async move {
            if let Some(hint) = self.hint(name) {
                return Some(hint);
            }
            let joined = tokio::time::timeout_at(until, resolve::recall(name)).await;
            let addrs = joined.ok().flatten().filter(|a| !a.is_empty())?;
            Some(hint_of(name.trim().to_ascii_lowercase(), &addrs))
        });
        join_all(each).await.into_iter().flatten().collect()
    }

    /// Holds `addrs` for `name` as an answer ahead of now.
    #[cfg(test)]
    pub(crate) fn hold(&self, name: &str, addrs: Vec<IpAddr>) {
        let name = name.trim().to_ascii_lowercase();
        self.answers.lock().insert(name, (addrs, Instant::now()));
    }

    /// A request that carried the hint for `name` failed: it goes (S3-09 (e), speed3-a1), from
    /// here and from this process's resolver memory; the next start asks the resolvers.
    pub(crate) fn forget(&self, name: &str) {
        let name = name.trim().to_ascii_lowercase();
        self.answers.lock().remove(&name);
        resolve::drop_names(&[name]);
    }

    /// Resolves the selected server's graph names and its likely picks' ([`likely_names`]), all
    /// at once, each unless it was within 10 min.
    async fn likely(&self, servers: &Servers) {
        let Some(active) = servers.active().filter(|a| !a.fallback) else {
            return;
        };
        // Read (and decrypted) outside the list's lock.
        let own = row_hosts(&active.row);
        let names = servers.read(|doc| likely_names(&own, &active.row, &doc.profiles));
        let each = names
            .into_iter()
            .map(|(name, selected)| self.ahead(name, selected));
        join_all(each).await;
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

/// `addrs` as the hint for `name` (at most [`MAX_HINT_ADDRS`]).
fn hint_of(name: String, addrs: &[IpAddr]) -> NameHint {
    NameHint {
        addrs: addrs.iter().copied().take(MAX_HINT_ADDRS).collect(),
        name,
    }
}

/// Every host name `profile`'s Xray graph dials, as the runtime plans its start
/// (`ProxyGraph::hosts`: a provider graph's members, an XHTTP download host), lower case, each
/// once, at most [`MAX_HINT_NAMES`]; its own host name when no graph is built for it here.
pub(crate) fn graph_hosts(profile: &Profile, device: ClientDevice) -> Vec<String> {
    let hosts = match vpnte_engine::xray_config::proxy_graph(profile, device) {
        Ok(graph) => graph.hosts(),
        Err(_) => match &profile.server {
            vpnte_profiles::model::Host::Domain(name) => vec![name.to_string()],
            vpnte_profiles::model::Host::Ip(_) => Vec::new(),
        },
    };
    let mut names: Vec<String> = Vec::new();
    for host in hosts {
        push_name(&mut names, &host);
    }
    names.truncate(MAX_HINT_NAMES);
    names
}

/// `name` lower case at the end of `names`, unless it is an IP literal, empty or there already.
fn push_name(names: &mut Vec<String>, name: &str) {
    let name = name.trim().to_ascii_lowercase();
    let literal = name.trim_matches(['[', ']']).parse::<IpAddr>().is_ok();
    if !literal && !name.is_empty() && !names.contains(&name) {
        names.push(name);
    }
}

/// The selected row's graph names ([`graph_hosts`]; its own name when its key cannot be read).
fn row_hosts(row: &ServerRow) -> Vec<String> {
    let hosts = row.run_profile().map(|p| graph_hosts(&p, row.device));
    match hosts {
        Ok(hosts) if !hosts.is_empty() => hosts,
        _ => {
            let mut own = Vec::new();
            push_name(&mut own, &row.server);
            own
        }
    }
}

/// The names to resolve ahead: the selected row's graph names `own` (`true`), then those of its
/// group's likely picks ([`likely_picks`]) up to [`LIKELY`] more; host names only, lower case,
/// each once.
fn likely_names(own: &[String], selected: &ServerRow, rows: &[ServerRow]) -> Vec<(String, bool)> {
    let mut names: Vec<String> = Vec::new();
    for name in own {
        push_name(&mut names, name);
    }
    let selected_names = names.len();
    for row in likely_picks(rows, selected) {
        if names.len() - selected_names == LIKELY {
            break;
        }
        push_name(&mut names, &row.server);
    }
    let marked = names.into_iter().enumerate();
    marked.map(|(i, name)| (name, i < selected_names)).collect()
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
        let names = likely_names(&row_hosts(&selected), &selected, &rows);
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

    /// Lab L12-5: a provider graph's every member name is resolved ahead with the selected
    /// server's own and hinted at its start: lower case, each once, IP literals left out.
    #[test]
    fn every_name_of_the_selected_graph_is_resolved_ahead() {
        let member = |tag: &str, host: &str| {
            serde_json::json!({ "tag": tag, "protocol": "vless",
                "settings": { "vnext": [{ "address": host, "port": 443,
                    "users": [{ "id": "00000000-0000-4000-8000-000000000003" }] }] },
                "streamSettings": { "network": "tcp", "security": "tls",
                    "tlsSettings": { "serverName": "front.example" } } })
        };
        let doc = serde_json::json!({ "remarks": "Fake graph",
            "outbounds": [member("proxy-1", "A.example"), member("proxy-2", "b.example"),
                          member("proxy-3", "a.example"), member("proxy-4", "203.0.113.5")],
            "routing": { "balancers": [{ "tag": "l1", "selector": ["proxy-"],
                                         "strategy": { "type": "random" } }],
                         "rules": [{ "type": "field", "network": "tcp,udp", "balancerTag": "l1" }] } });
        let found = vpnte_profiles::json::parse_json(&doc);
        let profile = found.profiles.into_iter().next().expect("a provider graph");
        assert!(profile.native_xray.is_some());
        let hosts = graph_hosts(&profile, ClientDevice::Pc);
        assert_eq!(hosts, ["a.example", "b.example"]);
        let selected = row("sel", "g", "a.example", Some(100));
        let rows = vec![selected.clone(), row("r", "g", "r.example", Some(90))];
        let names = likely_names(&hosts, &selected, &rows);
        let got: Vec<_> = names.iter().map(|(n, s)| (n.as_str(), *s)).collect();
        assert_eq!(
            got,
            [
                ("a.example", true),
                ("b.example", true),
                ("r.example", false)
            ]
        );
    }

    /// Lab L12-5: a start's hints come from this process's resolver memory too (where a lookup
    /// ahead in flight lands, `resolve::recall`), not only from the answers already held here;
    /// a name nobody resolved costs the start no wait.
    #[tokio::test(start_paused = true)]
    async fn a_start_takes_the_hints_the_resolvers_memory_holds() {
        let ahead = Ahead::default();
        let (held, remembered) = ("held.l12-5.invalid", "remembered.l12-5.invalid");
        ahead.hold(held, vec![IpAddr::from([203, 0, 113, 41])]);
        resolve::remember(remembered, vec![IpAddr::from([203, 0, 113, 42])]);
        let names = [held, remembered, "unknown.l12-5.invalid"].map(String::from);
        let asked = Instant::now();
        let hints = ahead.hints(&names).await;
        assert_eq!(
            asked.elapsed(),
            Duration::ZERO,
            "nothing in flight: no wait"
        );
        let got: Vec<_> = hints
            .iter()
            .map(|h| (h.name.as_str(), h.addrs.len()))
            .collect();
        assert_eq!(got, [(held, 1), (remembered, 1)]);
        ahead.forget(remembered);
        let left = ahead.hints(&names).await;
        assert_eq!(left.len(), 1, "forgotten here and in its memory");
    }
}
