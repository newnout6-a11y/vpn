//! Lab live-9 L9-7: the server the tunnel runs over right now was proven by its own traffic (the
//! connect's or the switch's exit proof, the session's watchdog since). Its health is known, so
//! a key check spends no handshake of its server name's budget on it: under the RU freeze
//! discipline that budget is three handshakes a minute, shared with every key of the name.
use std::net::IpAddr;

use vpnte_base::types::{Engine, now_ms};
use vpnte_probes::discipline::{Classification, Reaction, Verdict};
use vpnte_probes::key_health::{KeyCheck, KeyHealth, ListGroup};
use vpnte_tunnel::fsm::{Health, TunnelState};

use super::Key;
use crate::services::TunnelOps;

/// The connected session's server: its row id, exit address and engine.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Proven {
    pub id: String,
    pub exit: Option<IpAddr>,
    pub engine: Option<Engine>,
}

/// The session's server while the tunnel is connected and nothing degrades it; `None` otherwise
/// (a local proxy has no row).
pub(super) fn connected(tunnel: &dyn TunnelOps) -> Option<Proven> {
    let snap = tunnel.snapshot().borrow().clone();
    let healthy = snap.state == TunnelState::Connected && snap.health != Some(Health::Degraded);
    let session = tunnel.session().borrow().clone().filter(|_| healthy)?;
    Some(Proven {
        id: session.server_id()?.to_owned(),
        exit: tunnel.ip_evidence().borrow().baseline,
        engine: session.engine.map(|run| run.kind),
    })
}

/// Takes the proven server's key out of `groups` and answers its check from the session.
pub(super) fn credit(
    mut groups: Vec<ListGroup<Key>>,
    proven: Option<&Proven>,
) -> (Vec<ListGroup<Key>>, Vec<(Key, KeyCheck)>) {
    let Some(proven) = proven else {
        return (groups, Vec::new());
    };
    let mut credited = Vec::new();
    for (_, items) in &mut groups {
        let (ours, rest): (Vec<_>, Vec<_>) = std::mem::take(items)
            .into_iter()
            .partition(|((id, _), p)| p.is_some() && id.to_string() == proven.id);
        *items = rest;
        credited.extend(ours.into_iter().map(|(key, _)| (key, check_of(proven))));
    }
    (groups, credited)
}

/// Online now, through the session's own exit; no latency was measured.
fn check_of(proven: &Proven) -> KeyCheck {
    KeyCheck {
        health: KeyHealth {
            online: true,
            at: now_ms(),
            rtt_ms: None,
            reason: None,
            egress_ip: proven.exit,
            country: None,
            engine: proven.engine,
        },
        verdict: Classification {
            verdict: Verdict::Healthy,
            reaction: Reaction::None,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use vpnte_base::types::{ClientDevice, EnginePref};
    use vpnte_probes::key_health::ProbeCtx;
    use vpnte_servers::model::ProfileId;

    use super::*;

    fn ctx() -> ProbeCtx {
        ProbeCtx {
            singbox_exe: PathBuf::new(),
            xray_exe: PathBuf::new(),
            engine_pref: EnginePref::Auto,
            device: ClientDevice::default(),
            net: Default::default(),
            dns_bootstrap_in: None,
        }
    }

    fn item(id: &str) -> (Key, Option<vpnte_profiles::model::Profile>) {
        let link = format!("trojan://fake-pass@{id}.example.com:443?sni={id}.example.com#{id}");
        let profile = vpnte_profiles::uri::parse_uri(&link).expect("fake key parses");
        ((ProfileId::from(id), None), Some(profile))
    }

    /// Lab live-9 L9-7: the connected server's key leaves the probe list and is answered from
    /// its session (online, its exit, no handshake); the other keys stay; no session, no credit.
    #[test]
    fn the_connected_server_is_answered_by_its_session() {
        let groups = vec![
            (ctx(), vec![item("a"), item("b")]),
            (ctx(), vec![item("c")]),
        ];
        let proven = Proven {
            id: "b".into(),
            exit: Some(IpAddr::from([198, 51, 100, 7])),
            engine: Some(Engine::Xray),
        };
        let (left, credited) = credit(groups.clone(), Some(&proven));
        let ids = |g: &[ListGroup<Key>]| -> Vec<String> {
            g.iter()
                .flat_map(|(_, i)| i.iter().map(|((id, _), _)| id.to_string()))
                .collect()
        };
        assert_eq!(ids(&left), ["a", "c"]);
        let [((id, _), check)] = credited.as_slice() else {
            panic!("one credited key: {credited:?}");
        };
        assert_eq!(id.to_string(), "b");
        assert!(check.health.online && check.health.rtt_ms.is_none());
        assert_eq!(check.health.egress_ip, proven.exit);
        assert_eq!(check.verdict.verdict, Verdict::Healthy);
        let (all, none) = credit(groups, None);
        assert_eq!((ids(&all).len(), none.len()), (3, 0));
    }
}
