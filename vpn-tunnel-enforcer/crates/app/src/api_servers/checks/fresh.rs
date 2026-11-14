//! Lab live-9 L9-7: the server the tunnel runs over right now was proven by its own traffic (the
//! connect's or the switch's exit proof, the session's watchdog since). Its health is known, so
//! a key check spends no handshake of its server name's budget on it: under the RU freeze
//! discipline that budget is three handshakes a minute, shared with every key of the name.
use std::net::IpAddr;

use vpnte_base::AppResult;
use vpnte_base::types::{Engine, now_ms};
use vpnte_probes::discipline::{Classification, Reaction, Verdict};
use vpnte_probes::key_health::{KeyCheck, KeyHealth, ListGroup, ListOutcome};
use vpnte_tunnel::fsm::{Health, ProxyStatus, TunnelSnapshot, TunnelState};

use super::Key;
use crate::services::TunnelOps;

/// The connected session's server: its row id, the identity of the key it dialled, exit
/// address and engine.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Proven {
    pub id: String,
    pub identity: Option<[u8; 16]>,
    pub exit: Option<IpAddr>,
    pub engine: Option<Engine>,
}

/// The session's server while the tunnel is settled on it ([`settled`]); `None` otherwise (a
/// local proxy has no row).
pub(super) fn connected(tunnel: &dyn TunnelOps) -> Option<Proven> {
    let healthy = settled(&tunnel.snapshot().borrow());
    let session = tunnel.session().borrow().clone().filter(|_| healthy)?;
    Some(Proven {
        id: session.server_id()?.to_owned(),
        identity: tunnel.session_key(),
        exit: tunnel.ip_evidence().borrow().baseline,
        engine: session.engine.map(|run| run.kind),
    })
}

/// Connected with the engine running, no reconnect or operation in flight and nothing
/// degrading it. Review speed2-a2/b6: while the runtime recovers a crash the state stays
/// `Connected` (transition `Reconnecting`, the engine stopped), and that proves nothing.
fn settled(snap: &TunnelSnapshot) -> bool {
    snap.state == TunnelState::Connected
        && snap.transition.is_none()
        && snap.proxy_status == ProxyStatus::Running
        && snap.health != Some(Health::Degraded)
}

/// Takes the proven server's key out of `groups` and answers its check from the session: the
/// row's key must still be the one the session dialled (review speed2-a4: a subscription
/// refresh re-keys a row in place and nothing reconnects).
pub(super) fn credit(
    mut groups: Vec<ListGroup<Key>>,
    proven: Option<&Proven>,
) -> (Vec<ListGroup<Key>>, Vec<(Key, KeyCheck)>) {
    let Some(proven) = proven else {
        return (groups, Vec::new());
    };
    let mut credited = Vec::new();
    for (_, items) in &mut groups {
        let (ours, rest): (Vec<_>, Vec<_>) =
            std::mem::take(items)
                .into_iter()
                .partition(|((id, identity), p)| {
                    let same_key = proven.identity.is_some() && *identity == proven.identity;
                    p.is_some() && same_key && id.to_string() == proven.id
                });
        *items = rest;
        credited.extend(ours.into_iter().map(|(key, _)| (key, check_of(proven))));
    }
    (groups, credited)
}

/// A check's answer: the credited rows and the probed ones, or the reason when no probe could
/// run at all. Review speed2-a5: a credit is no probe, so it never hides that reason
/// (psmall-a4); a check with only the session's row left to probe answers it.
pub(super) fn answer(
    credited: Vec<(Key, KeyCheck)>,
    found: ListOutcome<Key>,
) -> AppResult<Vec<(Key, KeyCheck)>> {
    if let Some(err) = found.unchecked.filter(|_| found.done.is_empty()) {
        return Err(err);
    }
    Ok(credited.into_iter().chain(found.done).collect())
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
        keyed(id, "fake-pass")
    }

    /// Row `id` holding the key with password `pass`.
    fn keyed(id: &str, pass: &str) -> (Key, Option<vpnte_profiles::model::Profile>) {
        let link = format!("trojan://{pass}@{id}.example.com:443?sni={id}.example.com#{id}");
        let profile = vpnte_profiles::uri::parse_uri(&link).expect("fake key parses");
        (
            (ProfileId::from(id), Some(profile.identity())),
            Some(profile),
        )
    }

    /// The session dialled row `id`'s key as [`item`] builds it.
    fn proven(id: &str) -> Proven {
        Proven {
            id: id.into(),
            identity: item(id).0.1,
            exit: Some(IpAddr::from([198, 51, 100, 7])),
            engine: Some(Engine::Xray),
        }
    }

    /// Lab live-9 L9-7: the connected server's key leaves the probe list and is answered from
    /// its session (online, its exit, no handshake); the other keys stay; no session, no credit.
    #[test]
    fn the_connected_server_is_answered_by_its_session() {
        let groups = vec![
            (ctx(), vec![item("a"), item("b")]),
            (ctx(), vec![item("c")]),
        ];
        let proven = proven("b");
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

    /// Review speed2-a4: a row re-keyed in place by a subscription refresh (same id, another
    /// key) is probed: the session ran the old key; a session whose key is unknown credits none.
    #[test]
    fn a_re_keyed_row_is_probed_not_credited() {
        let groups = vec![(ctx(), vec![keyed("b", "new-pass")])];
        let (left, credited) = credit(groups.clone(), Some(&proven("b")));
        assert_eq!((left[0].1.len(), credited.len()), (1, 0), "re-keyed");
        let unknown = Proven {
            identity: None,
            ..proven("b")
        };
        let groups = vec![(ctx(), vec![item("b")])];
        let (_, credited) = credit(groups.clone(), Some(&unknown));
        assert!(credited.is_empty(), "unknown key");
        let (_, credited) = credit(groups, Some(&proven("b")));
        assert_eq!(credited.len(), 1, "the same key");
    }

    /// Review speed2-a5: every real probe failed: the reason is the answer, the credited row
    /// does not turn it into a partial report; with a probe through, the credit joins it.
    #[test]
    fn a_credit_never_hides_why_nothing_was_probed() {
        let proven = proven("b");
        let groups = vec![(ctx(), vec![item("a"), item("b")])];
        let (_, credited) = credit(groups, Some(&proven));
        let deferred = vpnte_base::AppError::msg(
            vpnte_base::ErrorKind::Conflict,
            vpnte_base::Msg::new("probes.discipline.deferred"),
        );
        let failed = ListOutcome {
            done: Vec::new(),
            unchecked: Some(deferred),
        };
        let err = answer(credited.clone(), failed).expect_err("the reason");
        assert_eq!(err.user_msg().key, "probes.discipline.deferred");
        let probed = ListOutcome {
            done: vec![(item("a").0, check_of(&proven))],
            unchecked: None,
        };
        let done = answer(credited.clone(), probed).expect("a report");
        assert_eq!(done.len(), 2);
        let none_left = ListOutcome {
            done: Vec::new(),
            unchecked: None,
        };
        assert_eq!(answer(credited, none_left).expect("credit only").len(), 1);
    }

    /// Review speed2-a2/b6: only a settled, carrying session answers for its server; a crash
    /// recovery (still `Connected`, reconnecting, the engine stopped), a degraded or a stopped
    /// engine is probed like any other key.
    #[test]
    fn only_a_settled_session_answers_for_its_server() {
        use vpnte_tunnel::fsm::Transition;
        let up = TunnelSnapshot {
            state: TunnelState::Connected,
            proxy_status: ProxyStatus::Running,
            health: Some(Health::Ok),
            ..TunnelSnapshot::default()
        };
        assert!(settled(&up));
        let recovering = TunnelSnapshot {
            transition: Some(Transition::Reconnecting),
            proxy_status: ProxyStatus::Stopped,
            ..up.clone()
        };
        assert!(!settled(&recovering), "crash recovery");
        let reconnecting = TunnelSnapshot {
            transition: Some(Transition::Reconnecting),
            ..up.clone()
        };
        assert!(!settled(&reconnecting), "a switch in flight");
        let stopped = TunnelSnapshot {
            proxy_status: ProxyStatus::Stopped,
            ..up.clone()
        };
        assert!(!settled(&stopped), "engine down");
        let degraded = TunnelSnapshot {
            health: Some(Health::Degraded),
            ..up.clone()
        };
        assert!(!settled(&degraded));
        assert!(!settled(&TunnelSnapshot::default()));
    }
}
