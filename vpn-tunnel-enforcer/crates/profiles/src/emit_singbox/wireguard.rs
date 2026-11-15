//! WireGuard profile -> sing-box 1.14 `endpoints[]` entry (there is no wireguard outbound
//! since 1.13).
use serde_json::{Map, Value, json};

use super::outbound::domain_resolver;
use super::{EmitError, EmitPolicy, WgProblem, extra};
use crate::common::wg::unrouted_peer;
use crate::model::{Host, Profile, WireGuard};

pub(super) fn endpoint(
    p: &Profile,
    wg: &WireGuard,
    tag: &str,
    policy: &EmitPolicy,
) -> Result<Value, EmitError> {
    let fail = |problem| Err(EmitError::WireGuard(problem));
    if wg.local_address.is_empty() {
        return fail(WgProblem::NoAddress);
    }
    if wg.private_key.trim().is_empty() {
        return fail(WgProblem::NoPrivateKey);
    }
    if wg.peers.is_empty() {
        return fail(WgProblem::NoPeer);
    }
    if unrouted_peer(&wg.peers) {
        return fail(WgProblem::AllowedIpsRequired);
    }
    let mut peers = Vec::with_capacity(wg.peers.len());
    for peer in &wg.peers {
        let address = peer.host.to_string();
        if address.trim().is_empty() {
            return fail(WgProblem::NoPeerAddress);
        }
        if peer.port == 0 {
            return fail(WgProblem::BadPeerPort);
        }
        if peer.public_key.trim().is_empty() {
            return fail(WgProblem::NoPublicKey);
        }
        // Share links name no routes: a lone peer carries everything.
        let allowed_ips: Vec<String> = if peer.allowed_ips.is_empty() {
            vec!["0.0.0.0/0".into(), "::/0".into()]
        } else {
            peer.allowed_ips.iter().map(ToString::to_string).collect()
        };
        let mut o = Map::new();
        o.insert("address".into(), Value::String(address));
        o.insert("port".into(), json!(peer.port));
        o.insert(
            "public_key".into(),
            Value::String(peer.public_key.trim().to_owned()),
        );
        if let Some(psk) = peer
            .pre_shared_key
            .as_deref()
            .map(str::trim)
            .filter(|k| !k.is_empty())
        {
            o.insert("pre_shared_key".into(), Value::String(psk.to_owned()));
        }
        o.insert("allowed_ips".into(), json!(allowed_ips));
        if let Some(keepalive) = peer.keepalive_s.filter(|&k| k > 0) {
            o.insert("persistent_keepalive_interval".into(), json!(keepalive));
        }
        if let Some(reserved) = peer.reserved {
            o.insert("reserved".into(), json!(reserved));
        }
        peers.push(Value::Object(o));
    }

    let mut o = Map::new();
    o.insert("type".into(), Value::String("wireguard".into()));
    o.insert("tag".into(), Value::String(tag.to_owned()));
    let address: Vec<String> = wg.local_address.iter().map(ToString::to_string).collect();
    o.insert("address".into(), json!(address));
    o.insert(
        "private_key".into(),
        Value::String(wg.private_key.trim().to_owned()),
    );
    if let Some(mtu) = wg.mtu.filter(|&m| m > 0) {
        o.insert("mtu".into(), json!(mtu));
    }
    if wg
        .peers
        .iter()
        .any(|peer| matches!(peer.host, Host::Domain(_)))
        && let Some(resolver) = domain_resolver(&p.dial, policy)
    {
        o.insert("domain_resolver".into(), resolver);
    }
    o.insert("peers".into(), Value::Array(peers));
    // The app owns the only system interface (the TUN): a profile must not make the privileged
    // core create another interface or open a listening port.
    extra::merge(&mut o, &p.singbox_extra, |path| {
        !matches!(path.first(), Some(&("system" | "name" | "listen_port")))
    });
    Ok(Value::Object(o))
}
