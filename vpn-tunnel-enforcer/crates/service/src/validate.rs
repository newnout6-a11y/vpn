//! Request validation: what a SYSTEM engine must never get from an untrusted client.
//!
//! The protocol's types already exclude file paths, command lines and engine JSON; this module
//! bounds every free-form part that remains: provider sing-box keys (`Profile::singbox_extra`)
//! pass only the union of the importers' allow-lists, provider JSON (sing-box values, an XHTTP
//! `extra`, a native Xray graph) may only use keys a Go decoder reads as we do, a provider Xray
//! graph re-runs its full import checks, a local upstream proxy must be on loopback, text and list
//! sizes are capped, and kill-switch exceptions are re-validated as the UI validates them (an app
//! exception is a local `.exe` that becomes a WFP app id: opened for reading, never run).
use std::collections::BTreeSet;

use serde_json::{Map, Value};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};
use vpnte_profiles::model::{NativeXray, Profile, Transport};
use vpnte_profiles::xray_native;
use vpnte_winnet::wfp::{self, KillSwitchException, ProtectionSettings};

use crate::proto::{RoutingInputs, ServerUpstream, TunnelStart, Upstream};

/// Most split-tunnel entries per list.
pub const MAX_SPLIT: usize = 1024;
/// Most domain rules.
pub const MAX_DOMAIN_RULES: usize = 20_000;
/// Longest split-tunnel regex, reason, id or name.
pub const MAX_TEXT: usize = 4096;
/// Most provider sing-box keys on one profile.
pub const MAX_EXTRA: usize = 64;

/// Provider sing-box keys the importers keep (`vpnte_profiles` json / Clash importers): the only
/// ones a profile may carry into the service. The emitter additionally drops `*_path`, bind and
/// tag keys at any depth.
const EXTRA_ALLOWED: &[&str] = &[
    "network",
    "packet_encoding",
    "brutal_debug",
    "disable_chrome_parrot",
    "initial_packet_size",
    "disable_path_mtu_discovery",
    "idle_timeout",
    "keep_alive_period",
    "stream_receive_window",
    "connection_receive_window",
    "max_concurrent_streams",
    "udp_over_stream",
    "udp_over_tcp",
    "quic_congestion_control",
    "quic_session_receive_window",
    "client_metadata",
    "path",
    "headers",
    "disable_tcp_keep_alive",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
    "udp_timeout",
    "workers",
    "udp_mapping",
    "udp_filtering",
    "udp_nat_max",
    "tls.cipher_suites",
    "tls.curve_preferences",
    "tls.client_certificate",
    "tls.client_key",
    "tls.fragment",
    "tls.fragment_fallback_delay",
    "tls.record_fragment",
    "tls.spoof",
    "tls.spoof_method",
    "tls.handshake_timeout",
    "tls.ech.pq_signature_schemes_enabled",
    "transport.idle_timeout",
    "transport.ping_timeout",
    "transport.permit_without_stream",
    "transport.method",
    "transport.headers",
    "multiplex.min_streams",
    "multiplex.max_streams",
    "obfs.min_packet_size",
    "obfs.max_packet_size",
];

fn refused(key: &'static str, field: &'static str) -> AppError {
    AppError::msg(ErrorKind::Validation, Msg::new(key).arg("field", field))
}

/// `text` is at most [`MAX_TEXT`] bytes without control characters.
pub fn text(value: &str, field: &'static str) -> AppResult<()> {
    if value.len() > MAX_TEXT {
        return Err(refused("service.refused.tooLong", field));
    }
    if value.chars().any(char::is_control) {
        return Err(refused("service.refused.text", field));
    }
    Ok(())
}

/// A start, restart or switch request (its kill-switch settings go through [`protection`]).
pub fn start(req: &TunnelStart) -> AppResult<()> {
    match &req.upstream {
        Upstream::LocalProxy { addr, .. } => {
            if !addr.ip().is_loopback() || addr.port() == 0 {
                return Err(AppError::msg(
                    ErrorKind::Validation,
                    Msg::new("service.refused.localProxy"),
                ));
            }
        }
        Upstream::Server(server) => self::server(server)?,
    }
    routing(&req.routing)
}

/// A server profile.
pub fn server(server: &ServerUpstream) -> AppResult<()> {
    text(&server.id, "id")?;
    profile(&server.profile)
}

fn profile(p: &Profile) -> AppResult<()> {
    text(&p.name, "name")?;
    if let Some(d) = &p.description {
        text(d, "description")?;
    }
    if p.singbox_extra.len() > MAX_EXTRA {
        return Err(refused("service.refused.tooMany", "singbox_extra"));
    }
    if let Some(key) = p
        .singbox_extra
        .keys()
        .find(|k| !EXTRA_ALLOWED.contains(&k.as_str()))
    {
        tracing::warn!(key = %key.chars().take(64).collect::<String>(), "refused a provider sing-box key");
        return Err(refused("service.refused.text", "singbox_extra"));
    }
    for value in p.singbox_extra.values() {
        provider_json(value, "singbox_extra")?;
    }
    if let Some(Transport::Xhttp {
        extra: Some(extra), ..
    }) = &p.transport
    {
        provider_object(extra, "extra")?;
    }
    if let Some(graph) = &p.native_xray {
        native_graph(graph)?;
    }
    Ok(())
}

/// A provider Xray graph: its JSON as [`provider_json`] requires, then the full import checks
/// (reach, local files, insecure TLS, application bypass) that the engine runs again at start.
fn native_graph(graph: &NativeXray) -> AppResult<()> {
    xray_native::validate(graph)?;
    let routing = graph
        .routing
        .iter()
        .flat_map(|r| r.rules.iter().chain(&r.balancers));
    let extras = [&graph.observatory, &graph.burst_observatory, &graph.policy];
    graph
        .outbounds
        .iter()
        .chain(routing)
        .chain(extras.into_iter().flatten())
        .try_for_each(|value| provider_json(value, "native_xray"))?;
    xray_native::compile(graph, xray_native::selected_outbound(graph)?)?;
    Ok(())
}

/// Provider JSON reaches Go engines, whose decoder matches keys without regard to case, with
/// Unicode folding (`ſ` is `s`, the Kelvin sign is `k`), and lets the last of two such keys win,
/// while our checks compare ASCII. So every object, at any depth, may only have keys of printable
/// ASCII, no two of them equal ignoring ASCII case (review service-b1).
fn provider_json(value: &Value, field: &'static str) -> AppResult<()> {
    match value {
        Value::Object(map) => provider_object(map, field),
        Value::Array(items) => items.iter().try_for_each(|v| provider_json(v, field)),
        _ => Ok(()),
    }
}

fn provider_object(map: &Map<String, Value>, field: &'static str) -> AppResult<()> {
    let mut seen = BTreeSet::new();
    for (key, child) in map {
        let printable = key.bytes().all(|b| b == b' ' || b.is_ascii_graphic());
        if !printable || !seen.insert(key.to_ascii_lowercase()) {
            tracing::warn!(key = ?key.chars().take(64).collect::<String>(), "refused a provider JSON key");
            return Err(refused("service.refused.text", field));
        }
        provider_json(child, field)?;
    }
    Ok(())
}

/// The routing inputs.
pub fn routing(r: &RoutingInputs) -> AppResult<()> {
    for (list, field) in [
        (&r.split_direct, "split_direct"),
        (&r.split_vpn, "split_vpn"),
    ] {
        if list.len() > MAX_SPLIT {
            return Err(refused("service.refused.tooMany", field));
        }
        for entry in list {
            text(entry, field)?;
        }
    }
    if r.domain_rules.len() > MAX_DOMAIN_RULES {
        return Err(refused("service.refused.tooMany", "domain_rules"));
    }
    Ok(())
}

/// Kill-switch settings: every exception re-validated (canonical `.exe` path, IP / CIDR, label)
/// and the list checked for duplicates and its limit.
pub fn protection(settings: &ProtectionSettings) -> AppResult<ProtectionSettings> {
    let mut checked = settings.clone();
    checked.exceptions = exceptions_checked(&settings.exceptions)?;
    Ok(checked)
}

fn exceptions_checked(list: &[KillSwitchException]) -> AppResult<Vec<KillSwitchException>> {
    if list.len() > wfp::MAX_EXCEPTIONS {
        return Err(wfp::ValidationError::TooMany.into());
    }
    let mut out = Vec::with_capacity(list.len());
    for e in list {
        text(&e.id, "id")?;
        let (target, label) =
            wfp::validate_exception(e.target.kind(), &e.target.value(), &e.label)?;
        out.push(KillSwitchException {
            id: e.id.clone(),
            target,
            label,
        });
    }
    wfp::check_list(&out)?;
    Ok(out)
}

#[cfg(test)]
mod tests;
