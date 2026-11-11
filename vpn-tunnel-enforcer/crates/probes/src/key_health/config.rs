//! sing-box config of a key probe (old `buildKeyProbeConfig`, keyHealthChecker.ts:452-505): the
//! profile as `proxy-out`, an authenticated loopback mixed inbound `probe-in`, and how the probe
//! leaves this PC: through our tunnel's `mixed-direct-in` while the TUN runs (a detour avoids a
//! self-loop through proxy-out and keeps the kill switch intact), else bound to the physical
//! adapter (`auto_detect_interface` alone could pick another VPN's TUN).
use serde_json::{Value, json};
use vpnte_base::types::{ClientDevice, Loopback};
use vpnte_profiles::emit_singbox::{EmitError, EmitPolicy, emit_singbox};
use vpnte_profiles::model::Profile;

/// Tag of the profile outbound.
pub const PROXY_TAG: &str = "proxy-out";
/// Tag of the probe's way out of this PC.
pub const DIRECT_TAG: &str = "probe-direct-out";
/// Tag of the probe's local inbound.
pub const INBOUND_TAG: &str = "probe-in";
/// Direct resolver of hostname servers.
const DNS_TAG: &str = "dns-bootstrap";

/// How the probe engine reaches the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeRoute {
    /// Our TUN runs: dial through its authenticated `mixed-direct-in` (routed `direct-out`).
    Detour(Loopback),
    /// No TUN of ours: bind to this physical adapter alias (`None`: none found).
    Bind(Option<String>),
}

/// The probe config for `p` listening on `listen` (port + credentials of `probe-in`). `Err` when
/// sing-box cannot express the profile (the caller reports a configuration verdict).
pub fn probe_config(
    p: &Profile,
    listen: &Loopback,
    device: ClientDevice,
    route: &ProbeRoute,
) -> Result<Value, EmitError> {
    let policy = EmitPolicy {
        device: Some(device),
        domain_resolver: Some(DNS_TAG.to_owned()),
        ..EmitPolicy::default()
    };
    let fragment = emit_singbox(p, PROXY_TAG, &policy)?;
    let place = |mut entry: Value| {
        // Only entries that dial the server themselves; a chain's inner hop already detours.
        if entry.get("detour").is_none() {
            match route {
                ProbeRoute::Detour(_) => entry["detour"] = json!(DIRECT_TAG),
                ProbeRoute::Bind(Some(alias)) => entry["bind_interface"] = json!(alias),
                ProbeRoute::Bind(None) => {}
            }
        }
        entry
    };
    let mut outbounds: Vec<Value> = fragment.outbounds().iter().cloned().map(place).collect();
    let endpoints: Vec<Value> = fragment.endpoints().iter().cloned().map(place).collect();
    outbounds.push(match route {
        ProbeRoute::Detour(direct) => {
            let mut socks = json!({
                "type": "socks",
                "tag": DIRECT_TAG,
                "server": "127.0.0.1",
                "server_port": direct.port,
                "version": "5",
            });
            if let Some(creds) = &direct.creds {
                socks["username"] = json!(creds.user);
                socks["password"] = json!(creds.pass);
            }
            socks
        }
        ProbeRoute::Bind(_) => json!({ "type": "direct", "tag": DIRECT_TAG }),
    });
    let mut inbound = json!({
        "type": "mixed",
        "tag": INBOUND_TAG,
        "listen": "127.0.0.1",
        "listen_port": listen.port,
    });
    if let Some(creds) = &listen.creds {
        inbound["users"] = json!([{ "username": creds.user, "password": creds.pass }]);
    }
    let mut config = json!({
        "log": { "level": "debug", "timestamp": true },
        "inbounds": [inbound],
        "outbounds": outbounds,
        "route": { "final": PROXY_TAG, "auto_detect_interface": true },
    });
    if !endpoints.is_empty() {
        config["endpoints"] = Value::Array(endpoints);
    }
    if fragment.needs_bootstrap_dns() {
        config["dns"] = json!({
            "servers": [{ "type": "local", "tag": DNS_TAG }],
            "strategy": "ipv4_only",
        });
        config["route"]["default_domain_resolver"] = json!(DNS_TAG);
    }
    Ok(config)
}
