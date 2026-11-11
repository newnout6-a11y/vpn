//! Runtime config of one Xray instance: the authenticated loopback SOCKS inbound `in`, the
//! proxy (translated outbound or compiled provider graph), `direct` and `block`.
use std::fmt;

use serde_json::{Value, json};
use vpnte_base::types::ClientDevice;
use vpnte_profiles::model::Profile;
use vpnte_profiles::xray_native::{self, CompiledGraph};

use super::translate::translate;
use super::{BLOCK_TAG, DIRECT_TAG, INBOUND_TAG, PROXY_TAG, XrayConfigError};
use crate::slot::SlotEndpoint;

/// Private, loopback, link-local and CGNAT destinations go `direct`. Explicit CIDRs because
/// `geoip:private` needs geoip.dat, which is not shipped.
const PRIVATE_CIDRS: [&str; 6] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10",
];

/// What the instance's `proxy` route leads to.
#[derive(Clone, PartialEq)]
pub enum ProxyGraph {
    /// One translated outbound tagged `proxy` ([`translate`]).
    Translated(Value),
    /// A provider graph compiled with namespaced tags; its selected outbound is `proxy`.
    Native(Box<CompiledGraph>),
}

/// Outbounds carry credentials: `{:?}` shows only the shape.
impl fmt::Debug for ProxyGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyGraph::Translated(outbound) => {
                let protocol = outbound.get("protocol").and_then(Value::as_str);
                f.debug_tuple("Translated").field(&protocol).finish()
            }
            ProxyGraph::Native(graph) => f.debug_tuple("Native").field(graph).finish(),
        }
    }
}

/// The proxy side of an Xray config for `p`: its provider graph (validated and compiled), else
/// the translated typed profile. Addresses are still the stored host names.
pub fn proxy_graph(p: &Profile, device: ClientDevice) -> Result<ProxyGraph, XrayConfigError> {
    let Some(graph) = &p.native_xray else {
        return translate(p, device).map(ProxyGraph::Translated);
    };
    xray_native::validate(graph)?;
    let primary = xray_native::selected_outbound(graph)?;
    Ok(ProxyGraph::Native(Box::new(xray_native::compile(
        graph, primary,
    )?)))
}

/// The complete Xray config for one instance listening on `ep` (valid by construction, so this
/// cannot fail).
///
/// Log: `info` (Xray reports dial and handshake failures only at Info), error log to stdout
/// (`""`), access log off. Never `dns`, `api`, `stats`, provider inbounds or provider log.
pub fn build_config(graph: &ProxyGraph, ep: &SlotEndpoint) -> Value {
    let creds = ep.creds();
    let inbound = json!({
        "tag": INBOUND_TAG,
        "listen": "127.0.0.1",
        "port": ep.port(),
        "protocol": "socks",
        "settings": {
            "udp": true,
            "auth": "password",
            "accounts": [{"user": creds.user, "pass": creds.pass}],
        },
        // Proxied browsers may carry another SNI / Host than the requested endpoint: route on
        // the sniffed name without replacing the destination.
        "sniffing": {"enabled": true, "destOverride": ["tls", "http", "quic"], "routeOnly": true},
    });
    let private = json!({"type": "field", "ip": PRIVATE_CIDRS, "outboundTag": DIRECT_TAG});
    let mut config = json!({
        "log": {"loglevel": "info", "access": "none", "error": ""},
        "inbounds": [inbound],
    });
    let (mut outbounds, routing) = match graph {
        ProxyGraph::Translated(proxy) => {
            let all = json!({"type": "field", "network": "tcp,udp", "outboundTag": PROXY_TAG});
            (vec![proxy.clone()], json!({"rules": [private, all]}))
        }
        ProxyGraph::Native(g) => {
            let mut first = private;
            first["inboundTag"] = json!([INBOUND_TAG]);
            let mut entry =
                json!({"type": "field", "inboundTag": [INBOUND_TAG], "network": "tcp,udp"});
            if let (Some(rule), Some(target)) = (entry.as_object_mut(), g.entry.as_object()) {
                rule.extend(target.clone());
            }
            let mut rules = vec![first];
            rules.extend(g.rules.iter().cloned());
            rules.push(entry);
            // Whatever a provider graph injects under another inbound tag (e.g. a VLESS reverse
            // tunnel) is blackholed; provider loopbacks never fall into `direct`.
            rules.push(json!({"type": "field", "network": "tcp,udp", "outboundTag": BLOCK_TAG}));
            let mut routing = json!({ "rules": rules });
            if !g.balancers.is_empty() {
                routing["balancers"] = Value::Array(g.balancers.clone());
            }
            for (key, value) in [
                ("observatory", &g.observatory),
                ("burstObservatory", &g.burst_observatory),
                ("policy", &g.policy),
            ] {
                if let Some(value) = value {
                    config[key] = value.clone();
                }
            }
            (g.outbounds.clone(), routing)
        }
    };
    outbounds.push(json!({"tag": DIRECT_TAG, "protocol": "freedom"}));
    outbounds.push(json!({"tag": BLOCK_TAG, "protocol": "blackhole"}));
    config["outbounds"] = Value::Array(outbounds);
    config["routing"] = routing;
    config
}
