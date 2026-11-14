//! Test helpers of the process package: harmless loopback-only engine configs (the engines,
//! temp dirs and checks are in `crate::test_support`).
use serde_json::json;
use vpnte_base::types::Creds;

use crate::clash_api::ClashEndpoint;

/// sing-box: an authenticated mixed inbound on `127.0.0.1:mixed` routed to a direct outbound,
/// plus (with `clash`) the Clash API and a `proxy-out` selector over two direct outbounds named
/// like the Xray slots. Nothing leaves the machine unless a test sends traffic through it.
pub(crate) fn singbox_config(mixed: u16, creds: &Creds, clash: Option<&ClashEndpoint>) -> Vec<u8> {
    let mut config = json!({
        "log": { "level": "info", "timestamp": true },
        "inbounds": [{
            "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": mixed,
            "users": [{ "username": creds.user, "password": creds.pass }]
        }],
        "outbounds": [
            { "type": "direct", "tag": "direct-out" },
            { "type": "direct", "tag": "vpnte-upstream-a" },
            { "type": "direct", "tag": "vpnte-upstream-b" },
            {
                "type": "selector", "tag": "proxy-out",
                "outbounds": ["vpnte-upstream-a", "vpnte-upstream-b"],
                "default": "vpnte-upstream-a", "interrupt_exist_connections": true
            }
        ],
        "route": { "final": "direct-out" }
    });
    if let Some(ep) = clash {
        config["experimental"] = json!({ "clash_api": {
            "external_controller": format!("127.0.0.1:{}", ep.port),
            "secret": ep.secret,
            "default_mode": "rule"
        }});
    }
    serde_json::to_vec(&config).unwrap()
}

/// Xray: an authenticated SOCKS inbound on `127.0.0.1:port` routed to `freedom`.
pub(crate) fn xray_config(port: u16, creds: &Creds) -> Vec<u8> {
    let config = json!({
        "log": { "loglevel": "info" },
        "inbounds": [{
            "tag": "in", "listen": "127.0.0.1", "port": port, "protocol": "socks",
            "settings": {
                "auth": "password",
                "accounts": [{ "user": creds.user, "pass": creds.pass }],
                "udp": false
            }
        }],
        "outbounds": [{ "protocol": "freedom", "tag": "direct" }]
    });
    serde_json::to_vec(&config).unwrap()
}
