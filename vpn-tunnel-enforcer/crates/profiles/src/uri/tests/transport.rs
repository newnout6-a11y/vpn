//! Transport vectors of `transportCompatibility.test.ts` (AT-04-001 / AT-04-002 / AT-04-006).
use serde_json::{Value, json};

use super::*;
use crate::model::Transport;

const UUID: &str = "11111111-2222-4333-8444-555555555555";

/// The old test's `uri()` helper: values percent-encoded, vmess as v2rayN base64 JSON.
fn link(protocol: &str, kind: &str, params: &[(&str, &str)]) -> String {
    let get = |key: &str| params.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
    if protocol == "vmess" {
        let mut doc = json!({"add": "192.0.2.1", "port": 443, "id": UUID, "net": kind, "tls": "tls", "sni": "front.example.com"});
        let path = get("path").or(get("serviceName"));
        for (key, value) in [("path", path), ("host", get("host")), ("mode", get("mode"))] {
            if let Some(value) = value {
                doc[key] = json!(value);
            }
        }
        if let Some(extra) = get("extra") {
            doc["extra"] = serde_json::from_str(extra).unwrap();
        }
        return format!("vmess://{}", b64(&doc.to_string()));
    }
    let mut query = format!("security=tls&type={kind}&sni=front.example.com");
    for (key, value) in params {
        query.push_str(&format!("&{key}={}", enc(value)));
    }
    let user = if protocol == "trojan" {
        "SYNTHETIC_PASSWORD"
    } else {
        UUID
    };
    format!("{protocol}://{user}@192.0.2.1:443?{query}#Example")
}

fn extra() -> Value {
    json!({"noSSEHeader": true, "custom": {"escaped": "%2F&=%25", "array": [true, 0, "text"]}})
}

/// AT-04-001: XHTTP path, host, mode and extra survive import exactly (one decode only).
#[test]
fn xhttp_fields_are_exact_for_every_protocol() {
    let extra_text = extra().to_string();
    for protocol in ["vless", "trojan", "vmess"] {
        let params = [
            ("path", "/a%2Fb"),
            ("host", "front.example.com"),
            ("mode", "packet-up"),
            ("extra", extra_text.as_str()),
        ];
        let p = ok(&link(protocol, "xhttp", &params));
        let Value::Object(map) = extra() else {
            unreachable!()
        };
        let expected = Transport::Xhttp {
            host: "front.example.com".into(),
            path: "/a%2Fb".into(),
            mode: Some("packet-up".into()),
            extra: Some(map),
        };
        assert_eq!(p.transport, Some(expected), "{protocol}");
        assert_eq!(
            p.tls.and_then(|t| t.server_name).as_deref(),
            Some("front.example.com")
        );
    }
}

/// AT-04-002: explicit gRPC gun / multi for every protocol.
#[test]
fn grpc_modes() {
    for protocol in ["vless", "trojan", "vmess"] {
        for (mode, multi) in [("gun", false), ("multi", true)] {
            let p = ok(&link(
                protocol,
                "grpc",
                &[("serviceName", "service-name"), ("mode", mode)],
            ));
            let expected = Transport::Grpc {
                service_name: "service-name".into(),
                multi_mode: Some(multi),
            };
            assert_eq!(p.transport, Some(expected), "{protocol} {mode}");
        }
    }
    let plain = ok(&link("vless", "grpc", &[("serviceName", "svc")]));
    assert_eq!(
        plain.transport,
        Some(Transport::Grpc {
            service_name: "svc".into(),
            multi_mode: None
        })
    );
}

/// K14: invalid XHTTP mode / extra is rejected instead of building a lossy connection.
#[test]
fn invalid_xhttp_is_skipped() {
    for params in [
        [("mode", "not-a-mode")],
        [("extra", "null")],
        [("extra", "[]")],
        [("extra", "{broken")],
    ] {
        let reason = err(&link("vless", "xhttp", &params));
        assert!(is_invalid(&reason), "{params:?}: {reason:?}");
    }
}

/// K14: contradictory or malformed gRPC flags are rejected; boolean aliases are kept.
#[test]
fn grpc_contradictions() {
    assert!(is_invalid(&err(&link(
        "vless",
        "grpc",
        &[("mode", "gun"), ("multiMode", "true")]
    ))));
    assert!(is_invalid(&err(&link(
        "vless",
        "grpc",
        &[("multiMode", "maybe")]
    ))));
    assert!(is_invalid(&err(&link(
        "vless",
        "grpc",
        &[("mode", "weird")]
    ))));
    let p = ok(&link("vless", "grpc", &[("multiMode", "false")]));
    assert!(matches!(
        p.transport,
        Some(Transport::Grpc {
            multi_mode: Some(false),
            ..
        })
    ));
    let agree = ok(&link(
        "vless",
        "grpc",
        &[("mode", "multi"), ("multiMode", "1")],
    ));
    assert!(matches!(
        agree.transport,
        Some(Transport::Grpc {
            multi_mode: Some(true),
            ..
        })
    ));
}

#[test]
fn ws_httpupgrade_and_h2() {
    let ws = ok(&format!(
        "vless://{UUID}@h.example:443?type=ws&path=ws&host=cdn.example&ed=2048&eh=Sec-WebSocket-Protocol"
    ));
    let expected = Transport::Ws {
        path: "/ws".into(),
        host: Some("cdn.example".into()),
        max_early_data: Some(2048),
        early_data_header: Some("Sec-WebSocket-Protocol".into()),
    };
    assert_eq!(ws.transport, Some(expected));
    let up = ok(&format!(
        "vless://{UUID}@h.example:443?type=http-upgrade&host=cdn.example"
    ));
    assert_eq!(
        up.transport,
        Some(Transport::HttpUpgrade {
            host: "cdn.example".into(),
            path: "/".into()
        })
    );
    let h2 = ok(&format!(
        "vless://{UUID}@h.example:443?type=h2&path=%2Fh&host=a.example"
    ));
    assert_eq!(
        h2.transport,
        Some(Transport::Http {
            hosts: vec!["a.example".into()],
            path: "/h".into()
        })
    );
}
