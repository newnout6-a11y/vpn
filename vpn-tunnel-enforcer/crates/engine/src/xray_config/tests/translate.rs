//! Translation vectors (xray-engine spec §7 "Translation"; old xrayEngine.test.ts,
//! transportCompatibility.test.ts) plus the new mapping rules of §2.3.
use serde_json::{Value, json};
use vpnte_base::types::ClientDevice;
use vpnte_profiles::model::{Kind, Profile, Transport};

use super::*;
use crate::xray_config::translate;

fn out(p: &Profile) -> Value {
    translate(p, ClientDevice::Pc).expect("translates")
}

fn user(v: &Value) -> &Value {
    &v["settings"]["vnext"][0]["users"][0]
}

fn ws(path: &str, ed: Option<u32>, header: Option<&str>) -> Option<Transport> {
    Some(Transport::Ws {
        path: path.into(),
        host: None,
        max_early_data: ed,
        early_data_header: header.map(str::to_owned),
    })
}

fn vision() -> Kind {
    Kind::Vless {
        uuid: UUID.into(),
        flow: Some("xtls-rprx-vision".into()),
        packet_encoding: None,
        encryption: None,
    }
}

/// AT-00-004: VLESS + REALITY + Vision. The address stays the stored server (pre-resolution
/// swaps it later); exactly one `vnext` with one user.
#[test]
fn vless_reality_vision() {
    let p = Profile {
        tls: reality("yahoo.com"),
        ..profile(vision())
    };
    let v = out(&p);
    assert_eq!(v["tag"], "proxy");
    assert_eq!(v["protocol"], "vless");
    let vnext = v["settings"]["vnext"].as_array().expect("vnext");
    assert_eq!(vnext.len(), 1);
    assert_eq!(vnext[0]["address"], "nl.example");
    assert_eq!(vnext[0]["port"], 443);
    assert_eq!(vnext[0]["users"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        *user(&v),
        json!({"id": UUID, "encryption": "none", "flow": "xtls-rprx-vision"})
    );
    let s = &v["streamSettings"];
    assert_eq!(s["network"], "tcp");
    assert_eq!(s["security"], "reality");
    assert_eq!(
        s["realitySettings"],
        json!({"serverName": "yahoo.com", "password": PBK, "shortId": SID, "fingerprint": "chrome"})
    );
    let literal = Profile {
        server: ip("185.1.2.3"),
        ..p
    };
    assert_eq!(
        out(&literal)["settings"]["vnext"][0]["address"],
        "185.1.2.3"
    );
}

/// Vision is dropped on ws (Xray refuses it there) but kept with VLESS Encryption.
#[test]
fn flow_only_where_xray_takes_it() {
    let over_ws = Profile {
        tls: tls("front.example"),
        transport: ws("/vless-ws", None, None),
        ..profile(vision())
    };
    let v = out(&over_ws);
    assert_eq!(v["streamSettings"]["network"], "ws");
    assert!(user(&v).get("flow").is_none(), "{v}");
    let enc = "mlkem768x25519plus.native.0rtt.AAAA";
    let encrypted = Profile {
        transport: Some(Transport::Xhttp {
            host: String::new(),
            path: "/x".into(),
            mode: None,
            extra: None,
        }),
        ..profile(Kind::Vless {
            uuid: UUID.into(),
            flow: Some("xtls-rprx-vision".into()),
            packet_encoding: None,
            encryption: Some(enc.into()),
        })
    };
    let v = out(&encrypted);
    assert_eq!(user(&v)["encryption"], enc);
    assert_eq!(user(&v)["flow"], "xtls-rprx-vision");
    assert_eq!(v["streamSettings"]["security"], "none");
}

/// VMess over ws + TLS: Host goes to `wsSettings.host` (from the SNI), never `headers.Host`;
/// no `alterId`.
#[test]
fn vmess_ws_tls() {
    let p = Profile {
        tls: tls("cdn.example"),
        transport: ws("/ws", None, None),
        ..profile(vmess())
    };
    let v = out(&p);
    assert_eq!(*user(&v), json!({"id": UUID, "security": "auto"}));
    let s = &v["streamSettings"];
    assert_eq!(s["security"], "tls");
    assert_eq!(
        s["wsSettings"],
        json!({"path": "/ws", "host": "cdn.example"})
    );
    assert_eq!(
        s["tlsSettings"],
        json!({"serverName": "cdn.example", "fingerprint": "chrome"})
    );
    let mut authenticated = p;
    if let Kind::Vmess {
        authenticated_length,
        ..
    } = &mut authenticated.kind
    {
        *authenticated_length = true;
    }
    assert_eq!(
        user(&out(&authenticated))["experiments"],
        "AuthenticatedLength"
    );
}

/// Trojan + TLS and Shadowsocks: one `servers` entry; never `flow` nor `uot` / `UoTVersion`.
#[test]
fn trojan_and_shadowsocks() {
    let p = Profile {
        tls: tls("front.example"),
        ..profile(trojan())
    };
    let v = out(&p);
    assert_eq!(
        v["settings"],
        json!({"servers": [{"address": "nl.example", "port": 443, "password": PW}]})
    );
    assert_eq!(v["streamSettings"]["security"], "tls");
    let ss = Profile {
        port: 8388,
        ..profile(shadowsocks("AES-256-GCM"))
    };
    let v = out(&ss);
    assert_eq!(
        v["settings"],
        json!({"servers": [{"address": "nl.example", "port": 8388, "method": "aes-256-gcm", "password": PW}]})
    );
    let text = v.to_string();
    assert!(!text.contains("uot") && !text.contains("UoT"), "{text}");
}

/// XHTTP for VLESS / Trojan / VMess: path, host, mode and `extra` verbatim; the input profile is
/// not touched. A Host header inside `extra.headers` moves out (Xray refuses it there).
#[test]
fn xhttp_settings() {
    let extra =
        json!({"noSSEHeader": true, "custom": {"escaped": "%2F&=%25", "array": [true, 0, "text"]}});
    let Value::Object(extra) = extra else {
        unreachable!()
    };
    for kind in [vless(), trojan(), vmess()] {
        let p = Profile {
            tls: tls("front.example.com"),
            transport: Some(Transport::Xhttp {
                host: "front.example.com".into(),
                path: "/a%2Fb".into(),
                mode: Some("packet-up".into()),
                extra: Some(extra.clone()),
            }),
            ..profile(kind)
        };
        let before = p.clone();
        let v = out(&p);
        assert_eq!(p, before);
        assert_eq!(v["streamSettings"]["network"], "xhttp");
        let mut sent = extra.clone();
        sent.insert("xmux".into(), default_xmux());
        assert_eq!(
            v["streamSettings"]["xhttpSettings"],
            json!({"path": "/a%2Fb", "host": "front.example.com", "mode": "packet-up", "extra": sent})
        );
    }
    let with_header = Profile {
        tls: tls("front.example.com"),
        transport: Some(Transport::Xhttp {
            host: String::new(),
            path: "/".into(),
            mode: Some("stream-up".into()),
            extra: Some(
                json!({"headers": {"host": "header.example", "X-Pad": "1"}})
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
            ),
        }),
        ..profile(trojan())
    };
    let x = &out(&with_header)["streamSettings"]["xhttpSettings"];
    assert_eq!(x["host"], "header.example");
    assert_eq!(x["mode"], "stream-up");
    assert_eq!(
        x["extra"],
        json!({"headers": {"X-Pad": "1"}, "xmux": default_xmux()})
    );
}

/// gRPC gun / multi; without TLS the authority is pinned to the host name.
#[test]
fn grpc_settings() {
    for (multi, expected) in [(Some(false), false), (Some(true), true), (None, false)] {
        let p = Profile {
            tls: tls("front.example"),
            transport: Some(Transport::Grpc {
                service_name: "service-name".into(),
                multi_mode: multi,
            }),
            ..profile(vless())
        };
        let s = &out(&p)["streamSettings"];
        assert_eq!(s["network"], "grpc");
        assert_eq!(
            s["grpcSettings"],
            json!({"serviceName": "service-name", "multiMode": expected})
        );
    }
    let plain = Profile {
        transport: Some(Transport::Grpc {
            service_name: "svc".into(),
            multi_mode: Some(true),
        }),
        ..profile(vmess())
    };
    assert_eq!(
        out(&plain)["streamSettings"]["grpcSettings"]["authority"],
        "nl.example"
    );
}

/// B3: sing-box early data becomes `?ed=N` in the ws path (max 8192); an existing `ed` wins; a
/// custom header name cannot be expressed in Xray.
#[test]
fn websocket_early_data() {
    let path = |t: Option<Transport>| {
        let p = Profile {
            tls: tls("front.example"),
            transport: t,
            ..profile(vless())
        };
        out(&p)["streamSettings"]["wsSettings"]["path"]
            .as_str()
            .map(str::to_owned)
    };
    assert_eq!(
        path(ws("/ws", Some(2048), None)).as_deref(),
        Some("/ws?ed=2048")
    );
    assert_eq!(
        path(ws("/p?x=1", Some(2560), Some("Sec-WebSocket-Protocol"))).as_deref(),
        Some("/p?x=1&ed=2560")
    );
    assert_eq!(
        path(ws("/ws?ed=1024", Some(2048), None)).as_deref(),
        Some("/ws?ed=1024")
    );
    assert_eq!(
        path(ws("/ws", Some(20000), None)).as_deref(),
        Some("/ws?ed=8192")
    );
    assert_eq!(
        path(ws("/ws", Some(2048), Some("X-Early"))).as_deref(),
        Some("/ws")
    );
    assert_eq!(path(ws("", None, None)).as_deref(), Some("/"));
}

/// HTTPUpgrade host and the RAW HTTP header mask (B32).
#[test]
fn httpupgrade_and_tcp_http_header() {
    let upgrade = Profile {
        tls: tls("front.example"),
        transport: Some(Transport::HttpUpgrade {
            host: String::new(),
            path: "/up".into(),
        }),
        ..profile(trojan())
    };
    assert_eq!(
        out(&upgrade)["streamSettings"]["httpupgradeSettings"],
        json!({"path": "/up", "host": "front.example"})
    );
    let header = Profile {
        port: 80,
        transport: Some(Transport::TcpHttpHeader {
            host: vec!["h.example".into()],
            path: Vec::new(),
        }),
        ..profile(vmess())
    };
    let s = &out(&header)["streamSettings"];
    assert_eq!(s["network"], "tcp");
    let h = &s["tcpSettings"]["header"];
    assert_eq!(h["type"], "http");
    assert_eq!(h["request"]["headers"]["Host"], json!(["h.example"]));
    assert_eq!(h["request"]["path"], json!(["/"]));
}

/// XHTTP share links for VLESS and Trojan: the link's `extra` reaches Xray verbatim and an
/// export -> import round trip keeps `streamSettings` identical (old transportCompatibility
/// vector; the link is regenerated, not the imported line).
#[test]
fn xhttp_links_round_trip() {
    use vpnte_profiles::export::export_uri;
    use vpnte_profiles::model::Source;
    use vpnte_profiles::uri::parse_uri;

    let query = "type=xhttp&security=tls&sni=front.example.com&path=%2Fa%252Fb&host=front.example.com\
        &mode=packet-up&extra=%7B%22noSSEHeader%22%3Atrue%2C%22custom%22%3A%7B%22escaped%22%3A\
        %22%252F%26%3D%2525%22%2C%22array%22%3A%5Btrue%2C0%2C%22text%22%5D%7D%7D";
    for link in [
        format!("vless://{UUID}@nl.example:443?encryption=none&{query}#XHTTP"),
        format!("trojan://{PW}@nl.example:443?{query}#XHTTP"),
    ] {
        let mut p = parse_uri(&link).expect("link parses");
        let first = out(&p);
        assert_eq!(
            first["streamSettings"]["xhttpSettings"],
            json!({"path": "/a%2Fb", "host": "front.example.com", "mode": "packet-up",
                   "extra": {"noSSEHeader": true, "custom": {"escaped": "%2F&=%25", "array": [true, 0, "text"]},
                             "xmux": default_xmux()}})
        );
        p.source = Source::Json;
        let again = parse_uri(&export_uri(&p).expect("exports as a link")).expect("re-imports");
        assert_eq!(again.transport, p.transport);
        assert_eq!(out(&again)["streamSettings"], first["streamSettings"]);
    }
}
