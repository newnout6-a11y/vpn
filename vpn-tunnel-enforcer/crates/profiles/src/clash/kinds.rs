//! Credentials and protocol options per mihomo proxy type.
use std::net::IpAddr;

use super::yaml::Node;
use super::{Draft, Obj, Proto, invalid, parse_mbps, parse_u32};
use crate::common::fields::{HY2_OBFS_TYPES, parse_host, parse_port, port_range};
use crate::common::wg;
use crate::model::{
    Host, Hy2Obfs, Kind, Note, ShadowTlsLayer, SkipReason, SsPlugin, Tls, WgPeer, WireGuard,
};
use crate::wg_ini;

/// Shadowsocks methods sing-box 1.14 implements (`docs/configuration/outbound/shadowsocks.md`).
const SS_METHODS: &[&str] = &[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
];

/// The protocol part of an entry; may adjust `draft` (server, port, TLS, notes, extras).
pub(super) fn read_kind(proto: Proto, obj: &Obj, draft: &mut Draft) -> Result<Kind, SkipReason> {
    let text = |key: &str| obj.str(key).map(str::to_owned);
    Ok(match proto {
        Proto::Vless => Kind::Vless {
            uuid: required(obj.str("uuid"))?,
            flow: text("flow"),
            packet_encoding: packet_encoding(obj, &mut draft.notes),
            // `none` is VLESS's "no encryption"; anything else is Xray's ML-KEM scheme.
            encryption: obj
                .str("encryption")
                .filter(|e| !e.eq_ignore_ascii_case("none"))
                .map(str::to_owned),
        },
        Proto::Vmess => {
            let alter_id = obj
                .first_str(&["alterId", "alter-id"])
                .and_then(parse_u32)
                .unwrap_or(0);
            if alter_id != 0 {
                draft.notes.push(Note::AlterIdNormalized(alter_id));
            }
            if let Some(encoding) = packet_encoding(obj, &mut draft.notes) {
                draft
                    .extra
                    .insert("packet_encoding".to_owned(), encoding.into());
            }
            Kind::Vmess {
                uuid: required(obj.str("uuid"))?,
                security: obj.str("cipher").unwrap_or("auto").to_ascii_lowercase(),
                global_padding: obj.bool("global-padding").unwrap_or(false),
                authenticated_length: obj.bool("authenticated-length").unwrap_or(false),
            }
        }
        Proto::Trojan => {
            // trojan-go's extra Shadowsocks AEAD layer: no engine of ours speaks it.
            if obj
                .node("ss-opts")
                .and_then(|o| o.get("enabled"))
                .and_then(Node::as_bool)
                == Some(true)
            {
                return Err(SkipReason::UnsupportedTransport("ss-opts".to_owned()));
            }
            Kind::Trojan {
                password: required(obj.str("password"))?,
            }
        }
        Proto::Shadowsocks => shadowsocks(obj, draft)?,
        Proto::Hysteria2 => hysteria2(obj, draft)?,
        Proto::Tuic => tuic(obj, draft)?,
        Proto::Anytls => Kind::Anytls {
            password: required(obj.str("password"))?,
            idle_check_s: obj.str("idle-session-check-interval").and_then(seconds),
            idle_timeout_s: obj.str("idle-session-timeout").and_then(seconds),
            min_idle: obj.str("min-idle-session").and_then(parse_u32),
        },
        Proto::Wireguard => Kind::Wireguard(wireguard(obj, draft)?),
        Proto::Socks => {
            // sing-box's SOCKS outbound has no TLS; dialing a TLS-wrapped SOCKS server in clear
            // would fail and expose the credentials.
            if draft.tls.is_some() {
                return Err(SkipReason::UnsupportedTransport("socks5+tls".to_owned()));
            }
            Kind::Socks {
                username: text("username"),
                password: text("password"),
            }
        }
        Proto::Http => Kind::Http {
            username: text("username"),
            password: text("password"),
        },
    })
}

fn required(value: Option<&str>) -> Result<String, SkipReason> {
    value
        .map(str::to_owned)
        .ok_or(SkipReason::MissingCredential)
}

/// `packet-encoding` (`packet` is mihomo's alias of `packetaddr`) or the older `xudp` /
/// `packet-addr` switches, XUDP winning as in mihomo. Another value is noted and dropped:
/// sing-box refuses to start with it.
fn packet_encoding(obj: &Obj, notes: &mut Vec<Note>) -> Option<String> {
    let mut xudp = obj.bool("xudp") == Some(true);
    let mut packet_addr = obj.bool("packet-addr") == Some(true);
    match obj
        .str("packet-encoding")
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        None => {}
        Some("xudp") => xudp = true,
        Some("packetaddr" | "packet") => packet_addr = true,
        Some(_) => notes.push(Note::UnsupportedField("packet-encoding".to_owned())),
    }
    let encoding = if xudp {
        "xudp"
    } else if packet_addr {
        "packetaddr"
    } else {
        return None;
    };
    Some(encoding.to_owned())
}

/// Whole seconds: `30` or `30s`.
fn seconds(raw: &str) -> Option<u32> {
    parse_u32(raw.trim().strip_suffix('s').unwrap_or(raw)).filter(|&n| n > 0)
}

fn shadowsocks(obj: &Obj, draft: &mut Draft) -> Result<Kind, SkipReason> {
    let method = obj
        .first_str(&["cipher", "method"])
        .ok_or_else(|| invalid("ss: missing cipher"))?
        .to_ascii_lowercase();
    // mihomo knows many more ciphers (CCM, GCM-SIV, LEA, AEGIS, …): refuse them here rather
    // than store a profile that fails when the engine starts.
    let method = match method.as_str() {
        "chacha20-poly1305" => "chacha20-ietf-poly1305".to_owned(),
        "xchacha20-poly1305" => "xchacha20-ietf-poly1305".to_owned(),
        m if SS_METHODS.contains(&m) => method,
        _ => return Err(invalid(format!("ss: unsupported cipher {method}"))),
    };
    let password = match obj.str("password") {
        Some(p) => p.to_owned(),
        None if method == "none" => String::new(),
        None => return Err(SkipReason::MissingCredential),
    };
    // mihomo reads an absent or `0` version as 1 (sing-box's default is 2) and refuses others.
    let uot = match (
        obj.bool("udp-over-tcp"),
        obj.str("udp-over-tcp-version").map(str::trim),
    ) {
        (Some(true), None | Some("0" | "1")) => Some(1),
        (Some(true), Some("2")) => Some(2),
        (Some(true), Some(v)) => {
            return Err(invalid(format!("ss: unknown udp-over-tcp-version {v}")));
        }
        _ => None,
    };
    let opts = obj.node("plugin-opts");
    let opt = |key: &str| opts.and_then(|o| o.get(key)).and_then(Node::as_str);
    let mut plugin = None;
    let mut shadowtls = None;
    match obj.str("plugin").map(str::to_ascii_lowercase).as_deref() {
        None => {}
        Some("obfs" | "simple-obfs" | "obfs-local") => {
            let mode = opt("mode").unwrap_or("http").to_ascii_lowercase();
            if !matches!(mode.as_str(), "http" | "tls") {
                return Err(SkipReason::UnsupportedPlugin(format!("obfs ({mode})")));
            }
            // mihomo's default host; sing-box would send none.
            let host = sip003_escape(opt("host").unwrap_or("bing.com"));
            plugin = Some(SsPlugin {
                name: "obfs-local".to_owned(),
                opts: format!("obfs={mode};obfs-host={host}"),
            });
        }
        Some("v2ray-plugin") => plugin = Some(v2ray_plugin(opts, &mut draft.notes)?),
        Some("shadow-tls") => {
            let version = opt("version")
                .and_then(parse_u32)
                .and_then(|v| u8::try_from(v).ok())
                .unwrap_or(2);
            let password = opt("password").unwrap_or_default().to_owned();
            if !(1..=3).contains(&version) {
                return Err(invalid(format!("ss: unknown shadow-tls version {version}")));
            }
            if version >= 2 && password.is_empty() {
                return Err(SkipReason::MissingCredential);
            }
            let server_name = opt("host")
                .ok_or_else(|| invalid("ss: shadow-tls without host"))?
                .to_owned();
            // For a Shadowsocks profile `tls` describes the ShadowTLS layer (the emitter's view).
            draft.tls = Some(Tls {
                server_name: Some(server_name.clone()),
                insecure: opts
                    .and_then(|o| o.get("skip-cert-verify"))
                    .and_then(Node::as_bool)
                    .unwrap_or(false),
                alpn: opts
                    .and_then(|o| o.get("alpn"))
                    .map(Node::as_list)
                    .unwrap_or_default(),
                fingerprint: obj
                    .str("client-fingerprint")
                    .map(str::to_ascii_lowercase)
                    .filter(|f| f != "none"),
                ..Tls::default()
            });
            shadowtls = Some(ShadowTlsLayer {
                version,
                password,
                server_name,
            });
        }
        Some(other) => return Err(SkipReason::UnsupportedPlugin(other.to_owned())),
    }
    Ok(Kind::Shadowsocks {
        method,
        password,
        plugin,
        shadowtls,
        uot,
    })
}

/// mihomo `plugin-opts` -> the SIP003 option string sing-box's built-in v2ray-plugin parses.
fn v2ray_plugin(opts: Option<&Node>, notes: &mut Vec<Note>) -> Result<SsPlugin, SkipReason> {
    let get = |key: &str| opts.and_then(|o| o.get(key));
    let mode = get("mode")
        .and_then(Node::as_str)
        .unwrap_or("websocket")
        .to_ascii_lowercase();
    if mode != "websocket" || get("v2ray-http-upgrade").and_then(Node::as_bool) == Some(true) {
        return Err(SkipReason::UnsupportedPlugin(format!(
            "v2ray-plugin ({mode})"
        )));
    }
    let mut parts = vec!["mode=websocket".to_owned()];
    if get("tls").and_then(Node::as_bool) == Some(true) {
        parts.push("tls".to_owned());
    }
    // mihomo's defaults: host `bing.com` (also the TLS server name) and mux on.
    let host = get("host").and_then(Node::as_str).unwrap_or("bing.com");
    parts.push(format!("host={}", sip003_escape(host)));
    if let Some(path) = get("path").and_then(Node::as_str) {
        parts.push(format!("path={}", sip003_escape(path)));
    }
    let mux = get("mux").and_then(Node::as_bool).unwrap_or(true);
    parts.push(format!("mux={}", u8::from(mux)));
    for key in ["skip-cert-verify", "fingerprint", "headers"] {
        // `false` asks for what sing-box does anyway.
        if get(key).is_some_and(|v| !v.is_null() && v.as_bool() != Some(false)) {
            notes.push(Note::UnsupportedField(format!("plugin-opts.{key}")));
        }
    }
    Ok(SsPlugin {
        name: "v2ray-plugin".to_owned(),
        opts: parts.join(";"),
    })
}

/// SIP003 values escape `\`, `=` and `;` with a backslash.
fn sip003_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        if matches!(c, '\\' | '=' | ';') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn hysteria2(obj: &Obj, draft: &mut Draft) -> Result<Kind, SkipReason> {
    let password = required(obj.str("password"))?;
    let notes = &mut draft.notes;
    // mihomo: `ports` enables hopping and then `port` is ignored, so it may be absent.
    let ports = lenient(notes, "ports", obj.str("ports").map(parse_ports)).unwrap_or_default();
    let (hop_interval_s, hop_interval_max_s) =
        lenient(notes, "hop-interval", obj.str("hop-interval").map(hop)).unwrap_or_default();
    let up_mbps = lenient(notes, "up", obj.str("up").map(parse_mbps));
    let down_mbps = lenient(notes, "down", obj.str("down").map(parse_mbps));
    if draft.port.is_none() {
        draft.port = ports.first().map(|&(start, _)| start);
    }
    let obfs = match obj.str("obfs").map(str::to_ascii_lowercase) {
        None => None,
        Some(kind) if HY2_OBFS_TYPES.contains(&kind.as_str()) => {
            // sing-box refuses an obfuscator without a password at start (as the URI importer).
            let password = obj
                .str("obfs-password")
                .ok_or_else(|| invalid("hysteria2: obfs without a password"))?
                .to_owned();
            if kind == "gecko" {
                for (key, singbox_key) in [
                    ("obfs-min-packet-size", "obfs.min_packet_size"),
                    ("obfs-max-packet-size", "obfs.max_packet_size"),
                ] {
                    if let Some(n) = obj.str(key).and_then(parse_u32) {
                        draft.extra.insert(singbox_key.to_owned(), n.into());
                    }
                }
            }
            Some(Hy2Obfs { kind, password })
        }
        Some(kind) => return Err(invalid(format!("hysteria2: unknown obfs {kind}"))),
    };
    Ok(Kind::Hysteria2 {
        password,
        obfs,
        ports,
        hop_interval_s,
        hop_interval_max_s,
        up_mbps,
        down_mbps,
        bbr_profile: obj.str("bbr-profile").map(str::to_ascii_lowercase),
    })
}

/// A bad optional knob costs that knob (with a note), not the whole server.
fn lenient<T>(notes: &mut Vec<Note>, key: &str, value: Option<Option<T>>) -> Option<T> {
    if matches!(value, Some(None)) {
        notes.push(Note::UnsupportedField(key.to_owned()));
    }
    value.flatten()
}

/// Hopping ports: `443`, `443-8443`, `443,20000-30000` (mihomo also accepts `/` between items).
fn parse_ports(raw: &str) -> Option<Vec<(u16, u16)>> {
    raw.split([',', '/']).map(port_range).collect()
}

/// `30` seconds, or a `15-30` range picked at random by the core on each hop.
fn hop(raw: &str) -> Option<(Option<u32>, Option<u32>)> {
    match raw.split_once('-') {
        Some((min, max)) => {
            let (min, max) = (seconds(min)?, seconds(max)?);
            (min <= max).then_some((Some(min), Some(max)))
        }
        None => Some((Some(seconds(raw)?), None)),
    }
}

fn tuic(obj: &Obj, draft: &mut Draft) -> Result<Kind, SkipReason> {
    if obj.str("token").is_some() {
        return Err(invalid("tuic: TUIC v4 (token) is not supported"));
    }
    let uuid = required(obj.str("uuid"))?;
    let password = required(obj.str("password"))?;
    // `ip` replaces the DNS answer for `server`; the TLS server name was already taken from it.
    if let Some(ip) = obj.str("ip").and_then(|raw| raw.parse::<IpAddr>().ok()) {
        draft.server = Some(Host::Ip(ip));
    }
    if obj.bool("disable-sni") == Some(true)
        && let Some(tls) = draft.tls.as_mut()
    {
        tls.disable_sni = true;
    }
    let congestion =
        obj.str("congestion-controller")
            .map(|c| match c.to_ascii_lowercase().as_str() {
                "new-reno" | "newreno" => "new_reno".to_owned(),
                other => other.to_owned(),
            });
    Ok(Kind::Tuic {
        uuid,
        password,
        congestion,
        udp_relay_mode: obj.str("udp-relay-mode").map(str::to_ascii_lowercase),
        zero_rtt: obj.bool("reduce-rtt").unwrap_or(false),
        // mihomo counts milliseconds; sing-box takes a duration we store in whole seconds.
        heartbeat_s: obj
            .str("heartbeat-interval")
            .and_then(parse_u32)
            .filter(|&ms| ms > 0)
            .map(|ms| ms.div_ceil(1000)),
    })
}

fn wireguard(obj: &Obj, draft: &mut Draft) -> Result<WireGuard, SkipReason> {
    let private_key = wg_ini::key(obj.str("private-key"))?;
    let mut local_address = Vec::new();
    for key in ["ip", "ipv6"] {
        if let Some(raw) = obj.str(key) {
            local_address.push(
                wg::interface_address(raw)
                    .ok_or_else(|| invalid(format!("wireguard: invalid {key}")))?,
            );
        }
    }
    if local_address.is_empty() {
        return Err(invalid("wireguard: missing ip"));
    }
    let keepalive = obj.str("persistent-keepalive").and_then(wg_ini::keepalive);
    let peers = match obj.node("peers") {
        Some(Node::Seq(items)) if !items.is_empty() => items
            .iter()
            .map(|item| {
                let pairs = item
                    .as_map()
                    .ok_or_else(|| invalid("wireguard: peer is not a mapping"))?;
                let obj = Obj::new(pairs);
                let mut peer = peer(&obj, None, None, keepalive)?;
                peer.allowed_ips = obj
                    .list("allowed-ips")
                    .iter()
                    .map(|net| wg::interface_address(net))
                    .collect::<Option<_>>()
                    .ok_or_else(|| invalid("wireguard: invalid allowed-ips"))?;
                Ok(peer)
            })
            .collect::<Result<Vec<_>, _>>()?,
        // mihomo ignores `allowed-ips` of the single-peer form and routes everything of the
        // local address families; an empty list makes the emitter do the same (K21).
        _ => {
            obj.node("allowed-ips");
            vec![peer(obj, draft.server.clone(), draft.port, keepalive)?]
        }
    };
    // mihomo refuses such an entry at load; the emitter would refuse it at connect.
    if wg::unrouted_peer(&peers) {
        return Err(invalid("wireguard: a listed peer without allowed-ips"));
    }
    if let Some(first) = peers.first() {
        draft.server = Some(first.host.clone());
        draft.port = Some(first.port);
    }
    if let Some(option) = obj.node("amnezia-wg-option").and_then(Node::as_map) {
        let pairs = option
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str().unwrap_or_default()));
        draft.notes.extend(wg::amnezia_note(pairs));
        // Newer AmneziaWG knobs (header protection, padding, timers) are dropped: say so.
        for (key, value) in option {
            let off = value.is_null() || value.as_bool() == Some(false);
            if !off && key != "version" && !wg::is_amnezia_key(&key.to_ascii_lowercase()) {
                let field = format!("amnezia-wg-option.{key}");
                draft.notes.push(Note::UnsupportedField(field));
            }
        }
    }
    Ok(WireGuard {
        private_key,
        local_address,
        mtu: obj
            .str("mtu")
            .and_then(parse_u32)
            .and_then(|n| u16::try_from(n).ok())
            .filter(|&n| n > 0),
        dns: obj
            .list("dns")
            .iter()
            .filter_map(|d| d.parse().ok())
            .collect(),
        peers,
    })
}

/// One peer without its routes: the entry itself (single-peer form) or an item of `peers`.
fn peer(
    obj: &Obj,
    host: Option<Host>,
    port: Option<u16>,
    keepalive: Option<u16>,
) -> Result<WgPeer, SkipReason> {
    let host = host
        .or_else(|| obj.str("server").and_then(|s| parse_host(s.trim())))
        .ok_or_else(|| invalid("wireguard: peer without server"))?;
    let port = port
        .or_else(|| obj.str("port").and_then(|s| parse_port(s.trim())))
        .ok_or_else(|| invalid("wireguard: peer without port"))?;
    let reserved = match obj.node("reserved") {
        Some(node) if !node.is_null() => Some(
            wg::reserved(&node.as_list().join(","))
                .ok_or_else(|| invalid("wireguard: invalid reserved"))?,
        ),
        _ => None,
    };
    Ok(WgPeer {
        host,
        port,
        public_key: wg_ini::key(obj.str("public-key"))?,
        pre_shared_key: obj
            .str("pre-shared-key")
            .map(|k| wg_ini::key(Some(k)))
            .transpose()?,
        allowed_ips: Vec::new(),
        // mihomo has one keepalive for the whole entry.
        keepalive_s: keepalive,
        reserved,
    })
}
