//! Proxy outbounds (one per profile) and the Shadowsocks-over-ShadowTLS chain.
use serde_json::{Map, Value, json};

use super::tls::{self, Family};
use super::{EmitError, EmitPolicy, extra, udp};
use crate::common::fields::HY2_OBFS_TYPES;
use crate::model::{DialPrefs, Host, Kind, Profile, ShadowTlsLayer, SsPlugin, Transport};

type Obj = Map<String, Value>;

pub(super) fn outbound(p: &Profile, tag: &str, policy: &EmitPolicy) -> Result<Value, EmitError> {
    let mut o = head(p.kind.label(), tag);
    server(&mut o, p);
    protocol(&mut o, &p.kind)?;
    if let Some(tls) = tls::outbound_tls(p, policy)? {
        o.insert("tls".into(), tls);
    }
    if let Some(t) = &p.transport {
        o.insert("transport".into(), transport(t, &p.kind)?);
    }
    if let Some(m) = multiplex(p, policy)? {
        o.insert("multiplex".into(), m);
    }
    dial(&mut o, p, policy);
    let family = tls::family(p);
    extra::merge(&mut o, &p.singbox_extra, |path| match (family, path) {
        _ if tls::is_trick_key(path) => false,
        // naive refuses every TLS knob but the typed ones; uTLS breaks QUIC dials, whoever
        // asked for it.
        (Some(Family::Naive), ["tls", ..]) => false,
        (Some(Family::Quic), ["tls", "utls" | "reality", ..]) => false,
        _ => true,
    });
    // Older imports saved `network: "tcp"` on Hysteria2, which made the UDP guard block the
    // very transport it needs (QUIC).
    if matches!(p.kind, Kind::Hysteria2 { .. }) && !udp::network_allows_udp(o.get("network")) {
        o.remove("network");
    }
    Ok(Value::Object(o))
}

/// Shadowsocks dialing through a ShadowTLS outbound: `[shadowsocks (tag), shadowtls]`.
pub(super) fn shadowtls_chain(
    p: &Profile,
    layer: &ShadowTlsLayer,
    tag: &str,
    policy: &EmitPolicy,
) -> Result<Vec<Value>, EmitError> {
    if p.transport.is_some() {
        return Err(EmitError::TransportUnsupported(p.kind.label()));
    }
    let layer_tag = format!("{tag}-shadowtls");
    let mut ss = head("shadowsocks", tag);
    server(&mut ss, p);
    protocol(&mut ss, &p.kind)?;
    if let Some(m) = multiplex(p, policy)? {
        ss.insert("multiplex".into(), m);
    }
    // With `detour` sing-box ignores every other dial field: they belong to the ShadowTLS
    // dialer, which connects to the server itself and ignores the inner destination.
    ss.insert("detour".into(), Value::String(layer_tag.clone()));
    extra::merge(&mut ss, &p.singbox_extra, |path| {
        path.first() != Some(&"tls")
    });

    let mut st = head("shadowtls", &layer_tag);
    server(&mut st, p);
    st.insert("version".into(), json!(layer.version));
    if layer.version >= 2 && !layer.password.is_empty() {
        st.insert("password".into(), Value::String(layer.password.clone()));
    }
    st.insert("tls".into(), tls::layer_tls(p, layer, policy)?);
    dial(&mut st, p, policy);
    extra::merge(&mut st, &p.singbox_extra, |path| {
        path.first() == Some(&"tls") && !tls::is_trick_key(path)
    });
    Ok(vec![Value::Object(ss), Value::Object(st)])
}

fn head(kind: &str, tag: &str) -> Obj {
    let mut o = Obj::new();
    o.insert("type".into(), Value::String(kind.to_owned()));
    o.insert("tag".into(), Value::String(tag.to_owned()));
    o
}

/// `server` (IPv6 unbracketed) and the port; Hysteria2 port hopping replaces `server_port`
/// with `server_ports` (the two conflict), every entry `start:end`, a single port `N:N`.
fn server(o: &mut Obj, p: &Profile) {
    o.insert("server".into(), Value::String(p.server.to_string()));
    let ranges: Vec<String> = match &p.kind {
        Kind::Hysteria2 { ports, .. } => ports
            .iter()
            .map(|&(a, b)| (a.min(b), a.max(b)))
            .filter(|&(start, _)| start > 0)
            .map(|(start, end)| format!("{start}:{end}"))
            .collect(),
        _ => Vec::new(),
    };
    if ranges.is_empty() {
        o.insert("server_port".into(), json!(p.port));
    } else {
        o.insert("server_ports".into(), json!(ranges));
    }
}

/// Credentials and protocol knobs, as the provider gave them; durations become Go strings.
fn protocol(o: &mut Obj, kind: &Kind) -> Result<(), EmitError> {
    match kind {
        Kind::Vless {
            uuid,
            flow,
            packet_encoding,
            ..
        } => {
            put(o, "uuid", uuid);
            // Xray's `-udp443` variant only lifts its client-side QUIC block; on the wire it is
            // plain vision, the one flow sing-box knows.
            put_opt(
                o,
                "flow",
                flow.as_deref()
                    .map(|f| f.trim().trim_end_matches("-udp443")),
            );
            // An explicit empty encoding is meaningful (no UDP tunnelling): keep it.
            if let Some(pe) = packet_encoding {
                put(o, "packet_encoding", &pe.trim().to_ascii_lowercase());
            }
        }
        Kind::Vmess {
            uuid,
            security,
            global_padding,
            authenticated_length,
        } => {
            put(o, "uuid", uuid);
            put(
                o,
                "security",
                if security.trim().is_empty() {
                    "auto"
                } else {
                    security.trim()
                },
            );
            flag(o, "global_padding", *global_padding);
            flag(o, "authenticated_length", *authenticated_length);
        }
        Kind::Trojan { password } => put(o, "password", password),
        Kind::Shadowsocks {
            method,
            password,
            plugin,
            uot,
            ..
        } => {
            put(o, "method", method.trim());
            put(o, "password", password);
            if let Some(plugin) = plugin {
                ss_plugin(o, plugin)?;
            }
            if let Some(version) = uot {
                let uot = match version {
                    1 | 2 => json!({ "enabled": true, "version": version }),
                    _ => Value::Bool(true),
                };
                o.insert("udp_over_tcp".into(), uot);
            }
        }
        Kind::Hysteria2 {
            password,
            obfs,
            hop_interval_s,
            hop_interval_max_s,
            up_mbps,
            down_mbps,
            bbr_profile,
            ..
        } => {
            secs(o, "hop_interval", *hop_interval_s);
            secs(o, "hop_interval_max", *hop_interval_max_s);
            count(o, "up_mbps", *up_mbps);
            count(o, "down_mbps", *down_mbps);
            if let Some(obfs) = obfs {
                let kind = obfs.kind.trim().to_ascii_lowercase();
                if !HY2_OBFS_TYPES.contains(&kind.as_str()) || obfs.password.is_empty() {
                    return Err(EmitError::Hy2Obfs(obfs.kind.clone()));
                }
                o.insert(
                    "obfs".into(),
                    json!({ "type": kind, "password": obfs.password }),
                );
            }
            put(o, "password", password);
            put_opt(o, "bbr_profile", bbr_profile.as_deref());
        }
        Kind::Tuic {
            uuid,
            password,
            congestion,
            udp_relay_mode,
            zero_rtt,
            heartbeat_s,
        } => {
            put(o, "uuid", uuid);
            put(o, "password", password);
            put_opt(o, "congestion_control", congestion.as_deref());
            put_opt(o, "udp_relay_mode", udp_relay_mode.as_deref());
            flag(o, "zero_rtt_handshake", *zero_rtt);
            secs(o, "heartbeat", *heartbeat_s);
        }
        Kind::Naive {
            username,
            password,
            quic,
            extra_headers,
            insecure_concurrency,
        } => {
            put(o, "username", username);
            put(o, "password", password);
            count(o, "insecure_concurrency", *insecure_concurrency);
            if !extra_headers.is_empty() {
                let headers: Obj = extra_headers
                    .iter()
                    .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                    .collect();
                o.insert("extra_headers".into(), Value::Object(headers));
            }
            flag(o, "quic", *quic);
        }
        Kind::Anytls {
            password,
            idle_check_s,
            idle_timeout_s,
            min_idle,
        } => {
            put(o, "password", password);
            secs(o, "idle_session_check_interval", *idle_check_s);
            secs(o, "idle_session_timeout", *idle_timeout_s);
            if let Some(n) = min_idle {
                o.insert("min_idle_session".into(), json!(n));
            }
        }
        Kind::Socks { username, password } => {
            put(o, "version", "5");
            put_opt(o, "username", username.as_deref());
            put_opt(o, "password", password.as_deref());
        }
        Kind::Http { username, password } => {
            put_opt(o, "username", username.as_deref());
            put_opt(o, "password", password.as_deref());
        }
        // Emitted as an endpoint by `wireguard::endpoint` (AmneziaWG: refused), never as an
        // outbound.
        Kind::Wireguard(_) | Kind::Amneziawg { .. } => {}
    }
    Ok(())
}

/// sing-box implements exactly two SIP003 plugins, internally; Clash calls the first `obfs`.
fn ss_plugin(o: &mut Obj, plugin: &SsPlugin) -> Result<(), EmitError> {
    let name = match plugin.name.trim() {
        "obfs-local" | "obfs" | "simple-obfs" => "obfs-local",
        "v2ray-plugin" => "v2ray-plugin",
        other => return Err(EmitError::SsPlugin(other.to_owned())),
    };
    put(o, "plugin", name);
    put_opt(o, "plugin_opts", Some(plugin.opts.as_str()));
    Ok(())
}

fn transport(t: &Transport, kind: &Kind) -> Result<Value, EmitError> {
    if !matches!(
        kind,
        Kind::Vless { .. } | Kind::Vmess { .. } | Kind::Trojan { .. }
    ) {
        return Err(EmitError::TransportUnsupported(kind.label()));
    }
    let mut o = Obj::new();
    match t {
        Transport::Ws {
            path,
            host,
            max_early_data,
            early_data_header,
        } => {
            put(&mut o, "type", "ws");
            put_opt(&mut o, "path", Some(path.as_str()));
            if let Some(host) = host.as_deref().map(str::trim).filter(|h| !h.is_empty()) {
                o.insert("headers".into(), json!({ "Host": host }));
            }
            count(&mut o, "max_early_data", *max_early_data);
            put_opt(
                &mut o,
                "early_data_header_name",
                early_data_header.as_deref(),
            );
        }
        // sing-box's gRPC transport speaks Xray's "gun" mode; only multi mode is Xray's alone.
        Transport::Grpc {
            service_name,
            multi_mode: None | Some(false),
        } => {
            put(&mut o, "type", "grpc");
            put_opt(&mut o, "service_name", Some(service_name.as_str()));
        }
        Transport::Http { hosts, path } => {
            put(&mut o, "type", "http");
            let hosts: Vec<&str> = hosts
                .iter()
                .map(|h| h.trim())
                .filter(|h| !h.is_empty())
                .collect();
            if !hosts.is_empty() {
                o.insert("host".into(), json!(hosts));
            }
            put_opt(&mut o, "path", Some(path.as_str()));
        }
        Transport::HttpUpgrade { host, path } => {
            put(&mut o, "type", "httpupgrade");
            put_opt(&mut o, "host", Some(host.as_str()));
            put_opt(&mut o, "path", Some(path.as_str()));
        }
        Transport::Quic => put(&mut o, "type", "quic"),
        Transport::Grpc {
            multi_mode: Some(true),
            ..
        } => return Err(EmitError::XrayOnly("gRPC multiMode")),
        Transport::Xhttp { .. } => return Err(EmitError::XrayOnly("XHTTP")),
        Transport::TcpHttpHeader { .. } => return Err(EmitError::XrayOnly("TCP header=http")),
    }
    Ok(Value::Object(o))
}

/// sing-mux exists only in these four outbounds; an enabled mux elsewhere is refused rather
/// than silently dropped. VLESS/Reality mux is kept: it mitigates TSPU blocking of parallel
/// ClientHellos.
fn multiplex(p: &Profile, policy: &EmitPolicy) -> Result<Option<Value>, EmitError> {
    let Some(m) = p.mux.as_ref().filter(|_| policy.allow_mux) else {
        return Ok(None);
    };
    if !matches!(
        p.kind,
        Kind::Vless { .. } | Kind::Vmess { .. } | Kind::Trojan { .. } | Kind::Shadowsocks { .. }
    ) {
        return if m.enabled {
            Err(EmitError::MuxUnsupported(p.kind.label()))
        } else {
            Ok(None)
        };
    }
    let mut o = Obj::new();
    o.insert("enabled".into(), Value::Bool(m.enabled));
    put_opt(&mut o, "protocol", m.protocol.as_deref());
    count(&mut o, "max_connections", m.max_connections);
    flag(&mut o, "padding", m.padding);
    if let Some((up, down)) = m.brutal.filter(|&(up, down)| up > 0 && down > 0) {
        o.insert(
            "brutal".into(),
            json!({ "enabled": true, "up_mbps": up, "down_mbps": down }),
        );
    }
    Ok(Some(Value::Object(o)))
}

fn dial(o: &mut Obj, p: &Profile, policy: &EmitPolicy) {
    let d = &p.dial;
    secs(o, "connect_timeout", d.connect_timeout_s);
    // The anytls outbound refuses TCP Fast Open outright.
    flag(
        o,
        "tcp_fast_open",
        d.tcp_fast_open && !matches!(p.kind, Kind::Anytls { .. }),
    );
    flag(o, "tcp_multi_path", d.tcp_multi_path);
    if let Some(fragment) = d.udp_fragment {
        o.insert("udp_fragment".into(), Value::Bool(fragment));
    }
    if matches!(p.server, Host::Domain(_))
        && let Some(resolver) = domain_resolver(d, policy)
    {
        o.insert("domain_resolver".into(), resolver);
    }
}

/// A hostname server is resolved by the direct bootstrap server, never through the tunnel it
/// is about to build. `domain_strategy` was removed in 1.14: the provider's choice becomes the
/// resolver strategy (IPv4 only by default, like the tunnel's own DNS).
pub(super) fn domain_resolver(dial: &DialPrefs, policy: &EmitPolicy) -> Option<Value> {
    let server = policy.domain_resolver.as_deref()?;
    let strategy = dial
        .dns_strategy
        .as_deref()
        .map(str::trim)
        .filter(|s| {
            matches!(
                *s,
                "prefer_ipv4" | "prefer_ipv6" | "ipv4_only" | "ipv6_only"
            )
        })
        .unwrap_or("ipv4_only");
    Some(json!({ "server": server, "strategy": strategy }))
}

fn put(o: &mut Obj, key: &str, value: &str) {
    o.insert(key.into(), Value::String(value.to_owned()));
}

/// Inserts `value` unless it is absent or blank (credentials are kept byte-exact).
fn put_opt(o: &mut Obj, key: &str, value: Option<&str>) {
    if let Some(v) = value.filter(|v| !v.trim().is_empty()) {
        put(o, key, v);
    }
}

fn flag(o: &mut Obj, key: &str, on: bool) {
    if on {
        o.insert(key.into(), Value::Bool(true));
    }
}

/// Positive integers only: zero means "not set" for every knob routed here.
fn count(o: &mut Obj, key: &str, n: Option<u32>) {
    if let Some(n) = n.filter(|&n| n > 0) {
        o.insert(key.into(), json!(n));
    }
}

/// Seconds as a Go duration string (`30s`); zero means "engine default".
fn secs(o: &mut Obj, key: &str, s: Option<u32>) {
    if let Some(s) = s.filter(|&s| s > 0) {
        o.insert(key.into(), Value::String(format!("{s}s")));
    }
}
