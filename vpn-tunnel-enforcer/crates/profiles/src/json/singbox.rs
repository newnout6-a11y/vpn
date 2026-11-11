//! One sing-box outbound (or WireGuard endpoint) -> typed [`Profile`]. Keys sing-box 1.14 knows
//! but the model does not are kept verbatim in `singbox_extra` (allow-list per type); everything
//! else becomes a Note, so a pasted config never loses a setting silently.
use serde_json::{Map, Value};

use super::parts::{self, DIAL_TYPED};
use super::scan::{Origin, Scan};
use super::values::{
    duration_secs, flag, port, positive_u32, rounded_positive, text, text_or_number,
};
use super::wireguard;
use crate::common::fields::{HY2_OBFS_TYPES, port_range};
use crate::model::{
    Host, Hy2Obfs, Kind, Note, Profile, ShadowTlsLayer, SkipReason, Source, SsPlugin, Tls,
};

/// sing-box outbound / endpoint types imported as profiles.
pub(crate) const SUPPORTED: &[&str] = &[
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "shadowtls",
    "hysteria2",
    "tuic",
    "naive",
    "anytls",
    "wireguard",
    "socks",
    "http",
];

/// One outbound to import.
pub(crate) struct Input<'a> {
    pub(crate) obj: &'a Map<String, Value>,
    /// Lower-case sing-box type.
    pub(crate) kind: &'a str,
    pub(crate) name: String,
    pub(crate) origin: Origin,
    /// The ShadowTLS outbound a Shadowsocks outbound dials through (`detour`), from the same list.
    pub(crate) shadowtls: Option<&'a Map<String, Value>>,
}

/// Builds the profile or says why the outbound cannot become one.
pub(crate) fn import(input: Input<'_>) -> Result<Profile, SkipReason> {
    let Input {
        obj,
        kind,
        name,
        origin,
        shadowtls,
    } = input;
    let invalid = |detail: String| SkipReason::Invalid {
        scheme: kind.to_owned(),
        detail,
    };
    let mut scan = Scan::default();
    if kind == "wireguard" {
        let (server, port, wg) = wireguard::import(obj, &mut scan).map_err(invalid)?;
        let dial = parts::dial(obj, &mut scan);
        return Ok(finish(
            name,
            server,
            port,
            Kind::Wireguard(wg),
            None,
            dial,
            scan,
            origin,
        ));
    }
    if kind == "shadowtls" {
        return Err(SkipReason::ShadowTlsNeedsInner);
    }
    // A chained Shadowsocks dials through the ShadowTLS outbound: address, TLS and dial options are its.
    let outer = shadowtls.unwrap_or(obj);
    let server = parts::server_host(outer).map_err(|e| invalid(e.to_owned()))?;
    // Hysteria2 may give only a port-hopping list; its first port stands in then.
    let server_port = outer.get("server_port").and_then(port);
    // Blocks a type cannot carry are not read (and so end up as Notes, like any unknown key).
    let takes_tls = matches!(
        kind,
        "vless" | "vmess" | "trojan" | "hysteria2" | "tuic" | "naive" | "anytls" | "http"
    );
    let takes_transport = matches!(kind, "vless" | "vmess" | "trojan");
    let takes_mux = matches!(kind, "vless" | "vmess" | "trojan" | "shadowsocks");
    let mut typed: Vec<&str> = ["type", "tag", "server", "server_port"].into();
    typed.extend_from_slice(DIAL_TYPED);
    typed.extend(takes_tls.then_some("tls"));
    typed.extend(takes_transport.then_some("transport"));
    typed.extend(
        takes_mux
            .then_some(["multiplex", "mux"])
            .into_iter()
            .flatten(),
    );
    if origin == Origin::Legacy {
        typed.push("vpnte_xray");
    }
    let tls_source = match shadowtls {
        Some(chain) => {
            typed.push("detour");
            chain.get("tls")
        }
        None if takes_tls => obj.get("tls"),
        None => None,
    };
    let tls = parts::tls(tls_source, &mut scan).map_err(|e| invalid(e.to_owned()))?;
    let (kind_value, port) = match kind {
        "vless" => (vless(obj, &mut typed)?, server_port),
        "vmess" => (vmess(obj, &mut typed, &mut scan)?, server_port),
        "trojan" => {
            typed.push("password");
            let password = text(obj, &["password"]).ok_or(SkipReason::MissingCredential)?;
            let password = password.to_owned();
            (Kind::Trojan { password }, server_port)
        }
        "shadowsocks" => (
            shadowsocks(obj, shadowtls, &tls, &server, &mut typed, &mut scan)?,
            server_port,
        ),
        "hysteria2" => {
            let (kind_value, first_port) = hysteria2(obj, &mut typed, &mut scan)?;
            (kind_value, server_port.or(first_port))
        }
        "tuic" => (tuic(obj, &mut typed)?, server_port),
        "naive" => (naive(obj, &mut typed, &mut scan), server_port),
        "anytls" => (anytls(obj, &mut typed)?, server_port),
        "socks" => (socks(obj, &mut typed, &mut scan), server_port),
        "http" => {
            typed.extend(["username", "password"]);
            let username = text_or_number(obj, &["username"]);
            let password = text_or_number(obj, &["password"]);
            (Kind::Http { username, password }, server_port)
        }
        other => return Err(SkipReason::UnknownScheme(other.to_owned())),
    };
    let port = port.ok_or_else(|| invalid("missing or invalid server_port".into()))?;
    scan.sort_keys(obj, "", &typed, extra_keys(kind));
    if let Some(chain) = shadowtls {
        let mut chain_typed: Vec<&str> = [
            "type",
            "tag",
            "server",
            "server_port",
            "version",
            "password",
            "tls",
        ]
        .into();
        chain_typed.extend_from_slice(DIAL_TYPED);
        scan.sort_keys(chain, "shadowtls", &chain_typed, &[]);
    }
    let transport = match takes_transport {
        true => parts::transport(obj.get("transport"), &mut scan)?,
        false => None,
    };
    let mux = takes_mux
        .then(|| parts::multiplex(obj, &mut scan))
        .flatten();
    let dial = parts::dial(outer, &mut scan);
    let fingerprint = tls.as_ref().is_some_and(|t| t.fingerprint.is_some());
    match &kind_value {
        // sing-box takes no uTLS on QUIC; the provider's choice is kept but cannot apply.
        Kind::Hysteria2 { .. } | Kind::Tuic { .. } | Kind::Naive { quic: true, .. }
            if fingerprint =>
        {
            scan.note(Note::ProviderFpDroppedOnQuic)
        }
        _ => {}
    }
    match &kind_value {
        Kind::Naive { .. } if tls.as_ref().is_some_and(|t| t.insecure) => {
            scan.note(Note::NaiveInsecureIgnored)
        }
        Kind::Socks { .. } => scan.note(Note::Unencrypted),
        Kind::Http { .. } if tls.is_none() => scan.note(Note::Unencrypted),
        Kind::Shadowsocks { method, .. } if method == "none" => scan.note(Note::Unencrypted),
        _ => {}
    }
    let mut profile = finish(name, server, port, kind_value, tls, dial, scan, origin);
    profile.transport = transport;
    profile.mux = mux;
    Ok(profile)
}

/// Keys of `kind` kept verbatim in `singbox_extra`.
fn extra_keys(kind: &str) -> &'static [&'static str] {
    match kind {
        "vless" | "trojan" => &["network"],
        "vmess" => &["network", "packet_encoding"],
        "shadowsocks" => &["network"],
        "hysteria2" => &[
            "brutal_debug",
            "disable_chrome_parrot",
            "initial_packet_size",
            "disable_path_mtu_discovery",
            "idle_timeout",
            "keep_alive_period",
            "stream_receive_window",
            "connection_receive_window",
            "max_concurrent_streams",
        ],
        "tuic" => &[
            "network",
            "udp_over_stream",
            "initial_packet_size",
            "disable_path_mtu_discovery",
            "idle_timeout",
            "keep_alive_period",
            "stream_receive_window",
            "connection_receive_window",
            "max_concurrent_streams",
        ],
        "naive" => &[
            "stream_receive_window",
            "udp_over_tcp",
            "quic_congestion_control",
            "quic_session_receive_window",
        ],
        "anytls" => &["client_metadata"],
        "socks" => &["network", "udp_over_tcp"],
        "http" => &["path", "headers"],
        _ => &[],
    }
}

#[allow(clippy::too_many_arguments)]
fn finish(
    name: String,
    server: Host,
    port: u16,
    kind: Kind,
    tls: Option<Tls>,
    dial: crate::model::DialPrefs,
    scan: Scan,
    origin: Origin,
) -> Profile {
    Profile {
        name,
        description: None,
        server,
        port,
        kind,
        tls,
        transport: None,
        mux: None,
        dial,
        native_xray: None,
        singbox_extra: scan.extra,
        source: match origin {
            Origin::Json => Source::Json,
            Origin::Legacy => Source::Legacy,
        },
        notes: scan.notes,
    }
}

fn vless(o: &Map<String, Value>, typed: &mut Vec<&str>) -> Result<Kind, SkipReason> {
    typed.extend(["uuid", "flow", "packet_encoding", "encryption"]);
    let uuid = text(o, &["uuid"]).ok_or(SkipReason::MissingCredential)?;
    let owned = |k: &str| text(o, &[k]).map(str::to_owned);
    Ok(Kind::Vless {
        uuid: uuid.to_owned(),
        flow: owned("flow"),
        packet_encoding: owned("packet_encoding"),
        // Clash imports stored `encryption: "none"`; anything else is VLESS Encryption (Xray only).
        encryption: owned("encryption").filter(|e| !e.eq_ignore_ascii_case("none")),
    })
}

fn vmess(
    o: &Map<String, Value>,
    typed: &mut Vec<&str>,
    scan: &mut Scan,
) -> Result<Kind, SkipReason> {
    typed.extend([
        "uuid",
        "security",
        "alter_id",
        "global_padding",
        "authenticated_length",
    ]);
    let uuid = text(o, &["uuid"]).ok_or(SkipReason::MissingCredential)?;
    // Old imports persisted a NaN alter_id as `null`; AEAD (0) is what modern servers accept.
    let alter_id = o
        .get("alter_id")
        .and_then(super::values::number)
        .unwrap_or(0.0);
    if alter_id != 0.0 {
        scan.note(Note::AlterIdNormalized(
            alter_id.clamp(0.0, f64::from(u32::MAX)) as u32,
        ));
    }
    Ok(Kind::Vmess {
        uuid: uuid.to_owned(),
        security: text(o, &["security"]).unwrap_or("auto").to_owned(),
        global_padding: flag(o, "global_padding"),
        authenticated_length: flag(o, "authenticated_length"),
    })
}

/// SIP003 plugins sing-box runs in-process.
const SS_PLUGINS: &[&str] = &["obfs-local", "v2ray-plugin"];

fn shadowsocks(
    o: &Map<String, Value>,
    chain: Option<&Map<String, Value>>,
    tls: &Option<Tls>,
    server: &Host,
    typed: &mut Vec<&str>,
    scan: &mut Scan,
) -> Result<Kind, SkipReason> {
    typed.extend([
        "method",
        "password",
        "plugin",
        "plugin_opts",
        "udp_over_tcp",
    ]);
    let method = text(o, &["method"]).ok_or_else(|| SkipReason::Invalid {
        scheme: "shadowsocks".into(),
        detail: "missing method".into(),
    })?;
    let password = text(o, &["password"]).unwrap_or_default();
    if password.is_empty() && method != "none" {
        return Err(SkipReason::MissingCredential);
    }
    let plugin = match text(o, &["plugin"]) {
        None => None,
        Some(name) => {
            let name = if name == "simple-obfs" {
                "obfs-local"
            } else {
                name
            };
            if !SS_PLUGINS.contains(&name) {
                return Err(SkipReason::UnsupportedPlugin(name.to_owned()));
            }
            Some(SsPlugin {
                name: name.to_owned(),
                opts: text(o, &["plugin_opts"]).unwrap_or_default().to_owned(),
            })
        }
    };
    let uot = match o.get("udp_over_tcp") {
        Some(Value::Object(u)) if flag(u, "enabled") => {
            scan.sort_keys(u, "udp_over_tcp", &["enabled", "version"], &[]);
            Some(
                u.get("version")
                    .and_then(port)
                    .and_then(|v| u8::try_from(v).ok())
                    .unwrap_or(2),
            )
        }
        Some(v) if super::values::boolean(v) == Some(true) => Some(2),
        _ => None,
    };
    let shadowtls = chain.map(|c| ShadowTlsLayer {
        version: c
            .get("version")
            .and_then(port)
            .and_then(|v| u8::try_from(v).ok())
            .unwrap_or(1),
        password: text(c, &["password"]).unwrap_or_default().to_owned(),
        server_name: tls
            .as_ref()
            .and_then(|t| t.server_name.clone())
            .unwrap_or_else(|| server.to_string()),
    });
    Ok(Kind::Shadowsocks {
        method: method.to_owned(),
        password: password.to_owned(),
        plugin,
        shadowtls,
        uot,
    })
}

/// Hysteria2 and, when `server_port` is absent, the first port of its hopping list.
fn hysteria2(
    o: &Map<String, Value>,
    typed: &mut Vec<&str>,
    scan: &mut Scan,
) -> Result<(Kind, Option<u16>), SkipReason> {
    typed.extend([
        "password",
        "obfs",
        "server_ports",
        "hop_interval",
        "hop_interval_max",
        "up_mbps",
        "down_mbps",
        "bbr_profile",
        "network",
    ]);
    let password = text(o, &["password"]).ok_or(SkipReason::MissingCredential)?;
    // Older imports saved `network: "tcp"` on Hysteria2, which made the UDP guard block it (K13).
    if let Some(network) = o.get("network").filter(|n| n.as_str() != Some("tcp")) {
        scan.extra.insert("network".into(), network.clone());
    }
    match o.get("obfs") {
        Some(Value::Object(ob)) => scan.sort_keys(
            ob,
            "obfs",
            &["type", "password"],
            &["min_packet_size", "max_packet_size"],
        ),
        Some(_) => typed.extend(["obfs_password", "obfs-password"]),
        None => {}
    }
    let obfs = hy2_obfs(o)?;
    let ports = match o.get("server_ports") {
        None => Vec::new(),
        Some(v) => port_ranges(v).unwrap_or_else(|| {
            scan.unsupported("server_ports");
            Vec::new()
        }),
    };
    let first = ports.first().map(|r| r.0);
    let kind = Kind::Hysteria2 {
        password: password.to_owned(),
        obfs,
        ports,
        hop_interval_s: o.get("hop_interval").and_then(duration_secs),
        hop_interval_max_s: o.get("hop_interval_max").and_then(duration_secs),
        up_mbps: o.get("up_mbps").and_then(rounded_positive),
        down_mbps: o.get("down_mbps").and_then(rounded_positive),
        bbr_profile: text(o, &["bbr_profile"]).map(str::to_owned),
    };
    Ok((kind, first))
}

/// Hysteria2 obfuscation: an object `{type, password}` or a bare type next to `obfs_password`.
/// An unknown type or a missing password could never connect, so the entry is refused.
pub(crate) fn hy2_obfs(o: &Map<String, Value>) -> Result<Option<Hy2Obfs>, SkipReason> {
    let (kind, password) = match o.get("obfs") {
        Some(Value::Object(ob)) => (text(ob, &["type"]), text(ob, &["password"])),
        Some(Value::String(kind)) => (
            Some(kind.as_str()),
            text(o, &["obfs_password", "obfs-password"]),
        ),
        _ => return Ok(None),
    };
    let kind = kind.map(|k| k.trim().to_ascii_lowercase());
    let Some(kind) = kind.filter(|k| !k.is_empty() && k != "none") else {
        return Ok(None);
    };
    let invalid = |detail: &str| SkipReason::Invalid {
        scheme: "hysteria2".into(),
        detail: detail.into(),
    };
    if !HY2_OBFS_TYPES.contains(&kind.as_str()) {
        return Err(invalid("unknown Hysteria2 obfs type"));
    }
    let password = password.ok_or_else(|| invalid("Hysteria2 obfs without a password"))?;
    Ok(Some(Hy2Obfs {
        kind,
        password: password.to_owned(),
    }))
}

/// `["443", "20000:30000"]`, `"443,20000-30000"` (old comma-joined string) -> inclusive ranges.
/// `None` when any entry is malformed: sing-box would refuse the whole list.
pub(crate) fn port_ranges(v: &Value) -> Option<Vec<(u16, u16)>> {
    let items: Vec<String> = match v {
        Value::Array(a) => a
            .iter()
            .map(|i| match i {
                Value::Number(n) => Some(n.to_string()),
                Value::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect::<Option<_>>()?,
        Value::String(s) => s.split(',').map(str::to_owned).collect(),
        _ => return None,
    };
    items.iter().map(|item| port_range(item)).collect()
}

fn tuic(o: &Map<String, Value>, typed: &mut Vec<&str>) -> Result<Kind, SkipReason> {
    typed.extend([
        "uuid",
        "password",
        "congestion_control",
        "udp_relay_mode",
        "zero_rtt_handshake",
        "heartbeat",
    ]);
    let uuid = text(o, &["uuid"]).ok_or(SkipReason::MissingCredential)?;
    let password = text(o, &["password"]).ok_or(SkipReason::MissingCredential)?;
    let owned = |k: &str| text(o, &[k]).map(str::to_owned);
    Ok(Kind::Tuic {
        uuid: uuid.to_owned(),
        password: password.to_owned(),
        congestion: owned("congestion_control"),
        udp_relay_mode: owned("udp_relay_mode"),
        zero_rtt: flag(o, "zero_rtt_handshake"),
        heartbeat_s: o.get("heartbeat").and_then(duration_secs),
    })
}

fn naive(o: &Map<String, Value>, typed: &mut Vec<&str>, scan: &mut Scan) -> Kind {
    typed.extend([
        "username",
        "password",
        "quic",
        "extra_headers",
        "insecure_concurrency",
    ]);
    let mut extra_headers = Vec::new();
    match o.get("extra_headers") {
        Some(Value::Object(h)) => {
            for (name, value) in h {
                let value = super::values::list(value).join(", ");
                if !value.is_empty() {
                    extra_headers.push((name.clone(), value));
                }
            }
        }
        Some(_) => scan.unsupported("extra_headers"),
        None => {}
    }
    Kind::Naive {
        username: text_or_number(o, &["username"]).unwrap_or_default(),
        password: text_or_number(o, &["password"]).unwrap_or_default(),
        quic: flag(o, "quic"),
        extra_headers,
        insecure_concurrency: o.get("insecure_concurrency").and_then(positive_u32),
    }
}

fn anytls(o: &Map<String, Value>, typed: &mut Vec<&str>) -> Result<Kind, SkipReason> {
    typed.extend([
        "password",
        "idle_session_check_interval",
        "idle_session_timeout",
        "min_idle_session",
        // The Electron app wrote milliseconds under these names (profiles spec P-07).
        "idle_session_check_interval_ms",
        "idle_session_timeout_ms",
    ]);
    let password = text(o, &["password"]).ok_or(SkipReason::MissingCredential)?;
    let secs = |key: &str, ms_key: &str| {
        o.get(key).and_then(duration_secs).or_else(|| {
            let ms = o.get(ms_key).and_then(super::values::number)?;
            duration_secs(&Value::String(format!("{ms}ms")))
        })
    };
    Ok(Kind::Anytls {
        password: password.to_owned(),
        idle_check_s: secs(
            "idle_session_check_interval",
            "idle_session_check_interval_ms",
        ),
        idle_timeout_s: secs("idle_session_timeout", "idle_session_timeout_ms"),
        min_idle: o.get("min_idle_session").and_then(rounded_positive),
    })
}

fn socks(o: &Map<String, Value>, typed: &mut Vec<&str>, scan: &mut Scan) -> Kind {
    typed.extend(["username", "password", "version"]);
    // The model is SOCKS5; an explicit SOCKS4 choice is kept for the emitter.
    if let Some(version) = text_or_number(o, &["version"]).filter(|v| v != "5") {
        scan.extra.insert("version".into(), Value::String(version));
    }
    Kind::Socks {
        username: text_or_number(o, &["username"]),
        password: text_or_number(o, &["password"]),
    }
}
