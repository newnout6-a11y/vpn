//! Xray outbound objects (`protocol` + `settings` + `streamSettings`) -> typed profiles, one per
//! server node and user. VLESS / VMess / Trojan / Shadowsocks keep their Xray graph (`native_xray`)
//! so provider details the model does not cover still reach Xray.
use serde_json::{Map, Value};

use super::singbox::{hy2_obfs, port_ranges};
use super::values::{duration_secs, number, port, rounded_positive, text, text_or_number};
use super::xray_stream::{self, sub};
use crate::common::fields::{parse_host, port_range};
use crate::model::{
    DialPrefs, Host, Hy2Obfs, Kind, NativeEntry, NativeXray, Note, Profile, SkipReason, Source,
};

/// Lower-case model protocol of an Xray `protocol` value (`hysteria` is Xray's Hysteria2).
pub(crate) fn protocol(raw: &Map<String, Value>) -> Option<&'static str> {
    let p = text(raw, &["protocol"])?.trim().to_ascii_lowercase();
    Some(match p.as_str() {
        "vless" => "vless",
        "vmess" => "vmess",
        "trojan" => "trojan",
        "shadowsocks" | "ss" => "shadowsocks",
        "hysteria2" | "hy2" | "hysteria" => "hysteria2",
        "naive" => "naive",
        "anytls" => "anytls",
        "shadowtls" => "shadowtls",
        "tuic" => "tuic",
        _ => return None,
    })
}

/// Where the provider document routes traffic (when it is one), and the document itself.
#[derive(Clone, Copy)]
pub(crate) struct Doc<'a> {
    #[cfg_attr(not(feature = "profiles-native"), allow(dead_code))]
    pub(crate) value: Option<&'a Value>,
    pub(crate) entry: Option<&'a NativeEntry>,
}

/// Profiles of one outbound, named from `name` (already resolved by the caller). With a
/// document entry only the first node/user is built: one provider document is one profile.
pub(crate) fn profiles(
    raw: &Map<String, Value>,
    name: &str,
    doc: Doc<'_>,
) -> Vec<Result<Profile, SkipReason>> {
    let Some(proto) = protocol(raw) else {
        return Vec::new();
    };
    let settings = sub(raw, "settings");
    let mut out = Vec::new();
    for (index, count, list, node, user) in nodes(settings) {
        let name = if count > 1 {
            format!("{name} #{}", index + 1)
        } else {
            name.to_owned()
        };
        let selected = match doc.entry {
            Some(_) => Value::Object(raw.clone()),
            None => narrowed(raw, settings, list, node, user),
        };
        out.push(build(proto, raw, node, user, &selected, name, doc));
        if doc.entry.is_some() {
            break;
        }
    }
    out
}

/// `(user index, users in node, settings list key, node, user)`. The list key is empty for the
/// Xray 26 flat `settings`; the user is the node itself where nodes carry no `users` list.
type Node<'a> = (
    usize,
    usize,
    &'static str,
    &'a Map<String, Value>,
    &'a Map<String, Value>,
);

fn nodes(settings: &Map<String, Value>) -> Vec<Node<'_>> {
    static NO_USER: std::sync::LazyLock<Map<String, Value>> = std::sync::LazyLock::new(Map::new);
    let list = |key: &str| {
        settings
            .get(key)
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_object))
            .into_iter()
            .flatten()
            .filter(|n| n.contains_key("address"))
    };
    let mut out = Vec::new();
    let is_list = |key: &str| settings.get(key).is_some_and(Value::is_array);
    if is_list("vnext") {
        for node in list("vnext") {
            let users: Vec<&Map<String, Value>> = node
                .get("users")
                .and_then(Value::as_array)
                .map(|u| u.iter().filter_map(Value::as_object).collect())
                .unwrap_or_default();
            if users.is_empty() {
                out.push((0, 1, "vnext", node, &*NO_USER));
            }
            for (i, user) in users.iter().enumerate() {
                out.push((i, users.len(), "vnext", node, *user));
            }
        }
    } else if is_list("servers") {
        out.extend(list("servers").map(|node| (0, 1, "servers", node, node)));
    } else if settings.contains_key("address") {
        out.push((0, 1, "", settings, settings));
    }
    out
}

/// `raw` narrowed to one node and one user, so a graph never carries other credentials. Built
/// key by key: copying the whole list once per user would be quadratic in a hostile outbound.
fn narrowed(
    raw: &Map<String, Value>,
    settings: &Map<String, Value>,
    list: &str,
    node: &Map<String, Value>,
    user: &Map<String, Value>,
) -> Value {
    if list.is_empty() {
        return Value::Object(raw.clone());
    }
    let item = match list == "vnext" && node.contains_key("users") {
        true => replaced(
            node,
            "users",
            Value::Array(vec![Value::Object(user.clone())]),
        ),
        false => node.clone(),
    };
    let settings = replaced(settings, list, Value::Array(vec![Value::Object(item)]));
    Value::Object(replaced(raw, "settings", Value::Object(settings)))
}

/// `m` with the value under `key` replaced (the old value is not copied; key order is kept).
fn replaced(m: &Map<String, Value>, key: &str, value: Value) -> Map<String, Value> {
    let mut out: Map<String, Value> = m
        .iter()
        .map(|(k, v)| (k.clone(), if k == key { Value::Null } else { v.clone() }))
        .collect();
    out.insert(key.to_owned(), value);
    out
}

fn build(
    proto: &'static str,
    raw: &Map<String, Value>,
    node: &Map<String, Value>,
    user: &Map<String, Value>,
    selected: &Value,
    name: String,
    doc: Doc<'_>,
) -> Result<Profile, SkipReason> {
    let invalid = |detail: &str| SkipReason::Invalid {
        scheme: proto.to_owned(),
        detail: detail.to_owned(),
    };
    let server: Host = text(node, &["address"])
        .and_then(|h| parse_host(h.trim()))
        .ok_or_else(|| invalid("invalid server address"))?;
    let stream = sub(raw, "streamSettings");
    let mut notes = Vec::new();
    let mut extra = Map::new();
    let password = || text_or_number(node, &["password"]).ok_or(SkipReason::MissingCredential);
    let mut hop_first_port = None;
    let kind = match proto {
        "vless" => Kind::Vless {
            uuid: text_or_number(user, &["id", "uuid"]).ok_or(SkipReason::MissingCredential)?,
            flow: text(user, &["flow"]).map(str::to_owned),
            packet_encoding: None,
            encryption: text(user, &["encryption"])
                .filter(|e| !e.eq_ignore_ascii_case("none"))
                .map(str::to_owned),
        },
        "vmess" => {
            let alter_id = user
                .get("alterId")
                .or_else(|| user.get("alter_id"))
                .and_then(number)
                .unwrap_or(0.0);
            if alter_id != 0.0 {
                notes.push(Note::AlterIdNormalized(
                    alter_id.clamp(0.0, f64::from(u32::MAX)) as u32,
                ));
            }
            Kind::Vmess {
                uuid: text_or_number(user, &["id", "uuid"]).ok_or(SkipReason::MissingCredential)?,
                security: text(user, &["security"]).unwrap_or("auto").to_owned(),
                global_padding: false,
                authenticated_length: false,
            }
        }
        "trojan" => Kind::Trojan {
            password: password()?,
        },
        "shadowsocks" => {
            let method =
                text(node, &["method", "cipher"]).ok_or_else(|| invalid("missing method"))?;
            let password = text_or_number(node, &["password"]).unwrap_or_default();
            if password.is_empty() && method != "none" {
                return Err(SkipReason::MissingCredential);
            }
            let uot = super::values::flag(node, "uot").then(|| {
                node.get("UoTVersion")
                    .and_then(port)
                    .and_then(|v| u8::try_from(v).ok())
                    .unwrap_or(2)
            });
            Kind::Shadowsocks {
                method: method.to_owned(),
                password,
                plugin: None,
                shadowtls: None,
                uot,
            }
        }
        "hysteria2" => {
            let (kind, first) = hysteria2(raw, node, stream, &mut extra, &mut notes)?;
            hop_first_port = first;
            kind
        }
        "naive" => Kind::Naive {
            username: text_or_number(node, &["username", "user"]).unwrap_or_default(),
            password: text_or_number(node, &["password"]).unwrap_or_default(),
            quic: false,
            extra_headers: Vec::new(),
            insecure_concurrency: None,
        },
        "anytls" => Kind::Anytls {
            password: password()?,
            idle_check_s: None,
            idle_timeout_s: None,
            min_idle: None,
        },
        "tuic" => Kind::Tuic {
            uuid: text_or_number(node, &["uuid", "id"]).ok_or(SkipReason::MissingCredential)?,
            password: password()?,
            congestion: text(node, &["congestion_control", "congestionControl"]).map(str::to_owned),
            udp_relay_mode: text(node, &["udp_relay_mode", "udpRelayMode"]).map(str::to_owned),
            zero_rtt: false,
            heartbeat_s: None,
        },
        "shadowtls" => return Err(SkipReason::ShadowTlsNeedsInner),
        _ => return Err(SkipReason::UnknownScheme(proto.to_owned())),
    };
    let port = node
        .get("port")
        .and_then(port)
        .or(hop_first_port)
        .ok_or_else(|| invalid("missing or invalid port"))?;
    let native_xray = match proto {
        "vless" | "vmess" | "trojan" | "shadowsocks" => {
            preserve(selected, doc).map_err(SkipReason::NativeGraphRejected)?
        }
        _ => None,
    };
    let tls = xray_stream::tls(stream).map_err(invalid)?;
    let transport = xray_stream::transport(stream, native_xray.is_some())?;
    // Xray enforces its own pin; anything that runs on sing-box 1.14 cannot (profiles spec P-03).
    if native_xray.is_none() && tls.as_ref().is_some_and(|t| t.cert_pin_sha256.is_some()) {
        notes.push(Note::CertPinNotEnforced);
    }
    Ok(Profile {
        name,
        description: None,
        server,
        port,
        kind,
        tls,
        transport,
        mux: None,
        dial: DialPrefs::default(),
        native_xray,
        singbox_extra: extra,
        source: Source::Json,
        notes,
    })
}

/// Hysteria2 from Xray's `hysteria` protocol (`settings.version: 2`, password in
/// `streamSettings.hysteriaSettings.auth`) or from the generic `servers[]` shape other clients write.
fn hysteria2(
    raw: &Map<String, Value>,
    node: &Map<String, Value>,
    stream: &Map<String, Value>,
    extra: &mut Map<String, Value>,
    notes: &mut Vec<Note>,
) -> Result<(Kind, Option<u16>), SkipReason> {
    let is_xray = text(raw, &["protocol"]).is_some_and(|p| p.eq_ignore_ascii_case("hysteria"));
    if is_xray {
        if node.get("version").and_then(port) != Some(2) {
            return Err(SkipReason::Invalid {
                scheme: "hysteria".into(),
                detail: "only Hysteria version 2 is supported".into(),
            });
        }
        let auth = text_or_number(sub(stream, "hysteriaSettings"), &["auth"])
            .ok_or(SkipReason::MissingCredential)?;
        return Ok((
            finalmask(auth, sub(stream, "finalmask"), extra, notes)?,
            None,
        ));
    }
    let password = text_or_number(node, &["password"]).ok_or(SkipReason::MissingCredential)?;
    let obfs = hy2_obfs(node)?;
    let ports = match ["server_ports", "serverPorts", "mport"]
        .iter()
        .find_map(|k| node.get(*k))
    {
        None => Vec::new(),
        Some(v) => port_ranges(v).unwrap_or_else(|| {
            notes.push(Note::UnsupportedField("server_ports".into()));
            Vec::new()
        }),
    };
    let first = ports.first().map(|r| r.0);
    let rate = |keys: &[&str]| {
        keys.iter()
            .find_map(|k| node.get(*k))
            .and_then(rounded_positive)
    };
    let kind = Kind::Hysteria2 {
        password,
        obfs,
        ports,
        hop_interval_s: ["hop_interval", "hopInterval"]
            .iter()
            .find_map(|k| node.get(*k))
            .and_then(duration_secs),
        hop_interval_max_s: None,
        up_mbps: rate(&["up_mbps", "upMbps", "upmbps"]),
        down_mbps: rate(&["down_mbps", "downMbps", "downmbps"]),
        bbr_profile: None,
    };
    Ok((kind, first))
}

/// Xray 26 Hysteria keeps obfuscation and port hopping in `streamSettings.finalmask`: Salamander
/// (Gecko when it has a `packetSize`) and `quicParams.udpHop` map to sing-box. Every other mask or
/// QUIC knob is a Note: dropped silently, it would leave a profile that cannot reach its server.
fn finalmask(
    password: String,
    mask: &Map<String, Value>,
    extra: &mut Map<String, Value>,
    notes: &mut Vec<Note>,
) -> Result<Kind, SkipReason> {
    let mut note = |path: String| notes.push(Note::UnsupportedField(path));
    let mut obfs = None;
    for layer in mask
        .get("udp")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let mask_type = layer
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let settings = layer.get("settings").and_then(Value::as_object);
        let (Some(settings), "salamander", None) = (settings, mask_type, &obfs) else {
            note(format!("finalmask.udp.{mask_type}"));
            continue;
        };
        // Gecko's fragment size is an Int32Range (`512-1200`); sing-box takes the two bounds.
        let kind = match text(settings, &["packetSize"]).map(port_range) {
            None => "salamander",
            Some(Some((min, max))) => {
                extra.insert("obfs.min_packet_size".into(), min.into());
                extra.insert("obfs.max_packet_size".into(), max.into());
                "gecko"
            }
            Some(None) => {
                note("finalmask.udp.salamander.packetSize".into());
                continue;
            }
        };
        let password = text(settings, &["password"]).ok_or_else(|| SkipReason::Invalid {
            scheme: "hysteria".into(),
            detail: "Hysteria2 obfs without a password".into(),
        })?;
        obfs = Some(Hy2Obfs {
            kind: kind.into(),
            password: password.to_owned(),
        });
    }
    let quic = sub(mask, "quicParams");
    let hop = sub(quic, "udpHop");
    let ports = hop.get("ports").map(port_ranges);
    // `interval`: seconds, or a random range `5-10` = sing-box `hop_interval` .. `hop_interval_max`.
    let interval = hop.get("interval").map(|v| match v {
        Value::String(s) => port_range(s),
        _ => port(v).map(|s| (s, s)),
    });
    for (path, bad) in [
        ("ports", matches!(ports, Some(None))),
        ("interval", matches!(interval, Some(None))),
    ] {
        if bad {
            note(format!("finalmask.quicParams.udpHop.{path}"));
        }
    }
    let known = ["udp", "quicParams"];
    for key in mask.keys().filter(|k| !known.contains(&k.as_str())) {
        note(format!("finalmask.{key}"));
    }
    // Brutal as Xray's client runs it (`transport/internet/hysteria/dialer.go`): `brutalDown` is
    // always announced to the server (sing-box `down_mbps`); `brutalUp` paces the upload under
    // the default / `brutal` / `force-brutal` congestion (sing-box `up_mbps`), never under `bbr`.
    // sing-box has no Reno: BBR runs instead (noted).
    let congestion = text(quic, &["congestion"]).map(str::to_ascii_lowercase);
    let up_applies = match congestion.as_deref() {
        None | Some("" | "brutal" | "force-brutal") => true,
        Some("bbr") => false,
        Some(_) => {
            note("finalmask.quicParams.congestion".into());
            false
        }
    };
    let mut rate = |key: &str| {
        let raw = quic.get(key)?;
        let mbps = raw.as_str().and_then(xray_mbps);
        if mbps.is_none() {
            note(format!("finalmask.quicParams.{key}"));
        }
        mbps
    };
    let up_mbps = rate("brutalUp").filter(|_| up_applies);
    let down_mbps = rate("brutalDown");
    let handled = [
        "udpHop",
        "bbrProfile",
        "congestion",
        "brutalUp",
        "brutalDown",
    ];
    for key in quic.keys().filter(|k| !handled.contains(&k.as_str())) {
        note(format!("finalmask.quicParams.{key}"));
    }
    let (hop_min, hop_max) = interval.flatten().unzip();
    Ok(Kind::Hysteria2 {
        password,
        obfs,
        ports: ports.flatten().unwrap_or_default(),
        hop_interval_s: hop_min.map(u32::from),
        hop_interval_max_s: hop_max.filter(|max| Some(*max) != hop_min).map(u32::from),
        up_mbps,
        down_mbps,
        bbr_profile: text(quic, &["bbrProfile"]).map(str::to_owned),
    })
}

/// Xray `Bandwidth` (`infra/conf/transport_method.go`) in sing-box Mbps (10^6 bit/s, at least
/// 1): case-insensitive, always bits, binary multiples (`100 mbps` = 100 * 2^20 bit/s); `0` or
/// empty is unset.
fn xray_mbps(raw: &str) -> Option<u32> {
    let s = raw.trim().to_ascii_lowercase();
    let split = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let value: f64 = s[..split].parse().ok()?;
    let power = match s[split..].trim() {
        "" | "b" | "bps" => 0,
        "k" | "kb" | "kbps" => 1,
        "m" | "mb" | "mbps" => 2,
        "g" | "gb" | "gbps" => 3,
        "t" | "tb" | "tbps" => 4,
        _ => return None,
    };
    let mbps = (value * 1024f64.powi(power) / 1e6).round().max(1.0);
    (value > 0.0 && mbps <= f64::from(u32::MAX)).then_some(mbps as u32)
}

/// The provider graph for this outbound (validated by `xray_native`).
#[cfg(feature = "profiles-native")]
fn preserve(selected: &Value, doc: Doc<'_>) -> Result<Option<NativeXray>, String> {
    crate::xray_native::preserve(selected, doc.value, doc.entry.cloned())
        .map(Some)
        .map_err(|e| e.to_string())
}

/// Without the `profiles-native` package the typed profile is all there is.
#[cfg(not(feature = "profiles-native"))]
fn preserve(_selected: &Value, _doc: Doc<'_>) -> Result<Option<NativeXray>, String> {
    Ok(None)
}
