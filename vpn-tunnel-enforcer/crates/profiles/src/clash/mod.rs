//! Clash / mihomo YAML importer: the root `proxies` list mapped to typed profiles.
//!
//! Field names follow the mihomo wiki (`wiki.metacubex.one/en/config/proxies/`, checked
//! 2026-11-11). Fixes over the old reader (P-23): column-0 list items, block sequences and
//! quoted / leading-zero scalars work; `trojan`, `hysteria2`, `tuic`, `anytls` are always TLS
//! (mihomo has no `tls` key for them); `servername` alone never turns TLS on; `fingerprint` is a
//! certificate pin, not a uTLS name (P-03); `udp` and VLESS `encryption: none` never reach the
//! profile (P-06). A broken entry is reported in `skipped` and never stops the others.
use std::cell::Cell;

use serde_json::{Map, Value};

use crate::common::fields::{clean_name, display_name, parse_host, parse_port, reality_conflict};
use crate::model::{
    DialPrefs, Host, Kind, Mux, Note, ParseReport, Profile, SkipReason, Skipped, Source, Tls,
};

mod kinds;
mod providers;
mod tls;
mod yaml;

#[cfg(test)]
mod check;
#[cfg(test)]
mod tests;

pub use providers::{HttpProvider, MAX_PROVIDERS, http_providers};
use yaml::Node;

/// Entries read from one document; the text pipeline caps a whole paste at the same number.
const MAX_PROXIES: usize = 5000;
/// Keys mihomo uses that have no sing-box counterpart and change nothing for us.
const IGNORED_KEYS: &[&str] = &["udp", "remote-dns-resolve"];

/// `None` when the text is not a Clash document.
pub fn parse_clash(text: &str) -> Option<ParseReport> {
    // Cheap gate before any YAML work: a root `proxies:` key must start some line.
    let gate = text.lines().any(|line| {
        line.trim_start()
            .strip_prefix("proxies")
            .is_some_and(|rest| rest.trim_start().starts_with(':'))
    });
    if !gate {
        return None;
    }
    let mut report = ParseReport::default();
    let mut index = 0usize;
    let mut truncated = false;
    let outcome = yaml::read_proxies(text, |item| {
        index += 1;
        if index > MAX_PROXIES {
            truncated = true;
            return false;
        }
        match proxy(&item) {
            Ok(profile) => report.profiles.push(profile),
            Err(reason) => report.skipped.push(Skipped {
                excerpt: excerpt(&item, index),
                reason,
            }),
        }
        true
    });
    if !outcome.found {
        return None;
    }
    let stopped = match outcome.error {
        Some(error) => Some(error.to_string()),
        None => {
            truncated.then(|| format!("more than {MAX_PROXIES} entries: the rest were not read"))
        }
    };
    if let Some(detail) = stopped {
        tracing::debug!(%detail, "clash: proxies list not read to the end");
        report.skipped.push(Skipped {
            excerpt: "proxies".to_owned(),
            reason: invalid(detail),
        });
    }
    Some(report)
}

/// The mihomo proxy types we can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Proto {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Hysteria2,
    Tuic,
    Anytls,
    Wireguard,
    Socks,
    Http,
}

impl Proto {
    fn from_type(ty: &str) -> Option<Self> {
        Some(match ty {
            "vless" => Proto::Vless,
            "vmess" => Proto::Vmess,
            "trojan" => Proto::Trojan,
            "ss" | "shadowsocks" => Proto::Shadowsocks,
            "hysteria2" | "hy2" => Proto::Hysteria2,
            "tuic" => Proto::Tuic,
            "anytls" => Proto::Anytls,
            "wireguard" | "wg" => Proto::Wireguard,
            "socks5" | "socks" => Proto::Socks,
            "http" => Proto::Http,
            _ => return None,
        })
    }

    /// QUIC protocols: uTLS does not apply and breaks every dial on sing-box (§2.20).
    fn is_quic(self) -> bool {
        matches!(self, Proto::Hysteria2 | Proto::Tuic)
    }
}

/// How an entry's TLS is decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsMode {
    /// TLS is part of the protocol (`sni` defaults to `server`).
    Always,
    /// On only with `tls: true` or `reality-opts`.
    Optional,
    Never,
}

/// Fields the type readers fill besides the protocol kind.
struct Draft {
    /// `None` only for a WireGuard entry that lists its servers under `peers`.
    server: Option<Host>,
    port: Option<u16>,
    tls: Option<Tls>,
    notes: Vec<Note>,
    extra: Map<String, Value>,
}

fn proxy(item: &Node) -> Result<Profile, SkipReason> {
    let pairs = item
        .as_map()
        .ok_or_else(|| invalid("entry is not a mapping"))?;
    let obj = Obj::new(pairs);
    let ty = obj
        .str("type")
        .map(|t| t.trim().to_ascii_lowercase())
        .ok_or_else(|| invalid("entry without type"))?;
    let proto = Proto::from_type(&ty).ok_or_else(|| SkipReason::UnknownScheme(ty.clone()))?;
    let name = clean_name(obj.str("name").unwrap_or_default());
    let server = match obj.str("server") {
        Some(raw) => {
            Some(parse_host(raw.trim()).ok_or_else(|| invalid(format!("{ty}: invalid server")))?)
        }
        None if proto == Proto::Wireguard => None,
        None => return Err(invalid(format!("{ty}: missing server"))),
    };
    let port = match obj.str("port") {
        Some(raw) => {
            Some(parse_port(raw.trim()).ok_or_else(|| invalid(format!("{ty}: invalid port")))?)
        }
        None => None,
    };
    let mut draft = Draft {
        server,
        port,
        tls: None,
        notes: Vec::new(),
        extra: Map::new(),
    };

    let mode = match proto {
        Proto::Trojan | Proto::Hysteria2 | Proto::Tuic | Proto::Anytls => TlsMode::Always,
        Proto::Vless | Proto::Vmess | Proto::Socks | Proto::Http => TlsMode::Optional,
        Proto::Shadowsocks | Proto::Wireguard => TlsMode::Never,
    };
    draft.tls = tls::read_tls(&obj, draft.server.as_ref(), mode, &mut draft.notes)?;
    if proto.is_quic()
        && let Some(tls) = draft.tls.as_mut()
        && tls.fingerprint.take().is_some()
    {
        draft.notes.push(Note::ProviderFpDroppedOnQuic);
    }
    let transport = tls::read_transport(&obj, proto, &mut draft.notes)?;
    let kind = kinds::read_kind(proto, &obj, &mut draft)?;
    let server = draft
        .server
        .take()
        .ok_or_else(|| invalid(format!("{ty}: missing server")))?;
    let port = draft
        .port
        .ok_or_else(|| invalid(format!("{ty}: missing port")))?;
    let dial = read_dial(&obj, &mut draft.notes);
    // sing-box multiplexes only these; elsewhere `smux` stays unread and becomes a Note.
    let mux = match proto {
        Proto::Vless | Proto::Vmess | Proto::Trojan | Proto::Shadowsocks => {
            read_mux(&obj, &mut draft.extra)
        }
        _ => None,
    };
    let plaintext = match &kind {
        Kind::Socks { .. } | Kind::Http { .. } => draft.tls.is_none(),
        Kind::Shadowsocks { method, .. } => method == "none",
        _ => false,
    };
    if plaintext {
        draft.notes.push(Note::Unencrypted);
    }
    for key in obj.unread() {
        if !IGNORED_KEYS.contains(&key) {
            draft.notes.push(Note::UnsupportedField(key.to_owned()));
        }
    }
    let profile = Profile {
        name: if name.is_empty() {
            display_name(kind.label()).to_owned()
        } else {
            name
        },
        description: None,
        server,
        port,
        kind,
        tls: draft.tls,
        transport,
        mux,
        dial,
        native_xray: None,
        singbox_extra: draft.extra,
        source: Source::Clash,
        notes: draft.notes,
    };
    match reality_conflict(&profile) {
        Some(detail) => Err(invalid(format!("{ty}: {detail}"))),
        None => Ok(profile),
    }
}

/// One proxy mapping that remembers which keys were read: the rest become `UnsupportedField`.
struct Obj<'n> {
    pairs: &'n [(String, Node)],
    read: Vec<Cell<bool>>,
}

impl<'n> Obj<'n> {
    fn new(pairs: &'n [(String, Node)]) -> Self {
        Self {
            pairs,
            read: vec![Cell::new(false); pairs.len()],
        }
    }

    /// The value of `key`, marked as read.
    fn node(&self, key: &str) -> Option<&'n Node> {
        let i = self.pairs.iter().position(|(k, _)| k == key)?;
        self.read[i].set(true);
        Some(&self.pairs[i].1)
    }

    fn str(&self, key: &str) -> Option<&'n str> {
        self.node(key).and_then(Node::as_str)
    }

    /// First non-empty value among aliases; every alias present is marked as read.
    fn first_str(&self, keys: &[&str]) -> Option<&'n str> {
        let mut first = None;
        for key in keys {
            if let Some(value) = self.str(key) {
                first.get_or_insert(value);
            }
        }
        first
    }

    fn bool(&self, key: &str) -> Option<bool> {
        self.node(key).and_then(Node::as_bool)
    }

    fn list(&self, key: &str) -> Vec<String> {
        self.node(key).map(Node::as_list).unwrap_or_default()
    }

    /// Keys present but never read.
    fn unread(&self) -> impl Iterator<Item = &'n str> + '_ {
        self.pairs
            .iter()
            .zip(&self.read)
            .filter(|(_, r)| !r.get())
            .map(|((k, _), _)| k.as_str())
    }
}

fn read_dial(obj: &Obj, notes: &mut Vec<Note>) -> DialPrefs {
    let dns_strategy = obj
        .str("ip-version")
        .and_then(|v| match v.to_ascii_lowercase().as_str() {
            "ipv4" => Some("ipv4_only"),
            "ipv6" => Some("ipv6_only"),
            "ipv4-prefer" => Some("prefer_ipv4"),
            "ipv6-prefer" => Some("prefer_ipv6"),
            _ => None,
        });
    // Binding to an interface or chaining through another Clash proxy cannot be reproduced.
    for key in ["interface-name", "routing-mark", "dialer-proxy"] {
        if obj.node(key).is_some_and(|n| !n.is_null()) {
            notes.push(Note::DialFieldDropped(key.to_owned()));
        }
    }
    DialPrefs {
        tcp_fast_open: obj.bool("tfo").unwrap_or(false),
        tcp_multi_path: obj.bool("mptcp").unwrap_or(false),
        dns_strategy: dns_strategy.map(str::to_owned),
        ..DialPrefs::default()
    }
}

/// mihomo `smux` is sing-mux, i.e. sing-box `multiplex` (K15: padding and brutal survive).
fn read_mux(obj: &Obj, extra: &mut Map<String, Value>) -> Option<Mux> {
    let smux = obj.node("smux")?;
    if smux.get("enabled").and_then(Node::as_bool) != Some(true) {
        return None;
    }
    let num = |key: &str| {
        smux.get(key)
            .and_then(Node::as_str)
            .and_then(parse_u32)
            .filter(|&n| n > 0)
    };
    for (key, singbox_key) in [
        ("min-streams", "multiplex.min_streams"),
        ("max-streams", "multiplex.max_streams"),
    ] {
        if let Some(n) = num(key) {
            extra.insert(singbox_key.to_owned(), n.into());
        }
    }
    let brutal = smux
        .get("brutal-opts")
        .filter(|b| b.get("enabled").and_then(Node::as_bool) == Some(true))
        .and_then(|b| {
            Some((
                parse_mbps(b.get("up")?.as_str()?)?,
                parse_mbps(b.get("down")?.as_str()?)?,
            ))
        });
    Some(Mux {
        enabled: true,
        protocol: smux
            .get("protocol")
            .and_then(Node::as_str)
            .map(str::to_ascii_lowercase),
        max_connections: num("max-connections"),
        padding: smux.get("padding").and_then(Node::as_bool).unwrap_or(false),
        brutal,
    })
}

/// A malformed Clash entry; `detail` is an English diagnostic.
fn invalid(detail: impl Into<String>) -> SkipReason {
    SkipReason::Invalid {
        scheme: "clash".to_owned(),
        detail: detail.into(),
    }
}

/// Excerpt shown next to a skipped entry: its name and type, never credentials.
fn excerpt(item: &Node, index: usize) -> String {
    let ty = item.get("type").and_then(Node::as_str).unwrap_or("?");
    let text = match item.get("name").and_then(Node::as_str) {
        Some(name) => format!("{} ({ty})", clean_name(name)),
        None => format!("#{index} ({ty})"),
    };
    text.chars().take(80).collect()
}

/// Decimal digits only (`0x1BB`, `1e3`, `443.0` are rejected).
pub(crate) fn parse_u32(raw: &str) -> Option<u32> {
    let raw = raw.trim();
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

/// mihomo bandwidth (`30`, `"30 Mbps"`, `"100 MBps"`, `"512 Kbps"`) in whole Mbps; a bare
/// number is Mbps, `B` means bytes and `b` bits, K/M/G/T are powers of 1024 (mihomo's own
/// conversion). Positive results below 1 round up to 1 so a tiny limit is not read as "unset".
fn parse_mbps(raw: &str) -> Option<u32> {
    let raw = raw.trim();
    if let Some(n) = parse_u32(raw) {
        return (n > 0).then_some(n);
    }
    let digits = raw.find(|c: char| !c.is_ascii_digit()).unwrap_or(raw.len());
    let value = f64::from(parse_u32(&raw[..digits])?);
    let unit = raw[digits..].trim();
    let unit = unit
        .strip_suffix("ps")
        .or_else(|| unit.strip_suffix("PS"))?;
    let (prefix, bits) = match unit.char_indices().last()? {
        (i, 'b') => (&unit[..i], true),
        (i, 'B') => (&unit[..i], false),
        _ => return None,
    };
    let scale = match prefix.to_ascii_uppercase().as_str() {
        "" => 1.0 / 1_048_576.0,
        "K" => 1.0 / 1024.0,
        "M" => 1.0,
        "G" => 1024.0,
        "T" => 1_048_576.0,
        _ => return None,
    };
    let mbps = value * scale * if bits { 1.0 } else { 8.0 };
    (mbps > 0.0).then(|| mbps.round().clamp(1.0, f64::from(u32::MAX)) as u32)
}
