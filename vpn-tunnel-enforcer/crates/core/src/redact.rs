//! The one redaction policy of the app (storage spec §6.4, B4/B6): secrets in free text, secret
//! keys in JSON documents, and pseudonyms for public IP addresses.
//!
//! Every log line, engine log line and diagnostics export passes through here. The rules fail
//! closed: a value that only looks like a secret is masked too. Masks are typed
//! (`<redacted-key>`, `<redacted-uuid>`, ...) so support can tell what was removed.
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use hmac::{Hmac, KeyInit, Mac};
use parking_lot::RwLock;
use regex::{Captures, Regex};
use serde_json::Value;
use sha2::Sha256;

/// Replacement for a value stored under a secret key or field name.
pub const REDACTED: &str = "<redacted>";

const CREDENTIAL: &str = "<redacted-credential>";
const KEY: &str = "<redacted-key>";

fn re(pattern: &str) -> Regex {
    // Patterns are compile-time constants; every one is exercised by the tests.
    Regex::new(pattern).expect("redaction pattern compiles")
}

/// VPN share links and client deep links (`sing-box://import-remote-profile?url=…` carries a
/// subscription URL, which is a secret even when percent-encoded): every scheme the importers
/// accept, and more. URL rules run to whitespace, `"`, `<`, `>` or a backtick, not to `'`:
/// a Trojan or proxy password may contain one unencoded.
static VPN_URI: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r"(?i)\b(?:vless|vmess|trojan|ssr?|hysteria2?|hy2|naive(?:\+https|\+quic)?|anytls|",
        r"shadowtls|tuic|wg|wireguard|awg|happ|mantaray|v2raytun|incy|sing-box|clash|hiddify)",
        r#"://[^\s"<>`]+"#,
    ))
});
static PROXY_URL: LazyLock<Regex> = LazyLock::new(|| re(r#"(?i)\bsocks(?:4a?|5h?)?://[^\s"<>`]+"#));
static HTTP_URL: LazyLock<Regex> = LazyLock::new(|| re(r#"(?i)\bhttps?://[^\s"<>`]{8,}"#));
/// `key = value`, `key: "value"`, JSON `"key":"value"` (the old rule missed the quote between
/// key and separator, B4) and the same JSON inside a string, as `?value` prints it in a log field
/// (`\"key\":\"value\"`). Group 1 is kept, group 2 is the masked value.
static CREDENTIAL_KV: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r#"(?i)\b((?:[a-z0-9]+[_-])*"#,
        r"(?:password|passwd|passphrase|token|secret|private[_-]?key|public[_-]?key|",
        r"pre[_-]?shared[_-]?key|psk|api[_-]?key|auth[_-]?str|uuid|short[_-]?id|pbk|sid|hwid|",
        r#"authorization)(?:\\?["'])?\s*[:=]\s*)("#,
        r#"\\"(?:[^"\\\r\n]|\\[^"\r\n])*\\"|"(?:[^"\\\r\n]|\\.)*"|'[^'\r\n]*'|"#,
        r#"(?:basic|bearer|digest|negotiate)\s+[^\s,;"'\\]+|[^\s,;]+)"#,
    ))
});
/// 32- and 64-byte keys in base64 (padded). The `regex` crate has no lookbehind, so the left
/// boundary is captured and re-emitted: `\b` never matched before a key starting with `+` or `/`
/// (B4). `=` counts as a boundary (`key=<key>`): the spec's class left it out, a regression
/// against the old `\b` for keys starting with a letter.
static B64_KEY_PADDED: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|[^A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{43}=|[A-Za-z0-9+/_-]{86}==)"));
/// Unpadded 32-byte keys (REALITY public keys are printed as 43 chars of base64url). The
/// character mix is checked in code: a maximal run of exactly 43 chars with digits and both cases.
static B64_KEY_BARE: LazyLock<Regex> =
    LazyLock::new(|| re(r"(^|[^A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{43,})"));
static BEARER: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\bBearer\s+[a-z0-9._~+/=-]+"));
static RESOLVE_HOST: LazyLock<Regex> = LazyLock::new(|| {
    re(r#"(?i)\b(Could not resolve host|No such host is known|resolve host):\s*[^\s"'<>]+"#)
});
/// `[\\/]+` also catches JSON-escaped paths (`C:\\Users\\name`). Runs through `'` (O'Brien) to
/// the end of the line or a `"`: the user name is the secret here.
static WIN_USER_PATH: LazyLock<Regex> =
    LazyLock::new(|| re(r#"(?i)\b[a-z]:[\\/]+(?:Users|Documents and Settings)[\\/]+[^\r\n"<>]+"#));
static POSIX_USER_PATH: LazyLock<Regex> =
    LazyLock::new(|| re(r#"/(?:home|Users)/[^\s/"<>]+(?:/[^\r\n"<>]*)?"#));
/// Any UUID version (the old rule only knew v1-v5, so v6-v8 user ids leaked, B4). No `\b`: a
/// UUID glued to a word character (`profile_<uuid>.json`) is still one.
static UUID: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"));
static MAC: LazyLock<Regex> = LazyLock::new(|| re(r"(?i)\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b"));
/// IPv6 candidates (validated by parsing) or IPv4 dotted quads.
static IP_CANDIDATE: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r"(?i)(?:[0-9a-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{1,4})?(?:%[0-9a-z_.-]+)?",
        r"|(?:\d{1,3}\.){3}\d{1,3}",
    ))
});
/// Secret field names (logging, §6.5) and the base of the JSON key rule (§2.9).
static SECRET_NAME: LazyLock<Regex> = LazyLock::new(|| {
    re(concat!(
        r"(?i)uuid|password|passwd|passphrase|token|secret|private[_-]?key|public[_-]?key|",
        r"pre[_-]?shared|short[_-]?id|auth|credential|cookie|headers|api[_-]?key|hwid|",
        r"^pbk$|^sid$|^psk$",
    ))
});
/// Exact (lowercased) JSON keys that are secret on top of [`SECRET_NAME`]: the §2.9 list plus
/// proxy credentials (`user` / `pass` in Xray socks/http users, `username` in sing-box).
const SECRET_KEYS: &[&str] = &[
    "uuid",
    "password",
    "pass",
    "user",
    "username",
    "id",
    "address",
    "server",
    "server_port",
    "private_key",
    "public_key",
    "short_id",
    "client_secret",
    "token",
    "auth_str",
    "directvpninput",
    "vpninput",
    "subscription",
    "subscriptionurl",
    "up_mbps",
    "down_mbps",
];
/// The legacy native Xray config field of a profile: always a full server config.
const NATIVE_XRAY_FIELD: &str = "vpnte_xray";

/// Masks secrets in free text: share links and URLs, credential assignments (quoted or not),
/// base64 keys, bearer tokens, host names in resolver errors, user profile paths, UUIDs and MACs.
pub fn text(s: &str) -> Cow<'_, str> {
    let mut out = Cow::Borrowed(s);
    out = apply(out, |t| VPN_URI.replace_all(t, "<redacted-vpn-uri>"));
    out = apply(out, |t| PROXY_URL.replace_all(t, "<redacted-proxy-url>"));
    out = apply(out, |t| HTTP_URL.replace_all(t, "<redacted-url>"));
    out = apply(out, |t| CREDENTIAL_KV.replace_all(t, mask_credential));
    out = apply(out, |t| B64_KEY_PADDED.replace_all(t, "${1}<redacted-key>"));
    out = apply(out, |t| B64_KEY_BARE.replace_all(t, mask_bare_key));
    out = apply(out, |t| BEARER.replace_all(t, "Bearer <redacted-token>"));
    out = apply(out, |t| {
        RESOLVE_HOST.replace_all(t, "${1}: <redacted-host>")
    });
    out = apply(out, |t| {
        WIN_USER_PATH.replace_all(t, "<redacted-user-path>")
    });
    out = apply(out, |t| {
        POSIX_USER_PATH.replace_all(t, "<redacted-user-path>")
    });
    out = apply(out, |t| UUID.replace_all(t, "<redacted-uuid>"));
    apply(out, |t| MAC.replace_all(t, "<redacted-mac>"))
}

/// Free text as it may appear in a log: [`text`], then public IP addresses as pseudonyms.
pub fn for_log(s: &str) -> Cow<'_, str> {
    apply(text(s), ips)
}

/// Redacts a JSON document in place: values under secret keys become `"<redacted>"` whatever
/// their type, every other string goes through [`text`].
pub fn json(v: &mut Value) {
    match v {
        Value::String(s) => {
            if let Cow::Owned(r) = text(s) {
                *s = r;
            }
        }
        Value::Array(items) => items.iter_mut().for_each(json),
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                if is_secret_key(key) {
                    *value = Value::String(REDACTED.to_owned());
                } else {
                    json(value);
                }
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// JSON key rule (§2.9): the exact key list, the name pattern, `^id$` and the native Xray field.
pub fn is_secret_key(key: &str) -> bool {
    key == NATIVE_XRAY_FIELD
        || key.eq_ignore_ascii_case("id")
        || SECRET_KEYS.iter().any(|k| key.eq_ignore_ascii_case(k))
        || SECRET_NAME.is_match(key)
}

/// Log field-name rule (§6.5): a field with such a name is replaced whole by `<redacted>`.
pub fn is_secret_field(name: &str) -> bool {
    SECRET_NAME.is_match(name)
}

/// Runs one replacement step, keeping the borrowed input when nothing matched.
fn apply<'a>(cur: Cow<'a, str>, step: impl for<'t> Fn(&'t str) -> Cow<'t, str>) -> Cow<'a, str> {
    let replaced = match step(&cur) {
        Cow::Owned(s) => Some(s),
        Cow::Borrowed(_) => None,
    };
    replaced.map_or(cur, Cow::Owned)
}

/// Keeps the key and separator, masks the value in its own quoting so JSON text stays valid.
fn mask_credential(c: &Captures) -> String {
    let quote = ["\\\"", "\"", "'"]
        .into_iter()
        .find(|q| c[2].starts_with(q))
        .unwrap_or_default();
    format!("{}{quote}{CREDENTIAL}{quote}", &c[1])
}

fn mask_bare_key(c: &Captures) -> String {
    let (lead, token) = (&c[1], &c[2]);
    let mixed = token.bytes().any(|b| b.is_ascii_digit())
        && token.bytes().any(|b| b.is_ascii_uppercase())
        && token.bytes().any(|b| b.is_ascii_lowercase());
    if token.len() == 43 && mixed {
        format!("{lead}{KEY}")
    } else {
        c[0].to_owned()
    }
}

type HmacSha256 = Hmac<Sha256>;

/// Pseudonym key. Until the app installs the per-install key from settings, a per-process random
/// key is used (pseudonyms are then stable only within this run).
static IP_KEY: LazyLock<RwLock<HmacSha256>> = LazyLock::new(|| {
    let mut key = [0u8; 32];
    if getrandom::fill(&mut key).is_err() {
        key.iter_mut().for_each(|b| *b = fastrand::u8(..));
    }
    RwLock::new(keyed(&key))
});

fn keyed(key: &[u8; 32]) -> HmacSha256 {
    // HMAC accepts keys of any length; this cannot fail.
    HmacSha256::new_from_slice(key).expect("HMAC key of any length")
}

/// Installs the stable per-install pseudonym key (`logKey` in settings).
pub fn set_ip_key(key: &[u8; 32]) {
    *IP_KEY.write() = keyed(key);
}

/// Public address → `ip_` + first 8 hex of HMAC-SHA256(key, octets). Private, loopback, CGNAT,
/// link-local, ULA, multicast and the sing-box fake-ip pools are not personal and stay readable.
pub fn ip_pseudonym(ip: IpAddr) -> String {
    let ip = ip.to_canonical();
    if is_kept(ip) {
        return ip.to_string();
    }
    let mut mac = IP_KEY.read().clone();
    match ip {
        IpAddr::V4(v4) => mac.update(&v4.octets()),
        IpAddr::V6(v6) => mac.update(&v6.octets()),
    }
    let digest = mac.finalize().into_bytes();
    format!("ip_{}", hex::encode(&digest[..4]))
}

/// Replaces public IPv4/IPv6 addresses in free text by [`ip_pseudonym`]s.
pub fn ips(s: &str) -> Cow<'_, str> {
    IP_CANDIDATE.replace_all(s, |c: &Captures| {
        let Some(m) = c.get(0) else {
            return String::new();
        };
        let before = s[..m.start()].chars().next_back();
        let mut rest = s[m.end()..].chars();
        let (after, after2) = (rest.next(), rest.next());
        let word = |ch: char| ch.is_ascii_alphanumeric() || ch == '_';
        // A candidate glued to a longer token is not an address: `vpnte_base::error` holds the
        // valid IPv6 `e::`, `AB:CD:…` fingerprints run past 8 groups, `1.2.3.4.5` is a version.
        let glued = if m.as_str().contains(':') {
            before.is_some_and(|c| word(c) || c == ':' || c == '.')
                || after.is_some_and(|c| word(c) || c == ':')
        } else {
            before.is_some_and(|c| word(c) || c == '.')
                || after.is_some_and(word)
                || (after == Some('.') && after2.is_some_and(|c| c.is_ascii_digit()))
        };
        if glued {
            return m.as_str().to_owned();
        }
        let addr = m.as_str().split('%').next().unwrap_or_default();
        match addr.parse::<IpAddr>() {
            // Kept addresses stay byte-for-byte (zone index, spelling).
            Ok(ip) if !is_kept(ip.to_canonical()) => ip_pseudonym(ip),
            _ => m.as_str().to_owned(),
        }
    })
}

fn is_kept(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_kept_v4(v4),
        IpAddr::V6(v6) => is_kept_v6(v6),
    }
}

fn is_kept_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    a == 0
        || ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || (a == 100 && (b & 0xc0) == 64) // 100.64.0.0/10 CGNAT
        || (a == 198 && (b & 0xfe) == 18) // 198.18.0.0/15: sing-box fake-ip pool
        || ip.is_multicast()
        || a >= 240 // reserved and broadcast
}

fn is_kept_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00 // fc00::/7 ULA: TUN address, fake-ip fc00::/18
        || (first & 0xffc0) == 0xfe80 // link-local
}

#[cfg(test)]
mod tests;
