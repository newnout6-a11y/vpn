//! Sanitising a check before it is stored or returned (live-probe §2.6 as amended by B-33): free
//! text only — errors, notes, details, headers, certificate text, message arguments, evidence
//! strings — never ids, our own constants or numbers. Runs once, on write.
use std::sync::LazyLock;

use regex::Regex;
use vpnte_base::Msg;
use vpnte_core::redact;

use super::model::LiveCheck;
use crate::live_stages::Text;

/// VLESS / VMess user ids show up in engine errors (old wording of the mask kept).
static UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        .expect("static regex")
});
/// Evidence keys that may only ever carry secrets (a guard for future rules).
static SECRET_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)uuid|secret|password|key|short.?id|token|uri|auth|cookie|header")
        .expect("static regex")
});

/// UUIDs → `[REDACTED_UUID]`, then the app-wide free-text redaction.
pub(crate) fn clean(text: &str) -> String {
    let text = UUID.replace_all(text, "[REDACTED_UUID]");
    redact::text(&text).into_owned()
}

fn clean_opt(value: &mut Option<String>) {
    if let Some(v) = value {
        *v = clean(v);
    }
}

fn clean_msg(msg: &mut Msg) {
    for (name, value) in &mut msg.args {
        *value = if name == "location" {
            location(value)
        } else {
            clean(value)
        };
    }
}

fn clean_text(text: &mut Text) {
    match text {
        Text::Msg(msg) => clean_msg(msg),
        Text::Legacy(s) => *s = clean(s),
    }
}

fn clean_text_opt(text: &mut Option<Text>) {
    if let Some(t) = text {
        clean_text(t);
    }
}

/// A redirect target reduced to `scheme://host[:port]` + the decoded path, redacted: query,
/// fragment and userinfo carry tokens and are dropped.
pub(crate) fn location(raw: &str) -> String {
    match url::Url::parse(raw.trim()) {
        Ok(u) if matches!(u.scheme(), "http" | "https") => {
            let host = u.host_str().unwrap_or_default();
            let port = u.port().map(|p| format!(":{p}")).unwrap_or_default();
            let path = percent_decode(u.path());
            format!("{}://{}", u.scheme(), clean(&format!("{host}{port}{path}")))
        }
        _ => {
            let cut = raw.find(['?', '#']).unwrap_or(raw.len());
            clean(&percent_decode(&raw[..cut]))
        }
    }
}

/// `%XX` decoding (invalid escapes kept as they are; bytes decoded lossily as UTF-8).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Redacts the free text of `check` in place (ids, hosts, numbers and our constants untouched).
pub fn sanitize(check: &mut LiveCheck) {
    let dns = &mut check.dns;
    clean_opt(&mut dns.timed.error);
    dns.discrepancies.iter_mut().for_each(clean_text);
    for r in &mut dns.resolvers {
        clean_opt(&mut r.error);
    }
    clean_opt(&mut check.reachability.timed.error);
    if let Some(tls) = &mut check.tls {
        clean_opt(&mut tls.timed.error);
        clean_opt(&mut tls.authorization_error);
        clean_opt(&mut tls.subject);
        clean_opt(&mut tls.issuer);
        for san in &mut tls.sans {
            *san = clean(san);
        }
    }
    if let Some(http) = &mut check.http {
        clean_opt(&mut http.timed.error);
        clean_opt(&mut http.server_header);
        clean_opt(&mut http.via_header);
        clean_opt(&mut http.content_type);
        if let Some(loc) = &mut http.location_header {
            *loc = location(loc);
        }
    }
    clean_opt(&mut check.ports_error);
    if let Some(route) = &mut check.route {
        clean_opt(&mut route.timed.error);
        for hop in &mut route.hop_details {
            *hop = clean(hop);
        }
    }
    if let Some(infra) = &mut check.infrastructure {
        clean_text_opt(&mut infra.error);
    }
    if let Some(h) = &mut check.handshake {
        clean_opt(&mut h.error);
        clean_text_opt(&mut h.note);
        if let Some(e) = &mut h.evidence {
            clean_opt(&mut e.detail);
            clean_opt(&mut e.transport);
            clean_opt(&mut e.alpn);
        }
    }
    if let Some(e) = &mut check.egress {
        clean_opt(&mut e.error);
        clean_text_opt(&mut e.discrepancy);
        clean_text_opt(&mut e.note);
        for r in &mut e.reflectors {
            clean_opt(&mut r.error);
        }
    }
    if let Some(m) = &mut check.media_stream {
        clean_opt(&mut m.error);
        clean_text_opt(&mut m.detail);
        for ep in &mut m.tested_endpoints {
            clean_opt(&mut ep.error);
        }
    }
    if let Some(t) = &mut check.throughput {
        clean_opt(&mut t.error);
        clean_text_opt(&mut t.detail);
    }
    if let Some(p) = &mut check.path_diagnostics {
        clean_text_opt(&mut p.error);
    }
    if let Some(p) = &mut check.pmtu {
        clean_opt(&mut p.error);
        clean_text_opt(&mut p.detail);
    }
    if let Some(s) = &mut check.split_tunnel {
        clean_opt(&mut s.error);
        clean_text_opt(&mut s.detail);
    }
    for f in &mut check.findings {
        clean_text(&mut f.title);
        clean_text(&mut f.detail);
        f.evidence.retain(|key, _| !SECRET_KEY.is_match(key));
        for (key, value) in &mut f.evidence {
            if let super::model::Evidence::Str(s) = value {
                *s = if key == "location" {
                    location(s)
                } else {
                    clean(s)
                };
            }
        }
    }
}
