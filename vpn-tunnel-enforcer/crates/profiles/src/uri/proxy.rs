//! Naive (`naive://`, `naive+https://`, `naive+quic://`), AnyTLS, and plain proxy links
//! (`socks://`, `socks5://`, `http://`, `https://`).
use super::parts::{
    Link, Params, duration_ms, host_port, non_empty, pct, port_or, secs, split_once,
};
use super::quic::fingerprint_note;
use super::stream::{TlsMode, tls};
use super::{Meta, Res, bad, skip};
use crate::common::b64::base64_text;
use crate::model::{Host, Kind, Note, Profile, SkipReason};

const TLS_DEFAULT_PORT: u16 = 443;

pub(super) fn naive(body: &str, meta: Meta, quic: bool) -> Res<Profile> {
    let link = Link::parse(body);
    let (server, port) = link.endpoint(Some(TLS_DEFAULT_PORT))?;
    let p = &link.params;
    let (username, password) = link.user_password();
    let mut notes = Vec::new();
    let kind = Kind::Naive {
        username,
        password: password.unwrap_or_default(),
        quic,
        extra_headers: extra_headers(p, &mut notes),
        insecure_concurrency: p
            .get(&[
                "insecure-concurrency",
                "insecure_concurrency",
                "insecureConcurrency",
            ])
            .and_then(|v| v.trim().parse().ok())
            .filter(|v| *v > 0),
    };
    let mut profile = meta.profile(server, port, kind);
    profile.notes = notes;
    profile.tls = tls(p, TlsMode::AlwaysNoReality, &mut profile.notes)?;
    // The naive core verifies certificates itself and refuses `insecure`: keep the provider's
    // wish visible instead of dropping it silently.
    if profile.tls.as_ref().is_some_and(|t| t.insecure) {
        profile.notes.push(Note::NaiveInsecureIgnored);
    }
    if quic {
        fingerprint_note(&mut profile);
    }
    Ok(profile)
}

/// NaiveProxy `extra-headers`: `Name: value` pairs separated by CRLF.
fn extra_headers(p: &Params, notes: &mut Vec<Note>) -> Vec<(String, String)> {
    let Some(raw) = p.get(&["extra-headers", "extra_headers", "extraHeaders"]) else {
        return Vec::new();
    };
    let mut headers = Vec::new();
    for line in raw.split('\n').map(str::trim).filter(|l| !l.is_empty()) {
        match line.split_once(':') {
            Some((name, value)) if !name.trim().is_empty() => {
                headers.push((name.trim().to_owned(), value.trim().to_owned()));
            }
            _ => notes.push(Note::UnsupportedField("extra-headers".into())),
        }
    }
    headers
}

pub(super) fn anytls(body: &str, meta: Meta) -> Res<Profile> {
    let link = Link::parse(body);
    let (server, port) = link.endpoint(Some(TLS_DEFAULT_PORT))?;
    let p = &link.params;
    let password = Some(link.userinfo_whole())
        .filter(|v| !v.is_empty())
        .or_else(|| p.get(&["password"]).map(str::to_owned))
        .unwrap_or_default();
    if password.is_empty() {
        return skip(SkipReason::MissingCredential);
    }
    let mut notes = Vec::new();
    let check = [
        "idle_session_check_interval",
        "idleCheckInterval",
        "idle-check-interval",
    ];
    let timeout = ["idle_session_timeout", "idleTimeout", "idle-timeout"];
    let kind = Kind::Anytls {
        password,
        idle_check_s: idle_secs(p, "idle_session_check_interval_ms", &check, &mut notes),
        idle_timeout_s: idle_secs(p, "idle_session_timeout_ms", &timeout, &mut notes),
        min_idle: p
            .get(&["min_idle_session", "minIdle", "min-idle"])
            .and_then(|v| v.trim().parse().ok()),
    };
    let mut profile = meta.profile(server, port, kind);
    profile.notes = notes;
    profile.tls = tls(p, TlsMode::Always, &mut profile.notes)?;
    Ok(profile)
}

/// AnyTLS idle setting in seconds. A bare number under a `*_ms` name is milliseconds, under the
/// other names seconds (mihomo); values with a unit are Go durations.
fn idle_secs(p: &Params, ms_name: &str, names: &[&str], notes: &mut Vec<Note>) -> Option<u32> {
    let (raw, bare_unit_ms) = match p.get(&[ms_name]) {
        Some(raw) => (raw, 1),
        None => (p.get(names)?, 1000),
    };
    let secs = duration_ms(raw, bare_unit_ms).and_then(secs);
    if secs.is_none() {
        notes.push(Note::UnsupportedField(names[0].into()));
    }
    secs
}

/// SOCKS5: `user:pass@host:port`, `<base64 user:pass>@host:port` and Happ's
/// `<base64 of user:pass@host:port>`.
pub(super) fn socks(body: &str, meta: Meta) -> Res<Profile> {
    let (before_query, _) = split_once(body, '?');
    let whole = before_query.strip_suffix('/').unwrap_or(before_query);
    let decoded = (!whole.contains('@')).then(|| base64_text(whole)).flatten();
    let (server, port, (username, password)) = match decoded {
        // Happ: the whole authority in base64; nothing inside it is percent-encoded.
        Some(text) => {
            let text = text.trim();
            let (credentials, hostport) = text.rsplit_once('@').unwrap_or(("", text));
            let (server, raw_port) = host_port(hostport)?;
            let (user, pass) = split_once(credentials, ':');
            let pass = pass.map(str::to_owned).and_then(non_empty);
            (
                server,
                port_or(raw_port, None)?,
                (non_empty(user.to_owned()), pass),
            )
        }
        None => {
            let link = Link::parse(body);
            if !link.root_path() {
                return bad("unexpected path in a proxy link");
            }
            let (server, port) = link.endpoint(None)?;
            (server, port, credentials(link.userinfo))
        }
    };
    let kind = Kind::Socks { username, password };
    Ok(plain_proxy(meta, server, port, kind))
}

/// HTTP(S) proxy link. A web address is not a proxy: proxy links have no path and always state
/// the port, so `https://provider.example/sub` is never mistaken for a server.
pub(super) fn http(body: &str, meta: Meta, over_tls: bool) -> Res<Profile> {
    let link = Link::parse(body);
    if !link.root_path() {
        return bad("a web address, not a proxy link");
    }
    let (server, port) = link.endpoint(None)?;
    let (username, password) = credentials(link.userinfo);
    let kind = Kind::Http { username, password };
    if !over_tls {
        return Ok(plain_proxy(meta, server, port, kind));
    }
    let unnamed = meta.name.is_none();
    let mut profile = meta.profile(server, port, kind);
    if unnamed {
        profile.name = "HTTPS".to_owned();
    }
    profile.tls = tls(&link.params, TlsMode::AlwaysNoReality, &mut profile.notes)?;
    Ok(profile)
}

fn plain_proxy(meta: Meta, server: Host, port: u16, kind: Kind) -> Profile {
    let mut profile = meta.profile(server, port, kind);
    profile.notes.push(Note::Unencrypted);
    profile
}

/// Proxy userinfo: `user:pass` (each part decoded once) or base64 of it; a lone name is a user.
fn credentials(userinfo: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(raw) = userinfo.filter(|u| !u.is_empty()) else {
        return (None, None);
    };
    let decoded = pct(raw);
    if !decoded.contains(':')
        && let Some(text) = base64_text(&decoded)
        && let Some((user, pass)) = text.split_once(':')
    {
        return (non_empty(user.to_owned()), non_empty(pass.to_owned()));
    }
    let (user, pass) = split_once(raw, ':');
    (non_empty(pct(user)), pass.map(pct).and_then(non_empty))
}
