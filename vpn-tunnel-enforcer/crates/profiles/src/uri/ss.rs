//! Shadowsocks: SIP002 (plain or base64 userinfo, optional `/` before `?`/`#`, SIP003 plugins)
//! and the legacy whole-base64 form.
use super::parts::{Link, Params, host_port, pct, port_or, split_once};
use super::{Meta, Res, bad, skip};
use crate::common::b64::base64_text;
use crate::model::{Host, Kind, Note, Profile, SkipReason, SsPlugin};

pub(super) fn shadowsocks(body: &str, meta: Meta) -> Res<Profile> {
    let (before_query, query) = split_once(body, '?');
    if !before_query.contains('@') {
        return legacy(before_query, query, meta);
    }
    let link = Link::parse(body);
    let (server, port) = link.endpoint(None)?;
    let userinfo = pct(link.userinfo.unwrap_or_default());
    if userinfo.is_empty() {
        return skip(SkipReason::MissingCredential);
    }
    // Percent-decoding comes first so `%3D` padding and `%2B` turn back into base64; a base64
    // userinfo is never decoded again (`p%41ss` is a literal password).
    let plain = if userinfo.contains(':') {
        userinfo
    } else {
        match base64_text(&userinfo) {
            Some(text) => text,
            None => return bad("userinfo is neither method:password nor base64"),
        }
    };
    build(meta, (server, port), &plain, &link.params)
}

/// `ss://<base64 of method:password@host:port>`: nothing inside the base64 is percent-encoded.
fn legacy(encoded: &str, query: Option<&str>, meta: Meta) -> Res<Profile> {
    let encoded = encoded.strip_suffix('/').unwrap_or(encoded);
    let Some(text) = base64_text(encoded) else {
        return bad("link is neither SIP002 nor base64");
    };
    let Some((credentials, hostport)) = text.trim().rsplit_once('@') else {
        return bad("decoded link has no method:password@host:port");
    };
    let (host, raw_port) = host_port(hostport)?;
    let port = port_or(raw_port, None)?;
    build(
        meta,
        (host, port),
        credentials,
        &Params::parse(query.unwrap_or_default()),
    )
}

fn build(meta: Meta, (server, port): (Host, u16), credentials: &str, p: &Params) -> Res<Profile> {
    let Some((method, password)) = credentials.split_once(':').filter(|(m, _)| !m.is_empty())
    else {
        return bad("missing method:password");
    };
    let method = method.to_ascii_lowercase();
    let plaintext = method == "none";
    if password.is_empty() && !plaintext {
        return skip(SkipReason::MissingCredential);
    }
    let kind = Kind::Shadowsocks {
        method,
        password: password.to_owned(),
        plugin: plugin(p)?,
        shadowtls: None,
        uot: None,
    };
    let mut profile = meta.profile(server, port, kind);
    if plaintext {
        profile.notes.push(Note::Unencrypted);
    }
    Ok(profile)
}

/// SIP003 `plugin=<name>;<opts>`: sing-box runs `obfs-local` (simple-obfs) and `v2ray-plugin`.
fn plugin(p: &Params) -> Res<Option<SsPlugin>> {
    let Some(raw) = p.get(&["plugin"]) else {
        return Ok(None);
    };
    let (name, opts) = split_once(raw, ';');
    let name = match name.trim() {
        "obfs-local" | "simple-obfs" => "obfs-local",
        "v2ray-plugin" => "v2ray-plugin",
        "" | "none" => return Ok(None),
        other => {
            let plain = other.len() <= 32
                && other
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
            let name = if plain { other } else { "unknown" };
            return skip(SkipReason::UnsupportedPlugin(name.to_owned()));
        }
    };
    let opts = opts.unwrap_or_default().to_owned();
    Ok(Some(SsPlugin {
        name: name.to_owned(),
        opts,
    }))
}
