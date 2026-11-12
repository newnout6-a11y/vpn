//! Exporters: share link (URI), share document (link or JSON) and plain proxy-list line.
//!
//! Exports are not redacted: they exist to hand the key to the user (clipboard, file), and the
//! caller shows the secret-export warning. A link is produced only when it carries the whole
//! profile exactly as the importer will read it back; anything a link cannot express (mux, dial
//! options, raw sing-box options, a provider graph, …) makes [`export_share`] fall back to JSON
//! instead of handing out a degraded key.
use serde_json::Value;
use vpnte_base::Msg;

use crate::model::{Kind, Profile, Source};

mod link;
mod schemes;
mod vmess;

#[cfg(test)]
mod tests;

/// A key ready to share.
#[derive(Clone, PartialEq)]
pub enum Shared {
    /// A one-line share link.
    Uri(String),
    /// A JSON document: sing-box `{"remarks", "outbounds"|"endpoints"}` or a provider Xray document.
    Json(Value),
}

/// Redacted like the model types (CONTRACT §4.9): the link and the document are the credentials.
impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Shared::Uri(uri) => {
                let scheme = uri.split_once("://").map_or("?", |(scheme, _)| scheme);
                write!(f, "Uri({scheme}://<hidden>)")
            }
            Shared::Json(_) => f.write_str("Json(<hidden>)"),
        }
    }
}

impl Shared {
    /// The text to copy or save: the link, or the JSON document on one line.
    pub fn text(&self) -> String {
        match self {
            Shared::Uri(uri) => uri.clone(),
            Shared::Json(doc) => doc.to_string(),
        }
    }

    /// What to tell the user next to the export: a JSON share means no link could carry the key.
    pub fn notice(&self) -> Option<Msg> {
        matches!(self, Shared::Json(_)).then(|| Msg::new("profiles.export.sharedAsJson"))
    }
}

/// Tag of the outbound / endpoint in a sing-box share document. Importers treat it as generic and
/// name the key by `remarks`.
const SHARE_TAG: &str = "proxy";

/// Share link of the profile, or `None` when no link can carry it without loss.
///
/// The imported line is returned unchanged while it still reads back as this very profile, so
/// provider parameters the model does not keep survive a copy.
pub fn export_uri(p: &Profile) -> Option<String> {
    if let Some(line) = faithful_line(p, |line| crate::uri::parse_uri(line).ok()) {
        return Some(line.to_owned());
    }
    schemes::link(p)
}

/// The key as a link when the link is lossless, otherwise as a JSON document: the provider Xray
/// document for a native graph, else `{"remarks", "outbounds"|"endpoints"}` from
/// [`emit_singbox`](crate::emit_singbox::emit_singbox) with the default policy. `None`: neither
/// a link nor the engine JSON can carry the key (e.g. an Xray-only transport with dial options).
pub fn export_share(p: &Profile) -> Option<Shared> {
    if let Some(uri) = export_uri(p) {
        return Some(Shared::Uri(uri));
    }
    let doc = match &p.native_xray {
        Some(graph) => crate::xray_native::export_document(graph, &p.name).ok()?,
        None => singbox_document(p)?,
    };
    Some(Shared::Json(doc))
}

fn singbox_document(p: &Profile) -> Option<Value> {
    use crate::emit_singbox::{EmitPolicy, emit_singbox};
    let fragment = emit_singbox(p, SHARE_TAG, &EmitPolicy::default()).ok()?;
    let (outbounds, endpoints) = (fragment.outbounds(), fragment.endpoints());
    let mut doc = serde_json::Map::new();
    doc.insert("remarks".into(), Value::String(p.name.clone()));
    if !outbounds.is_empty() {
        doc.insert("outbounds".into(), Value::Array(outbounds.to_vec()));
    }
    if !endpoints.is_empty() {
        doc.insert("endpoints".into(), Value::Array(endpoints.to_vec()));
    }
    Some(Value::Object(doc))
}

/// Plain proxy-list line (`http://`, `https://`, `socks5://`) for proxy pool tools. VPN
/// protocols get `None` on purpose: their credentials are not a proxy login.
pub fn export_proxy_line(p: &Profile) -> Option<String> {
    // A line has no place for a transport, REALITY or TLS around SOCKS: a tool would hand the
    // login in clear to a server that expects something else (a REALITY server forwards a plain
    // TLS client to its cover site).
    if p.transport.is_some() || p.tls.as_ref().is_some_and(|t| t.reality.is_some()) {
        return None;
    }
    let (scheme, user, pass) = match &p.kind {
        Kind::Socks { username, password } if p.tls.is_none() => {
            ("socks5", username.as_deref(), password.as_deref())
        }
        Kind::Http { username, password } => {
            let scheme = if p.tls.is_some() { "https" } else { "http" };
            (scheme, username.as_deref(), password.as_deref())
        }
        // Naive over HTTP/2 is an HTTPS proxy; over QUIC no proxy-list tool speaks it.
        Kind::Naive {
            username,
            password,
            quic: false,
            ..
        } => ("https", Some(username.as_str()), Some(password.as_str())),
        _ => return None,
    };
    let host = link::server(&p.server, p.port)?;
    let (user, pass) = (user.unwrap_or_default(), pass.unwrap_or_default());
    let userinfo = if user.is_empty() && pass.is_empty() {
        String::new()
    } else {
        format!("{}:{}@", link::pct(user), link::pct(pass))
    };
    Some(format!("{scheme}://{userinfo}{host}"))
}

/// The imported line, when reading it again yields this very profile: nothing changed since
/// import and the importer still reads the line the same way. Notes describe the reading, not
/// the key, so a note added later does not cost the provider's line.
fn faithful_line(p: &Profile, reparse: impl FnOnce(&str) -> Option<Profile>) -> Option<&str> {
    let Source::Uri(line) = &p.source else {
        return None;
    };
    reparse(line)
        .is_some_and(|again| {
            let again = Profile {
                notes: p.notes.clone(),
                ..again
            };
            again == *p
        })
        .then_some(line.as_str())
}
