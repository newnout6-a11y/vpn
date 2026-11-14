//! The manual local proxy setting (`proxyOverride`, storage B32): one parser for what the user
//! types, the host grammar of [`crate::net::HostPort`], credentials sealed as typed.
use serde::{Deserialize, Serialize, Serializer};
use vpnte_base::types::{Creds, ProxyKind};
use vpnte_base::{AppError, AppResult, Msg};

use crate::net::{AddrError, HostPort, Route};
use crate::secret::Secret;

/// A manual local proxy: a validated `host:port` plus optional credentials. Stored as
/// `{"host", "port", "credentials"?}`; a stored host that fails the grammar is dropped on load.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "Stored<Secret>")]
pub struct ProxyOverride {
    /// Where the proxy listens.
    pub addr: HostPort,
    /// The `user[:pass]` part exactly as typed (percent-encoded form), sealed.
    pub credentials: Option<Secret>,
}

impl ProxyOverride {
    /// Parses `[scheme://][user[:pass]@]host:port` (IPv6 in brackets). Returns the proxy and the
    /// protocol named by the scheme (`socks5` / `socks5h` / `socks` → SOCKS5, `http` → HTTP), if any.
    /// Other schemes (`https`, `socks4`, …), paths, queries and whitespace are refused.
    pub fn parse(input: &str) -> AppResult<(Self, Option<ProxyKind>)> {
        parse_proxy(input.trim())
            .ok_or_else(|| AppError::validation(Msg::new("core.settings.proxyOverrideInvalid")))
    }

    /// Decoded username and password; `None` without credentials or when they are locked.
    pub fn creds(&self) -> Option<Creds> {
        let raw = self.credentials.as_ref()?.expose()?;
        let (user, pass) = raw.split_once(':').unwrap_or((raw, ""));
        Some(Creds {
            user: percent_decode(user),
            pass: percent_decode(pass),
        })
    }

    /// App requests through this proxy; `kind` is [`super::Settings::proxy_type`].
    pub fn route(&self, kind: ProxyKind) -> Route {
        Route::proxy(kind, &self.addr, self.creds().as_ref())
    }
}

/// The on-disk shape (`C` = `Secret` when reading, `&Secret` when writing).
#[derive(Serialize, Deserialize)]
struct Stored<C> {
    host: String,
    port: u16,
    // A missing `Option` field reads as `None` without `default` (which would demand `C: Default`).
    #[serde(skip_serializing_if = "Option::is_none")]
    credentials: Option<C>,
}

impl Serialize for ProxyOverride {
    // By reference: `serde(into)` would serialise a clone, seal the clone's credentials and leave
    // these unsealed, so every later save would re-encrypt them.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Stored {
            host: self.addr.host().to_string(),
            port: self.addr.port(),
            credentials: self.credentials.as_ref(),
        }
        .serialize(serializer)
    }
}

impl TryFrom<Stored<Secret>> for ProxyOverride {
    type Error = AddrError;
    fn try_from(s: Stored<Secret>) -> Result<Self, AddrError> {
        Ok(ProxyOverride {
            addr: HostPort::new(&s.host, s.port)?,
            credentials: s.credentials,
        })
    }
}

fn parse_proxy(s: &str) -> Option<(ProxyOverride, Option<ProxyKind>)> {
    let (kind, rest) = match s.split_once("://") {
        Some((scheme, rest)) => {
            let kind = match scheme.to_ascii_lowercase().as_str() {
                "socks5" | "socks5h" | "socks" => ProxyKind::Socks5,
                "http" => ProxyKind::Http,
                _ => return None,
            };
            (Some(kind), rest.strip_suffix('/').unwrap_or(rest))
        }
        None => (None, s),
    };
    if rest.contains(['/', '?', '#']) || rest.chars().any(char::is_whitespace) {
        return None;
    }
    // The host cannot contain '@', so the last one separates the userinfo even if a pasted password
    // was not percent-encoded.
    let (userinfo, host_port) = match rest.rsplit_once('@') {
        Some((info, hp)) if !info.is_empty() => (Some(info), hp),
        Some(_) => return None,
        None => (None, rest),
    };
    let proxy = ProxyOverride {
        addr: HostPort::parse(host_port).ok()?,
        credentials: userinfo.map(Secret::new),
    };
    Some((proxy, kind))
}

/// Decodes `%XX` escapes; a malformed escape is kept literally.
fn percent_decode(s: &str) -> String {
    let hex = |b: Option<&u8>| b.and_then(|c| (*c as char).to_digit(16));
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let (Some(hi), Some(lo)) = (hex(bytes.get(i + 1)), hex(bytes.get(i + 2)))
        {
            out.push((hi * 16 + lo) as u8);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}
