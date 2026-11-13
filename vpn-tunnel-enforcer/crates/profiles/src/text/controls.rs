//! Provider controls: the Happ app-management keys that steer the client instead of describing
//! the plan (`routing`, `hide-settings`, `subscription-autoconnect`, `fragmentation-*`, the
//! relocation keys). They arrive like the metadata, as response headers or `#` / `//` lines at
//! the top of the body.
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::meta::{comment_block, unquote};
use crate::model::{HelloSplit, TlsTricks};

/// Longest routing value kept (a `happ://routing/…` link carries a base64 JSON profile).
const MAX_ROUTING_BYTES: usize = 64 * 1024;
/// Happ's routing link in a body line.
const ROUTING_LINK: &str = "happ://routing/";

/// How a subscription picks its server when it connects at start (`subscription-autoconnect-type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AutoconnectPick {
    LastUsed,
    LowestDelay,
    Random,
}

/// The provider's controls as the group keeps them (plain: no secret in here).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Controls {
    /// `routing`: the provider's routing profile as sent (a `happ://routing/…` link or its payload).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing: Option<String>,
    /// `hide-settings`: the servers' configs stay out of sight.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hide_settings: Option<bool>,
    /// `subscription-autoconnect`: connect at start.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autoconnect: Option<bool>,
    /// `subscription-autoconnect-type`.
    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "pick_or_none"
    )]
    pub autoconnect_pick: Option<AutoconnectPick>,
    /// `fragmentation-enable` / `-packets` / `-length` / `-interval` (Happ, limcore): the TLS
    /// tricks the provider sets for its servers. New rows take them once, when they are added;
    /// afterwards the value is the user's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_tricks: Option<TlsTricks>,
}

/// A pick a newer build stored (a name this one does not know) reads as none, the default pick:
/// the group keeps its other controls, `hide-settings` above all, and the list stays readable.
fn pick_or_none<'de, D: Deserializer<'de>>(d: D) -> Result<Option<AutoconnectPick>, D::Error> {
    let value = Option::<serde_json::Value>::deserialize(d)?;
    Ok(value.and_then(|v| serde_json::from_value(v).ok()))
}

impl Controls {
    /// The provider asked to keep the servers' configs hidden.
    pub fn hides_settings(&self) -> bool {
        self.hide_settings == Some(true)
    }
}

/// Where the provider says the subscription lives besides its URL. The values are access tokens
/// like the URL itself: `Debug` hides them and they are never stored as plain text.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Relocation {
    /// `fallback-url` (Happ): tried when the URL fails, answers 300-599 or takes over 9 s.
    pub fallback_url: Option<String>,
    /// `new-url` (Happ) or `moved-permanently-to` (Hiddify): the subscription's new address.
    pub new_url: Option<String>,
    /// `new-domain` (Happ): the same path on another `host[:port]`.
    pub new_domain: Option<String>,
}

impl fmt::Debug for Relocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Relocation")
            .field("fallback_url", &self.fallback_url.is_some())
            .field("new_url", &self.new_url.is_some())
            .field("new_domain", &self.new_domain.is_some())
            .finish()
    }
}

/// The controls and relocation hints of one answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderKeys {
    pub controls: Controls,
    pub relocation: Relocation,
    /// The `fragmentation-*` values as sent: read together into `controls.tls_tricks`.
    fragmentation: Fragmentation,
}

/// Happ's `fragmentation-*` keys of one answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Fragmentation {
    enable: Option<bool>,
    packets: Option<String>,
    length: Option<String>,
    interval: Option<String>,
}

impl Fragmentation {
    fn or(self, other: Fragmentation) -> Fragmentation {
        Fragmentation {
            enable: self.enable.or(other.enable),
            packets: self.packets.or(other.packets),
            length: self.length.or(other.length),
            interval: self.interval.or(other.interval),
        }
    }

    /// Off when the provider switched fragmentation off; on: its packets (Happ's first choice,
    /// `tlshello`, when not sent), length and pause, the preset where not sent. Nothing without
    /// `fragmentation-enable` or with a value Xray would not read.
    fn tricks(&self) -> Option<TlsTricks> {
        if !self.enable? {
            return Some(TlsTricks::Off);
        }
        let preset = HelloSplit::PRESET.interval_ms.to_string();
        TlsTricks::from_fragment(
            self.packets.as_deref().unwrap_or("tlshello"),
            self.length.as_deref(),
            Some(self.interval.as_deref().unwrap_or(&preset)),
        )
    }
}

impl ProviderKeys {
    /// Applies one `key: value` (key in any case); other keys and unusable values are ignored.
    pub fn apply(&mut self, key: &str, value: &str) {
        let value = unquote(value);
        let c = &mut self.controls;
        let r = &mut self.relocation;
        let f = &mut self.fragmentation;
        match key.trim().to_ascii_lowercase().as_str() {
            "routing" => c.routing = routing(value).or(c.routing.take()),
            "hide-settings" => c.hide_settings = toggle(value).or(c.hide_settings),
            "subscription-autoconnect" => c.autoconnect = toggle(value).or(c.autoconnect),
            "subscription-autoconnect-type" => {
                c.autoconnect_pick = pick(value).or(c.autoconnect_pick)
            }
            "fallback-url" => r.fallback_url = http_url(value).or(r.fallback_url.take()),
            "new-url" | "moved-permanently-to" => r.new_url = http_url(value).or(r.new_url.take()),
            "new-domain" => r.new_domain = domain(value).or(r.new_domain.take()),
            "fragmentation-enable" => f.enable = toggle(value).or(f.enable),
            "fragmentation-packets" => f.packets = short(value).or(f.packets.take()),
            "fragmentation-length" => f.length = short(value).or(f.length.take()),
            "fragmentation-interval" => f.interval = short(value).or(f.interval.take()),
            _ => return,
        }
        c.tls_tricks = f.tricks();
    }

    /// `self`, each missing field taken from `other` (headers over body, outer layer over inner).
    pub fn or(self, other: ProviderKeys) -> ProviderKeys {
        let (c, o) = (self.controls, other.controls);
        let (r, p) = (self.relocation, other.relocation);
        let fragmentation = self.fragmentation.or(other.fragmentation);
        ProviderKeys {
            controls: Controls {
                routing: c.routing.or(o.routing),
                hide_settings: c.hide_settings.or(o.hide_settings),
                autoconnect: c.autoconnect.or(o.autoconnect),
                autoconnect_pick: c.autoconnect_pick.or(o.autoconnect_pick),
                tls_tricks: fragmentation.tricks(),
            },
            relocation: Relocation {
                fallback_url: r.fallback_url.or(p.fallback_url),
                new_url: r.new_url.or(p.new_url),
                new_domain: r.new_domain.or(p.new_domain),
            },
            fragmentation,
        }
    }
}

/// The keys of the comment block at the top of `text`, and Happ's routing link when a body line
/// carries one (the `routing` key wins over it).
pub fn body_keys(text: &str) -> ProviderKeys {
    let mut keys = ProviderKeys::default();
    comment_block(text, |key, value| keys.apply(key, value));
    if keys.controls.routing.is_none() {
        keys.controls.routing = text.lines().map(str::trim).find_map(|line| {
            let head = line.get(..ROUTING_LINK.len())?;
            head.eq_ignore_ascii_case(ROUTING_LINK)
                .then(|| routing(line))
                .flatten()
        });
    }
    keys
}

/// The keys of response headers (names in any case, a repeated header: the last usable one wins),
/// each missing field taken from `body`.
pub fn header_keys<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    body: ProviderKeys,
) -> ProviderKeys {
    let mut keys = ProviderKeys::default();
    for (name, value) in headers {
        keys.apply(name, value);
    }
    keys.or(body)
}

/// Happ toggles: `true` / `1` switch on, any other non-blank value switches off.
fn toggle(value: &str) -> Option<bool> {
    (!value.is_empty()).then(|| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn pick(value: &str) -> Option<AutoconnectPick> {
    match value.to_ascii_lowercase().as_str() {
        "lastused" => Some(AutoconnectPick::LastUsed),
        "lowestdelay" => Some(AutoconnectPick::LowestDelay),
        "random" => Some(AutoconnectPick::Random),
        _ => None,
    }
}

/// A short value (a fragment range, `tlshello`), trimmed; `None` when blank or odd.
fn short(value: &str) -> Option<String> {
    let value = value.trim();
    let usable = !value.is_empty() && value.len() <= 32 && !value.chars().any(char::is_control);
    usable.then(|| value.to_owned())
}

/// Kept as sent, within the size cap and without control characters.
fn routing(value: &str) -> Option<String> {
    let value = value.trim();
    let usable = !value.is_empty()
        && value.len() <= MAX_ROUTING_BYTES
        && !value.chars().any(char::is_control);
    usable.then(|| value.to_owned())
}

fn http_url(value: &str) -> Option<String> {
    let url = url::Url::parse(value.trim()).ok()?;
    let usable = matches!(url.scheme(), "http" | "https") && url.host_str().is_some();
    usable.then(|| url.into())
}

/// `host` or `host:port`, nothing else (no scheme, path, query or credentials).
fn domain(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('/');
    let url = url::Url::parse(&format!("http://{value}/")).ok()?;
    let bare = url.host_str().is_some_and(|h| !h.is_empty())
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    bare.then(|| match url.port() {
        Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_owned(),
    })
}

#[cfg(test)]
mod tests;
