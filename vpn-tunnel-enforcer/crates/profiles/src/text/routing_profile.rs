//! Happ routing profiles: `happ://routing/add/<base64 JSON>`, `happ://routing/onadd/…`,
//! `happ://routing/off`, or the base64 / JSON itself (a provider's `routing` value, which
//! [`super::Controls`] keeps as sent). Read into plain lists for a preview: nothing here applies
//! anything, the app turns a profile into the user's own rules only on the user's click.
//!
//! Format: Happ's public docs (`happ.su/main/dev-docs/routing`). Single values are JSON strings,
//! `"true"` included; site and IP lists use Xray's routing syntax (`domain:`, `full:`,
//! `keyword:`, `regexp:`, `geosite:`, `geoip:`, CIDR).
use ipnet::IpNet;
use percent_encoding::percent_decode_str;
use serde_json::{Map, Value};
use vpnte_base::msg::Msg;

use crate::common::b64::base64_text;

/// Largest routing value read: the cap the stored `routing` value has too.
pub const MAX_PROFILE_BYTES: usize = 64 * 1024;
/// Happ's routing link.
const LINK: &str = "happ://routing/";
/// Longest list entry kept as an entry (a host name is at most 253 bytes).
const MAX_ENTRY_BYTES: usize = 512;
/// Keys of which a JSON object needs one to be a routing profile.
const PROFILE_KEYS: [&str; 8] = [
    "GlobalProxy",
    "DirectSites",
    "DirectIp",
    "ProxySites",
    "ProxyIp",
    "BlockSites",
    "BlockIp",
    "RouteOrder",
];

/// Why a value is not a usable routing profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RoutingError {
    #[error("not a Happ routing profile")]
    NotRouting,
    #[error("damaged routing profile")]
    Damaged,
    #[error("routing profile larger than 64 KiB")]
    TooLarge,
}

impl RoutingError {
    /// User-facing message (`profiles.routing.*`).
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            RoutingError::NotRouting => "profiles.routing.notRouting",
            RoutingError::Damaged => "profiles.routing.damaged",
            RoutingError::TooLarge => "profiles.routing.tooLarge",
        })
    }
}

/// A provider's routing value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingValue {
    Profile(RoutingProfile),
    /// `happ://routing/off`: the provider turns its own routing off.
    Off,
}

/// The parts of a profile that can matter to the user's rules, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingProfile {
    /// `Name`.
    pub name: Option<String>,
    /// `GlobalProxy`: what no list names goes through the proxy (Happ's default).
    pub global_proxy: bool,
    /// The lists in the profile's `RouteOrder` (block, proxy, direct when absent), each route's
    /// sites before its IPs; blank entries left out.
    pub entries: Vec<RouteEntry>,
    /// DNS servers the profile names (remote first), each once.
    pub dns: Vec<String>,
    /// Names in `DnsHosts` (fixed answers).
    pub dns_hosts: usize,
    /// `FakeDNS` on.
    pub fake_dns: bool,
}

/// Which list an entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Route {
    Block,
    Proxy,
    Direct,
}

/// One list entry: what it says and how it was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub route: Route,
    pub entry: Entry,
    /// As written (trimmed), for the preview.
    pub raw: String,
}

/// An entry of a site or IP list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// `domain:x`: the domain and its subdomains.
    Domain(String),
    /// `full:x`: exactly this host.
    Full(String),
    /// `keyword:k`: any host containing `k`.
    Keyword(String),
    /// A site without a prefix (Xray matches it as a substring of the host).
    Plain(String),
    /// `regexp:…`.
    Regexp(String),
    /// `geosite:tag`, lower case (`@attr` kept).
    Geosite(String),
    /// `geoip:tag`, lower case (`!tag`, a negation, kept).
    Geoip(String),
    /// An address or a CIDR range.
    Ip(IpNet),
    /// `ext:file:tag`: a list from the provider's own files.
    External(String),
    /// Not an entry of its list (a number in a site list, a word in an IP list…).
    Unknown(String),
}

/// Reads a routing value: a `happ://routing/…` link, its base64 payload or the JSON itself.
pub fn parse_routing(value: &str) -> Result<RoutingValue, RoutingError> {
    let value = value.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    if value.len() > MAX_PROFILE_BYTES {
        return Err(RoutingError::TooLarge);
    }
    let (payload, linked) = match link_rest(value) {
        Some(rest) => {
            let (verb, payload) = rest.split_once('/').unwrap_or((rest, ""));
            match verb.to_ascii_lowercase().as_str() {
                "off" => return Ok(RoutingValue::Off),
                "add" | "onadd" => (payload, true),
                _ => return Err(RoutingError::NotRouting),
            }
        }
        None => (value, false),
    };
    // Inside a link a payload that does not read is damaged; a bare value may be anything.
    let unusable = match linked {
        true => RoutingError::Damaged,
        false => RoutingError::NotRouting,
    };
    let json = json_text(payload).ok_or(unusable)?;
    let doc: Value = serde_json::from_str(&json).map_err(|_| unusable)?;
    let object = doc.as_object().ok_or(unusable)?;
    if !PROFILE_KEYS.iter().any(|key| object.contains_key(*key)) {
        return Err(RoutingError::NotRouting);
    }
    Ok(RoutingValue::Profile(profile(object)))
}

/// What follows `happ://routing/` (any case).
fn link_rest(value: &str) -> Option<&str> {
    let head = value.get(..LINK.len())?;
    head.eq_ignore_ascii_case(LINK)
        .then(|| &value[LINK.len()..])
}

/// The JSON text of a payload: the JSON itself or its base64, either percent-encoded or not
/// (senders escape the padding as `%3D` as often as not).
fn json_text(payload: &str) -> Option<String> {
    let decoded = percent_decode_str(payload)
        .decode_utf8()
        .map_or_else(|_| payload.to_owned(), |text| text.into_owned());
    let decoded = decoded.trim();
    if decoded.starts_with('{') {
        return Some(decoded.to_owned());
    }
    let text = base64_text(decoded)?;
    let text = text.trim_start_matches('\u{feff}').trim();
    text.starts_with('{').then(|| text.to_owned())
}

fn profile(object: &Map<String, Value>) -> RoutingProfile {
    let mut entries = Vec::new();
    for route in route_order(text(object, "RouteOrder")) {
        let (sites, ips) = match route {
            Route::Block => ("BlockSites", "BlockIp"),
            Route::Proxy => ("ProxySites", "ProxyIp"),
            Route::Direct => ("DirectSites", "DirectIp"),
        };
        list(object.get(sites), route, site, &mut entries);
        list(object.get(ips), route, ip, &mut entries);
    }
    let mut dns: Vec<String> = Vec::new();
    for side in ["Remote", "Domestic"] {
        if let Some(server) = dns_server(object, side).filter(|s| !dns.contains(s)) {
            dns.push(server);
        }
    }
    RoutingProfile {
        name: text(object, "Name").map(str::to_owned),
        global_proxy: flag(object.get("GlobalProxy")).unwrap_or(true),
        entries,
        dns,
        dns_hosts: object
            .get("DnsHosts")
            .and_then(Value::as_object)
            .map_or(0, Map::len),
        fake_dns: flag(object.get("FakeDNS")).unwrap_or(false),
    }
}

/// `RouteOrder` as written (`block-direct-proxy`, any order of the three words), else block,
/// proxy, direct: a site in two lists then goes through the proxy, the safer side.
fn route_order(order: Option<&str>) -> [Route; 3] {
    const DEFAULT: [Route; 3] = [Route::Block, Route::Proxy, Route::Direct];
    let Some(order) = order else {
        return DEFAULT;
    };
    let mut routes = Vec::with_capacity(3);
    for word in order.split('-') {
        let route = match word.trim().to_ascii_lowercase().as_str() {
            "block" => Route::Block,
            "proxy" => Route::Proxy,
            "direct" => Route::Direct,
            _ => return DEFAULT,
        };
        if routes.contains(&route) {
            return DEFAULT;
        }
        routes.push(route);
    }
    routes.try_into().unwrap_or(DEFAULT)
}

/// One list's entries; a list written as a single value counts as one entry, so nothing a
/// provider sent goes unseen.
fn list(value: Option<&Value>, route: Route, read: fn(&str) -> Entry, out: &mut Vec<RouteEntry>) {
    let items = match value {
        None | Some(Value::Null) => return,
        Some(Value::Array(items)) => items.as_slice(),
        Some(other) => std::slice::from_ref(other),
    };
    for item in items {
        let (raw, entry) = match item {
            Value::String(s) if s.trim().is_empty() => continue,
            Value::String(s) if s.trim().len() <= MAX_ENTRY_BYTES => {
                (s.trim().to_owned(), read(s.trim()))
            }
            // Too long for an entry, or not a string: shown as written (cut), never read.
            Value::String(s) => (shorten(s.trim()), Entry::Unknown(shorten(s.trim()))),
            other => {
                let shown = shorten(&other.to_string());
                (shown.clone(), Entry::Unknown(shown))
            }
        };
        out.push(RouteEntry { route, entry, raw });
    }
}

/// A site entry in Xray's syntax.
fn site(raw: &str) -> Entry {
    let Some((prefix, rest)) = raw.split_once(':') else {
        return Entry::Plain(raw.to_lowercase());
    };
    let rest = rest.trim();
    match prefix.trim().to_ascii_lowercase().as_str() {
        "domain" => Entry::Domain(rest.to_lowercase()),
        "full" => Entry::Full(rest.to_lowercase()),
        "keyword" => Entry::Keyword(rest.to_lowercase()),
        "regexp" => Entry::Regexp(rest.to_owned()),
        "geosite" => Entry::Geosite(rest.to_ascii_lowercase()),
        "ext" => Entry::External(rest.to_owned()),
        // Xray reads any other text as a plain substring; a URL or `host:port` stays one for
        // the app to judge as a site.
        _ => Entry::Plain(raw.to_lowercase()),
    }
}

/// An IP entry: `geoip:tag`, `ext:file:tag`, an address or a CIDR range.
fn ip(raw: &str) -> Entry {
    // An IPv6 address has colons too: only these two prefixes are taken as prefixes.
    if let Some((prefix, rest)) = raw.split_once(':') {
        match prefix.trim().to_ascii_lowercase().as_str() {
            "geoip" => return Entry::Geoip(rest.trim().to_ascii_lowercase()),
            "ext" => return Entry::External(rest.trim().to_owned()),
            _ => {}
        }
    }
    if let Ok(net) = raw.parse::<IpNet>() {
        return Entry::Ip(net.trunc());
    }
    match raw.parse::<std::net::IpAddr>() {
        Ok(addr) => Entry::Ip(IpNet::from(addr)),
        Err(_) => Entry::Unknown(raw.to_owned()),
    }
}

/// A non-blank string field.
fn text<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// One side's resolver as the user would recognise it: the DoH URL, else the address, else the
/// single `RemoteDns` / `DomesticDns` value of Happ's older sample.
fn dns_server(object: &Map<String, Value>, side: &str) -> Option<String> {
    let doh =
        text(object, &format!("{side}DNSType")).is_some_and(|t| t.eq_ignore_ascii_case("doh"));
    let url = text(object, &format!("{side}DNSDomain"));
    let address = text(object, &format!("{side}DNSIP"));
    let server = match (doh, url, address) {
        (true, Some(url), _) => url,
        (_, _, Some(address)) => address,
        (_, Some(url), None) => url,
        _ => text(object, &format!("{side}Dns"))?,
    };
    Some(shorten(server))
}

/// Happ writes switches as strings (`"true"`); a JSON bool reads the same.
fn flag(value: Option<&Value>) -> Option<bool> {
    match value? {
        Value::Bool(on) => Some(*on),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// At most [`MAX_ENTRY_BYTES`] of `text` (cut at a character), `…` when cut.
fn shorten(text: &str) -> String {
    if text.len() <= MAX_ENTRY_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_ENTRY_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

#[cfg(test)]
mod tests;
