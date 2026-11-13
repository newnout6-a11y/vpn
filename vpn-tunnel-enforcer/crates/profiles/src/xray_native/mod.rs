//! Provider Xray graphs (Happ/Remnawave-style JSON): balancers with `leastLoad`, loopback
//! "reroute" hops, bridge chains through `dialerProxy`, observatories. Flattening such a document
//! into one outbound lost failover and broke bridges, so the graph is kept as data
//! ([`NativeXray`]), validated on import, compiled with namespaced tags at start and exported
//! with the provider's own tags.
use serde::Deserialize;
use serde_json::Value;
use vpnte_base::error::AppError;
use vpnte_base::msg::Msg;

use crate::model::NativeXray;

/// Key under which the Electron app stored the graph inside a profile's outbound JSON.
pub const FIELD: &str = "vpnte_xray";

/// Tag of the blackhole an exported document adds for its fail-closed guard (never a provider tag).
pub const EXPORT_BLOCK_TAG: &str = "vpnte-block";

/// Compiled tag of the selected outbound and the prefixes of every other compiled name.
const PROXY_TAG: &str = "proxy";
const SOURCE_PREFIX: &str = "vpnte-source:";
const BALANCER_PREFIX: &str = "vpnte-balancer:";
const LOOP_PREFIX: &str = "vpnte-loop:";
/// The engine's own blackhole; compiled loopback guards end there.
const ENGINE_BLOCK_TAG: &str = "block";

/// Protocols that may carry application traffic or act as a hop of the graph.
const GRAPH_PROTOCOLS: [&str; 7] = [
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "hysteria",
    "freedom",
    "blackhole",
];
/// Plain egress: allowed as the dialer of an encrypted hop, never as an application route.
const BYPASS_PROTOCOLS: [&str; 4] = ["freedom", "socks", "http", "dns"];
/// Protocols a document import may pick as the profile's selected outbound.
const SELECTABLE_PROTOCOLS: [&str; 4] = ["vless", "vmess", "trojan", "shadowsocks"];
/// Stream networks the bundled Xray 26 refuses at load (checked with `xray run -test`).
const REMOVED_NETWORKS: [&str; 4] = ["h2", "h3", "http", "quic"];

/// The stream network of `outbound` when it is one Xray 26 removed (lower case).
pub(crate) fn removed_network(outbound: &Value) -> Option<String> {
    let network = outbound
        .pointer("/streamSettings/network")?
        .as_str()?
        .trim()
        .to_ascii_lowercase();
    REMOVED_NETWORKS
        .contains(&network.as_str())
        .then_some(network)
}

/// Why a provider graph was refused. `Display` keeps the old English diagnostics (logs, skip reasons).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NativeError {
    #[error("Invalid preserved Xray profile")]
    InvalidProfile,
    #[error("Preserved Xray entry outbound is missing")]
    MissingSelected,
    #[error("Missing or duplicate preserved Xray outbound tag")]
    DuplicateTag,
    #[error("Invalid preserved Xray balancer tag")]
    BadBalancerTag,
    #[error("Missing preserved Xray balancer dependency")]
    MissingBalancer,
    #[error("Empty preserved Xray balancer")]
    EmptyBalancer,
    #[error("Missing preserved Xray outbound dependency")]
    MissingDependency,
    #[error("Preserved Xray application route can bypass VPN protection")]
    ApplicationBypass,
    #[error("Cyclic preserved Xray connection dependencies")]
    Cyclic,
    #[error("Missing preserved Xray loopback route")]
    MissingLoopbackRoute,
    #[error("Preserved Xray loopback route has no destination")]
    LoopbackRouteNoDestination,
    #[error("Unsupported preserved Xray outbound dependency")]
    UnsupportedProtocol,
    #[error("Preserved Xray profile has no application entry")]
    NoEntry,
    #[error("Preserved Xray selected outbound is outside its entry graph")]
    SelectedOutsideGraph,
    #[error("Preserved Xray subscription references an external local file")]
    LocalFileReference,
    /// Xray builds VLESS/VMess with exactly one `vnext` and user, Trojan/SS with one `servers` entry.
    #[error("Preserved Xray outbound must have exactly one server and one user")]
    MultipleEndpoints,
    /// The bundled Xray refuses `allowInsecure: true`; only a pinned certificate or certificate
    /// names (`verifyPeerCertByName`) may stand in for the SNI check.
    #[error(
        "Preserved Xray outbound disables certificate checks without a pin or certificate names"
    )]
    InsecureWithoutPin,
    #[error("Preserved Xray outbound uses the reserved tag vpnte-block")]
    ReservedTag,
    /// Provider JSON is untrusted and the walk is recursive: absurdly long chains are refused.
    #[error("Preserved Xray connection chain is too deep")]
    TooDeep,
    /// A copied loop rule matches by `geoip:` / `geosite:` / `ext:` data: the bundled Xray ships
    /// no `.dat` files, so the graph could never start (and `ext:` reads a file from disk).
    #[error("Preserved Xray route needs geo data files the app does not ship")]
    GeoData,
    /// An outbound streams over HTTP/2 (`h2`, `h3`, `http`) or QUIC, which Xray 26 removed: the
    /// bundled binary refuses the whole config ("removed and migrated to XHTTP").
    #[error("Preserved Xray outbound uses the HTTP/2 or QUIC transport removed from Xray 26")]
    RemovedTransport,
}

impl NativeError {
    /// User-facing message (`profiles.xrayNative.*`).
    pub fn msg(&self) -> Msg {
        Msg::new(match self {
            NativeError::InvalidProfile => "profiles.xrayNative.invalidProfile",
            NativeError::MissingSelected => "profiles.xrayNative.missingSelected",
            NativeError::DuplicateTag => "profiles.xrayNative.duplicateTag",
            NativeError::BadBalancerTag => "profiles.xrayNative.badBalancerTag",
            NativeError::MissingBalancer => "profiles.xrayNative.missingBalancer",
            NativeError::EmptyBalancer => "profiles.xrayNative.emptyBalancer",
            NativeError::MissingDependency => "profiles.xrayNative.missingDependency",
            NativeError::ApplicationBypass => "profiles.xrayNative.applicationBypass",
            NativeError::Cyclic => "profiles.xrayNative.cyclic",
            NativeError::MissingLoopbackRoute => "profiles.xrayNative.missingLoopbackRoute",
            NativeError::LoopbackRouteNoDestination => {
                "profiles.xrayNative.loopbackRouteNoDestination"
            }
            NativeError::UnsupportedProtocol => "profiles.xrayNative.unsupportedProtocol",
            NativeError::NoEntry => "profiles.xrayNative.noEntry",
            NativeError::SelectedOutsideGraph => "profiles.xrayNative.selectedOutsideGraph",
            NativeError::LocalFileReference => "profiles.xrayNative.localFileReference",
            NativeError::MultipleEndpoints => "profiles.xrayNative.multipleEndpoints",
            NativeError::InsecureWithoutPin => "profiles.xrayNative.insecureWithoutPin",
            NativeError::ReservedTag => "profiles.xrayNative.reservedTag",
            NativeError::TooDeep => "profiles.xrayNative.tooDeep",
            NativeError::GeoData => "profiles.xrayNative.geoData",
            NativeError::RemovedTransport => "profiles.xrayNative.removedTransport",
        })
    }
}

impl From<NativeError> for AppError {
    fn from(err: NativeError) -> Self {
        AppError::validation(err.msg()).with_source(err)
    }
}

mod compile;
mod document;
mod reach;

pub use compile::{CompiledGraph, compile};
pub use document::{document_entry, document_selected, export_document, preserve};
pub(crate) use reach::dials_through;

/// Some outbound of the graph runs Xray mux with UDP/443 refused (`mux.enabled` and
/// `xudpProxyUDP443` absent — Xray's default — or `reject`): QUIC through such a connection must
/// be blocked so browsers fall back to TCP instead of stalling. The provider's mux policy wins.
pub fn mux_rejects_udp443(graph: &NativeXray) -> bool {
    graph
        .outbounds
        .iter()
        .filter_map(|o| o.get("mux"))
        .any(|mux| {
            mux.get("enabled") == Some(&Value::Bool(true))
                && !mux
                    .get("xudpProxyUDP443")
                    .is_some_and(|v| truthy(v) && *v != "reject")
        })
}

/// Reads a stored graph (the legacy `vpnte_xray` value) and validates it like the old reader.
pub fn decode(value: &Value) -> Result<NativeXray, NativeError> {
    let graph = NativeXray::deserialize(value).map_err(|_| NativeError::InvalidProfile)?;
    validate(&graph)?;
    Ok(graph)
}

/// Format checks of a stored graph: version 1 and a selected tag (the full checks are [`compile`]).
pub fn validate(graph: &NativeXray) -> Result<(), NativeError> {
    if graph.version != 1 || graph.selected_tag.is_empty() {
        return Err(NativeError::InvalidProfile);
    }
    Ok(())
}

/// The outbound that represents the profile (endpoint, display fields, engine translation).
pub fn selected_outbound(graph: &NativeXray) -> Result<&Value, NativeError> {
    graph
        .outbounds
        .iter()
        .find(|o| tag(o) == Some(graph.selected_tag.as_str()))
        .ok_or(NativeError::MissingSelected)
}

/// A non-empty string `tag`.
fn tag(value: &Value) -> Option<&str> {
    non_empty(value.get("tag"))
}

fn non_empty(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn non_empty_str(value: Option<&str>) -> Option<&str> {
    value.filter(|s| !s.is_empty())
}

fn protocol(outbound: &Value) -> &str {
    outbound
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// JavaScript truthiness: the stored format and the old checks were written against it.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// String items of a JSON array; anything else is ignored.
fn strings(value: Option<&Value>) -> Vec<&str> {
    value
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn list_of(value: &Value, key: &str) -> Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn routes_inbound(rule: &Value, inbound: &str) -> bool {
    rule.get("inboundTag")
        .and_then(Value::as_array)
        .is_some_and(|tags| tags.iter().any(|t| t.as_str() == Some(inbound)))
}

/// Rewrites the non-empty string at `pointer` through `map`.
fn retag(value: &mut Value, pointer: &str, map: impl Fn(&str) -> String) {
    if let Some(Value::String(t)) = value.pointer_mut(pointer)
        && !t.is_empty()
    {
        *t = map(t);
    }
}

/// Narrows a rule's `inboundTag` list to reachable loopback inbounds, renamed through `map`.
fn keep_inbounds(rule: &mut Value, reachable: &[&str], map: impl Fn(&str) -> String) {
    if let Some(tags) = rule.get_mut("inboundTag").and_then(Value::as_array_mut) {
        let kept = tags
            .iter()
            .filter_map(Value::as_str)
            .filter(|t| reachable.contains(t))
            .map(|t| Value::String(map(t)))
            .collect();
        *tags = kept;
    }
}

#[cfg(test)]
mod tests;
