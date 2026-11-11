//! Electron-era stored outbounds (`ServerProfile.outbound`, `directVpnCachedProfiles[].outbound`)
//! -> typed [`Profile`]. The old parsers stored a sing-box-shaped object plus extras (profiles spec
//! §2.3): bracketed IPv6, comma-joined Hysteria2 ports, AnyTLS milliseconds, XHTTP and gRPC
//! multi-mode transports, a `null` VMess `alter_id`, and an embedded Xray graph (`vpnte_xray`).
use serde_json::Value;
use vpnte_base::{AppError, Msg};

use crate::common::fields::{clean_name, display_name};
use crate::json::scan::Origin;
use crate::json::singbox::{self, Input, SUPPORTED};
use crate::model::{NativeXray, Profile, SkipReason};

/// TLS defaults every old parser wrote when the provider gave none (profiles spec P-01/P-05).
/// They were never provider choices: forgetting them lets the emitter apply today's per-device
/// fingerprint and keeps forced `h2,http/1.1` off Hysteria2 / TUIC.
const OLD_DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];
const OLD_DEFAULT_FINGERPRINT: &str = "chrome";

/// Why a stored outbound could not be imported.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LegacyError {
    #[error("stored outbound is not a JSON object")]
    NotAnObject,
    #[error("unsupported protocol {0:?}")]
    UnsupportedProtocol(String),
    /// The outbound is malformed or cannot run (English diagnostic, no credentials).
    #[error("stored outbound cannot be used: {0}")]
    Unusable(String),
    #[error("invalid preserved Xray graph")]
    InvalidNativeGraph,
}

impl From<LegacyError> for AppError {
    fn from(err: LegacyError) -> Self {
        let msg = match &err {
            LegacyError::NotAnObject => Msg::new("profiles.legacy.notAnObject"),
            LegacyError::UnsupportedProtocol(p) => {
                Msg::new("profiles.legacy.unsupportedProtocol").arg("protocol", p)
            }
            LegacyError::Unusable(_) => Msg::new("profiles.legacy.unusable"),
            LegacyError::InvalidNativeGraph => Msg::new("profiles.legacy.invalidNativeGraph"),
        };
        AppError::validation(msg).with_source(err)
    }
}

/// Converts one stored row. `protocol` is the row's label (`"sing-box"` for pasted JSON, whose real
/// type is `outbound.type`); `source_uri` is the share link the row was imported from, if any.
pub fn from_legacy(
    name: &str,
    protocol: &str,
    outbound: &Value,
    source_uri: Option<&str>,
) -> Result<Profile, LegacyError> {
    let obj = outbound.as_object().ok_or(LegacyError::NotAnObject)?;
    let native = match obj.get("vpnte_xray") {
        None | Some(Value::Null) => None,
        Some(graph) => Some(native_graph(graph)?),
    };
    let kind = obj
        .get("type")
        .and_then(Value::as_str)
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| protocol.trim().to_ascii_lowercase());
    // A row imported from a share link (and without a graph) is read again from that link: the new
    // parser keeps only what the provider wrote, and the identity matches the next refresh.
    let reparsed = if native.is_none() {
        reparse(source_uri)
    } else {
        None
    };
    let mut profile = match reparsed {
        // The link holds only what the provider wrote: an explicit `fp=chrome` stays.
        Some(profile) => profile,
        None => {
            if !SUPPORTED.contains(&kind.as_str()) {
                return Err(LegacyError::UnsupportedProtocol(kind));
            }
            let input = Input {
                obj,
                kind: &kind,
                name: String::new(),
                origin: Origin::Legacy,
                shadowtls: None,
            };
            let mut profile =
                singbox::import(input).map_err(|r| LegacyError::Unusable(describe(&r)))?;
            profile.native_xray = native;
            forget_old_defaults(&mut profile);
            profile
        }
    };
    let name = clean_name(name);
    if !name.is_empty() {
        profile.name = name;
    } else if profile.name.is_empty() {
        profile.name = display_name(profile.kind.label()).to_owned();
    }
    Ok(profile)
}

/// `vpnte_xray` read and checked by the graph owner (`xray_native::decode`).
#[cfg(feature = "profiles-native")]
fn native_graph(v: &Value) -> Result<NativeXray, LegacyError> {
    crate::xray_native::decode(v).map_err(|_| LegacyError::InvalidNativeGraph)
}

/// `vpnte_xray` exactly as the Electron app wrote it (`nativeXrayProfile.ts:15-21` checks).
#[cfg(not(feature = "profiles-native"))]
fn native_graph(v: &Value) -> Result<NativeXray, LegacyError> {
    // The serde message is not kept: it can quote parts of the graph.
    let graph: NativeXray =
        serde_json::from_value(v.clone()).map_err(|_| LegacyError::InvalidNativeGraph)?;
    if graph.version != 1 || graph.selected_tag.trim().is_empty() {
        return Err(LegacyError::InvalidNativeGraph);
    }
    Ok(graph)
}

fn forget_old_defaults(profile: &mut Profile) {
    if let Some(tls) = profile.tls.as_mut() {
        if tls.alpn.iter().map(String::as_str).eq(OLD_DEFAULT_ALPN) {
            tls.alpn.clear();
        }
        if tls.fingerprint.as_deref() == Some(OLD_DEFAULT_FINGERPRINT) {
            tls.fingerprint = None;
        }
    }
}

/// The share link of a URI-imported row, read by the URI importer (feed URLs are not links).
#[cfg(feature = "profiles-uri")]
fn reparse(source_uri: Option<&str>) -> Option<Profile> {
    let line = source_uri?.trim();
    let (scheme, _) = line.split_once("://")?;
    if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    crate::uri::parse_uri(line).ok()
}

/// Without the `profiles-uri` package the stored outbound is the only source.
#[cfg(not(feature = "profiles-uri"))]
fn reparse(_source_uri: Option<&str>) -> Option<Profile> {
    None
}

/// English diagnostic of a skip reason (for logs; never contains credentials).
fn describe(reason: &SkipReason) -> String {
    match reason {
        SkipReason::UnknownScheme(s) => format!("unknown protocol {s}"),
        SkipReason::Invalid { scheme, detail } => format!("{scheme}: {detail}"),
        SkipReason::MissingCredential => "missing credential".into(),
        SkipReason::ShadowTlsNeedsInner => {
            "a ShadowTLS outbound needs an inner Shadowsocks outbound".into()
        }
        SkipReason::UnsupportedPlugin(p) => format!("unsupported Shadowsocks plugin {p}"),
        SkipReason::UnsupportedTransport(t) => format!("unsupported transport {t}"),
        SkipReason::Duplicate => "duplicate".into(),
        SkipReason::NativeGraphRejected(d) => format!("Xray graph rejected: {d}"),
    }
}

#[cfg(test)]
mod tests;

/// Rows imported from a share link are read again from it (needs the `profiles-uri` package).
#[cfg(all(test, feature = "profiles-uri"))]
mod reparse_tests;
