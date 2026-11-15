//! AmneziaVPN share keys (`vpn://…`, what AmneziaVPN's "Share" and its QR codes hand out).
//!
//! Layout (amnezia-client `ExportController::generateVpnUrl`, `ImportController`): base64url
//! without padding of Qt's `qCompress` output, a 4-byte big-endian length followed by a zlib
//! stream (AmneziaVPN falls back to the raw bytes when that does not inflate). The text inside
//! is an AmneziaVPN server description (JSON with `containers`, see [`containers`]), or a bare
//! wg-quick / AmneziaWG `.conf`, an Xray JSON config, or an OpenVPN config.
use std::io::Read;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use flate2::read::ZlibDecoder;
use serde_json::Value;

use crate::model::{Note, ParseReport, Profile, SkipReason};
use crate::text::MAX_INPUT_BYTES;
use crate::{json, wg_ini};

mod containers;

pub use containers::parse_document;

/// The scheme of AmneziaVPN keys.
pub const SCHEME: &str = "vpn";

/// What a key carries once decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// JSON (an AmneziaVPN server description or an Xray config) or a `.conf`: import it.
    Text(String),
    /// A protocol no engine of this app runs (`OpenVPN`).
    Unsupported(&'static str),
}

/// The payload of `vpn://…`; `None` when the input is not such a key or does not decode
/// (damaged, truncated). The size is bounded by [`MAX_INPUT_BYTES`] after inflating.
pub fn decode_key(link: &str) -> Option<Payload> {
    let link = link.trim();
    let (scheme, payload) = link.split_once("://")?;
    if !scheme.eq_ignore_ascii_case(SCHEME) {
        return None;
    }
    let payload = payload.trim().trim_end_matches('=');
    // Qt writes the URL alphabet; keys retyped by hand or other tools use the standard one.
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| STANDARD_NO_PAD.decode(payload))
        .ok()?;
    let data = q_uncompress(&bytes).unwrap_or(bytes);
    let text = String::from_utf8(data).ok()?;
    let text = text.trim_start_matches('\u{feff}').trim();
    if text.starts_with('{') || (text.contains("[Interface]") && text.contains("[Peer]")) {
        Some(Payload::Text(text.to_owned()))
    } else if text.contains("client") && (text.contains("dev tun") || text.contains("dev tap")) {
        // AmneziaVPN's own test for an OpenVPN config.
        Some(Payload::Unsupported("OpenVPN"))
    } else {
        None
    }
}

/// Qt `qUncompress`: `None` unless the whole stream inflates to the announced length.
fn q_uncompress(bytes: &[u8]) -> Option<Vec<u8>> {
    let (len, stream) = bytes.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_be_bytes(*len)).ok()?;
    if len == 0 || len > MAX_INPUT_BYTES {
        return None;
    }
    let mut out = Vec::with_capacity(len);
    ZlibDecoder::new(stream)
        .take(MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut out)
        .ok()?;
    (out.len() == len).then_some(out)
}

/// Everything a decoded payload holds, as the other importers read it.
pub fn parse_payload(text: &str) -> ParseReport {
    // `parse_json` reads a server description first, an Xray config otherwise.
    if let Ok(value) = serde_json::from_str::<Value>(text) {
        return json::parse_json(&value);
    }
    let mut report = ParseReport::default();
    match wg_ini::parse_wg_ini(text) {
        Some(Ok(profile)) => report.profiles.push(profile),
        Some(Err(reason)) => report.skipped.push(skipped(reason)),
        None => report.skipped.push(skipped(invalid("carries no server"))),
    }
    report
}

/// One `vpn://` line among other keys ([`crate::uri::parse_uri`]): the one server it carries.
/// Containers it carries next to that server become notes; a pasted key alone goes through
/// [`crate::deeplink::unwrap_deeplink`] and reports each of them.
pub fn parse_key(line: &str) -> Result<Profile, SkipReason> {
    let report = match decode_key(line) {
        Some(Payload::Text(text)) => parse_payload(&text),
        Some(Payload::Unsupported(protocol)) => {
            return Err(SkipReason::UnsupportedProtocol(protocol.to_owned()));
        }
        None => return Err(invalid("does not decode (damaged or truncated)")),
    };
    let mut profiles = report.profiles.into_iter();
    match (profiles.next(), profiles.next()) {
        (Some(mut profile), None) => {
            for s in report.skipped {
                let name = match s.reason {
                    SkipReason::UnsupportedProtocol(name) => name,
                    _ => "AmneziaVPN container".to_owned(),
                };
                profile.notes.push(Note::UnsupportedField(name));
            }
            Ok(profile)
        }
        (None, _) => Err(report
            .skipped
            .into_iter()
            .next()
            .map_or_else(|| invalid("carries no server"), |s| s.reason)),
        (Some(_), Some(_)) => Err(invalid(
            "carries several servers: paste this key on its own",
        )),
    }
}

fn invalid(detail: &str) -> SkipReason {
    SkipReason::Invalid {
        scheme: SCHEME.to_owned(),
        detail: detail.to_owned(),
    }
}

fn skipped(reason: SkipReason) -> crate::model::Skipped {
    crate::model::Skipped {
        excerpt: format!("{SCHEME}://…"),
        reason,
    }
}

#[cfg(test)]
mod tests;
