//! Vectors of spec profiles.md §7 (synthetic values only) plus the §3.3 rules.
use std::net::IpAddr;

use crate::model::{Host, Kind, Profile, SkipReason};
use crate::uri::parse_uri;

mod common;
mod proxy;
mod quic;
mod robust;
mod ss;
mod transport;
mod v2ray;
mod vmess;
mod wg;

/// Parses a line that must import.
fn ok(line: &str) -> Profile {
    match parse_uri(line) {
        Ok(profile) => profile,
        Err(reason) => panic!("{line}: {reason:?}"),
    }
}

/// Parses a line that must be skipped.
fn err(line: &str) -> SkipReason {
    match parse_uri(line) {
        Ok(profile) => panic!("{line} imported: {profile:?}"),
        Err(reason) => reason,
    }
}

fn is_invalid(reason: &SkipReason) -> bool {
    matches!(reason, SkipReason::Invalid { .. })
}

fn domain(name: &str) -> Host {
    Host::Domain(name.to_owned())
}

fn ip(text: &str) -> Host {
    Host::Ip(text.parse::<IpAddr>().unwrap())
}

/// The base64 a provider would write (standard alphabet, padded).
fn b64(text: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(text)
}

/// Percent-encodes a query value the way a careful exporter would.
fn enc(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

fn kind_label(profile: &Profile) -> &'static str {
    profile.kind.label()
}
