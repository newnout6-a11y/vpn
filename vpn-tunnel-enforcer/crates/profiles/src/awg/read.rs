//! Builds an [`Awg`] from the key / value pairs of one WireGuard entry, as `.conf` files, links
//! and mihomo YAML write them.
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};

use super::check::{implied_generation, validate};
use super::field::{AwgField, AwgInvalid};
use super::tags::number;
use crate::model::{Awg, AwgGeneration, AwgRange};

/// Collects the AmneziaWG parameters of one entry.
#[derive(Default)]
pub(crate) struct AwgReader {
    awg: Awg,
    /// Fields whose value did not parse.
    bad: Vec<AwgField>,
    /// mihomo's `version`.
    version: Option<u32>,
}

impl AwgReader {
    /// Reads `key = raw` when `key` names an AmneziaWG parameter; `false`: not one of them.
    pub(crate) fn take(&mut self, key: &str, raw: &str) -> bool {
        let Some(field) = AwgField::from_key(key) else {
            return false;
        };
        self.set(field, raw);
        true
    }

    /// `key` names an AmneziaWG parameter but its value has the wrong shape (a YAML list):
    /// that field is invalid. `false`: not one of them.
    pub(crate) fn reject(&mut self, key: &str) -> bool {
        let field = AwgField::from_key(key).or((key == "version").then_some(AwgField::Version));
        self.bad.extend(field);
        field.is_some()
    }

    /// mihomo's `version`: 3 selects the 3.x implementation, anything else the legacy one.
    pub(crate) fn version(&mut self, raw: &str) {
        match number(raw.trim()) {
            Some(version) => self.version = Some(version),
            None => self.bad.push(AwgField::Version),
        }
    }

    /// A `PersistentKeepalive` written as a range (3.x); single values stay with the peer.
    pub(crate) fn keepalive_range(&mut self, range: AwgRange) {
        self.awg.keepalive_range = Some(range);
    }

    /// One parameter; a blank value is absent (mihomo writes `i3: ""`).
    pub(crate) fn set(&mut self, field: AwgField, raw: &str) {
        use AwgField::*;
        let raw = raw.trim();
        if raw.is_empty() {
            return;
        }
        let awg = &mut self.awg;
        let at = |list: &[AwgField]| list.iter().position(|&f| f == field).unwrap_or(0);
        let ok = match field {
            Jc => put(&mut awg.jc, number(raw)),
            Jmin => put(&mut awg.jmin, number(raw)),
            Jmax => put(&mut awg.jmax, number(raw)),
            S1 | S2 | S3 | S4 => put(&mut awg.s[at(&AwgField::S)], number(raw)),
            H1 | H2 | H3 | H4 => put(&mut awg.h[at(&AwgField::H)], AwgRange::parse(raw)),
            I1 | I2 | I3 | I4 | I5 => put(&mut awg.i[at(&AwgField::I)], Some(raw.to_owned())),
            J1 | J2 | J3 => put(&mut awg.j[at(&AwgField::J)], Some(raw.to_owned())),
            Itime => put(&mut awg.itime, number(raw)),
            HeaderProtectionKey => put(&mut awg.header_protection_key, Some(padded_key(raw))),
            ContentPaddingAddition => put(&mut awg.content_padding, AwgRange::parse(raw)),
            RekeyAfterTime | RekeyTimeout | RejectAfterTime | KeepaliveTimeout
            | MaxHandshakeAttempts => {
                put(&mut awg.timers[at(&AwgField::TIMERS)], AwgRange::parse(raw))
            }
            PersistentKeepalive => put(&mut awg.keepalive_range, AwgRange::parse(raw)),
            RandomTrailers => put(&mut awg.random_trailers, switch(raw)),
            DisableCookies => put(&mut awg.disable_cookies, switch(raw)),
            Version => {
                self.version(raw);
                true
            }
        };
        if !ok {
            self.bad.push(field);
        }
    }

    /// `Ok(None)`: no mechanism is on, so the entry is plain WireGuard and runs as such.
    /// Otherwise the parameters with their generation, or every field that is wrong.
    pub(crate) fn finish(mut self) -> Result<Option<Awg>, AwgInvalid> {
        let implied = implied_generation(&self.awg);
        self.awg.generation = match self.version {
            Some(3) => AwgGeneration::V3,
            // mihomo would run 3.x parameters on its legacy implementation.
            Some(_) if implied == AwgGeneration::V3 => {
                self.bad.push(AwgField::Version);
                implied
            }
            _ => implied,
        };
        let on = active(&self.awg);
        if on && let Err(invalid) = validate(&self.awg) {
            self.bad.extend(invalid.fields);
        }
        match AwgInvalid::of(self.bad) {
            Some(invalid) => Err(invalid),
            None => Ok(on.then_some(self.awg)),
        }
    }
}

fn put<T>(slot: &mut Option<T>, value: Option<T>) -> bool {
    let ok = value.is_some();
    if ok {
        *slot = value;
    }
    ok
}

/// AmneziaVPN writes `on` / `off`, mihomo YAML booleans.
fn switch(raw: &str) -> Option<bool> {
    match raw.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" => Some(true),
        "off" | "false" | "no" | "0" => Some(false),
        _ => None,
    }
}

/// A 32-byte key in the padded form mihomo decodes; anything else is kept for `validate`.
fn padded_key(raw: &str) -> String {
    match STANDARD
        .decode(raw)
        .or_else(|_| STANDARD_NO_PAD.decode(raw))
    {
        Ok(bytes) if bytes.len() == 32 => STANDARD.encode(bytes),
        _ => raw.to_owned(),
    }
}

/// Some mechanism differs from plain WireGuard. `Jmin` / `Jmax` without `Jc`, `Itime` without
/// chains and switches that are off change nothing on the wire.
fn active(awg: &Awg) -> bool {
    let on = |v: Option<u32>| v.is_some_and(|v| v > 0);
    let custom_header = |n: usize, h: &Option<AwgRange>| {
        h.is_some_and(|h| h != AwgRange::single(n as u32 + 1) && h != AwgRange::single(0))
    };
    on(awg.jc)
        || awg.s.iter().any(|s| on(*s))
        || awg.h.iter().enumerate().any(|(n, h)| custom_header(n, h))
        || awg.i.iter().chain(&awg.j).any(Option::is_some)
        || awg.header_protection_key.is_some()
        || awg.content_padding.is_some_and(|p| p.max > 0)
        || awg.timers.iter().flatten().any(|t| t.max > 0)
        || awg.keepalive_range.is_some()
        || awg.random_trailers == Some(true)
        || awg.disable_cookies == Some(true)
}
