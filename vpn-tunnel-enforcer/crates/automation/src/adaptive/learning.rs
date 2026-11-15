//! The learning store `adaptive.json`: per (network, profile) the compatibility mode that worked.
//!
//! Keys are HMAC-SHA256 values under a per-install secret (DPAPI-sealed in the same file), so the
//! file reveals no SSID, gateway, MAC address, server or credential. The secret is never written in
//! plaintext: when DPAPI refuses to seal it, or a stored secret cannot be opened (another account
//! or PC), learning is off for this run and the file is left untouched (old AB:51-79 semantics,
//! minus the throw that failed the connect).
use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use vpnte_base::AppResult;
use vpnte_base::types::{AdaptiveMode, UnixMs};
use vpnte_core::secret::Secret;
use vpnte_core::store::{Document, Store};
use zeroize::Zeroizing;

use super::ProfileView;
use super::identity::NetworkSnapshot;

/// A learned mode expires 30 days after it was last confirmed (AB:26).
pub const TTL_MS: i64 = 30 * 24 * 3600 * 1000;
/// At most this many records; the most recently used ones are kept (AB:27).
pub const MAX_RECORDS: usize = 24;
/// Prefix of current keys. Other prefixes (another fingerprint format) are ignored and pruned.
const KEY_VERSION: &str = "v3:";
/// Top-level outbound keys that do not describe the server (AB:133-140).
const IGNORED_KEYS: [&str; 5] = [
    "tag",
    "detour",
    "bind_interface",
    "domain_strategy",
    "domain_resolver",
];

/// What worked for one (network, profile) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LearnedRecord {
    pub mode: AdaptiveMode,
    pub learned_at: UnixMs,
    pub last_used_at: UnixMs,
    pub expires_at: UnixMs,
}

/// The `adaptive.json` document.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AdaptiveDoc {
    /// Base64 of the 32-byte HMAC key, DPAPI-sealed on disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<Secret>,
    /// A malformed record (hand edit) is dropped instead of making the whole file read-only.
    #[serde(default, deserialize_with = "crate::lenient::map")]
    pub learning: BTreeMap<String, LearnedRecord>,
}

impl Document for AdaptiveDoc {
    const FILE: &'static str = "adaptive.json";
    const VERSION: u32 = 1;
    const HOLDS_SECRETS: bool = true;
}

/// Drops records of other key versions and expired ones; keeps the `MAX_RECORDS` most recently used.
pub fn compact(learning: &mut BTreeMap<String, LearnedRecord>, now: UnixMs) {
    learning.retain(|k, r| k.starts_with(KEY_VERSION) && r.expires_at > now);
    if learning.len() > MAX_RECORDS {
        let mut by_use: Vec<(UnixMs, String)> = learning
            .iter()
            .map(|(k, r)| (r.last_used_at, k.clone()))
            .collect();
        by_use.sort_by(|a, b| b.cmp(a));
        for (_, key) in by_use.into_iter().skip(MAX_RECORDS) {
            learning.remove(&key);
        }
    }
}

/// Canonical JSON: object keys sorted, arrays in order, scalars as JSON. Written out by hand
/// because the workspace enables serde_json's `preserve_order`, so `Map` keeps insertion order.
pub(crate) fn canonical_json(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                canonical_json(&map[key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// The text a profile fingerprint is computed over: the outbound without its routing-only keys,
/// plus the client device and uTLS fingerprint the user picked.
pub(crate) fn profile_material(profile: &ProfileView) -> String {
    fn strip(v: &Value) -> Value {
        match v {
            Value::Object(map) => Value::Object(
                map.iter()
                    .filter(|(k, _)| !IGNORED_KEYS.contains(&k.as_str()))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            ),
            // A chained outbound (Shadowsocks + ShadowTLS): each element carries its own tag.
            Value::Array(items) => Value::Array(items.iter().map(strip).collect()),
            other => other.clone(),
        }
    }
    let material = serde_json::json!({
        "connection": strip(&profile.outbound),
        "clientDevice": profile.client_device,
        "clientFingerprint": profile.client_fingerprint,
    });
    let mut out = String::new();
    canonical_json(&material, &mut out);
    out
}

/// The learning store as adaptive bypass uses it: the HMAC key plus the document.
pub struct Learning {
    store: Arc<Store<AdaptiveDoc>>,
    /// `None`: learning is off for this run (no lookups, no writes).
    key: Option<Zeroizing<[u8; 32]>>,
}

impl Learning {
    /// Opens the key: the stored secret, or a fresh one sealed into the file. A secret that cannot
    /// be opened stays on disk untouched; a refused seal persists nothing. Both turn learning off.
    pub fn open(store: Arc<Store<AdaptiveDoc>>) -> Self {
        let key = match store.read(|d| d.secret.clone()) {
            Some(secret) => {
                let key = secret.expose().and_then(decode_key);
                if key.is_none() {
                    tracing::warn!(
                        "adaptive.json: stored secret unreadable; learning off this run"
                    );
                }
                key
            }
            None => fresh_key().filter(|key| {
                let text = Zeroizing::new(STANDARD.encode(key.as_slice()));
                match store.update(|d| d.secret = Some(Secret::new(text.as_str()))) {
                    Ok(()) => true,
                    Err(err) => {
                        tracing::warn!(
                            "adaptive.json: secret not saved ({err}); learning off this run"
                        );
                        false
                    }
                }
            }),
        };
        Self { store, key }
    }

    /// Learning works this run (the key is persisted).
    pub fn enabled(&self) -> bool {
        self.key.is_some()
    }

    /// `"v3:<network hmac>:<profile hmac>"`, or `None` while learning is off.
    pub fn key(&self, network: &NetworkSnapshot, profile: &ProfileView) -> Option<String> {
        let key = self.key.as_ref()?;
        let net = mac(key, network.text().as_bytes());
        let prof = mac(key, profile_material(profile).as_bytes());
        Some(format!("{KEY_VERSION}{net}:{prof}"))
    }

    /// The learned mode for `key` if `usable` accepts it; a hit counts as a use (keeps it fresh).
    pub fn lookup(
        &self,
        key: &str,
        usable: impl Fn(AdaptiveMode) -> bool,
        now: UnixMs,
    ) -> Option<AdaptiveMode> {
        self.key.as_ref()?;
        let mut hit = None;
        self.write(|learning| {
            compact(learning, now);
            if let Some(rec) = learning.get_mut(key).filter(|r| usable(r.mode)) {
                rec.last_used_at = now;
                hit = Some(rec.mode);
            }
        });
        hit
    }

    /// Remembers `mode` for `key` for 30 days (only compatibility modes are worth remembering).
    pub fn learn(&self, key: &str, mode: AdaptiveMode, now: UnixMs) {
        if self.key.is_none() || mode == AdaptiveMode::Baseline {
            return;
        }
        self.write(|learning| {
            let rec = LearnedRecord {
                mode,
                learned_at: now,
                last_used_at: now,
                expires_at: now + TTL_MS,
            };
            learning.insert(key.to_owned(), rec);
            compact(learning, now);
        });
    }

    /// Forgets `key` (a reused mode failed: fix A1).
    pub fn forget(&self, key: &str) {
        if self.key.is_some() {
            self.write(|learning| {
                learning.remove(key);
            });
        }
    }

    /// Deletes every record (the user's «reset» button); the secret stays.
    pub fn clear(&self) -> AppResult<()> {
        self.store.update(|d| d.learning.clear())
    }

    fn write(&self, f: impl FnOnce(&mut BTreeMap<String, LearnedRecord>)) {
        if let Err(err) = self.store.update(|d| f(&mut d.learning)) {
            tracing::warn!("adaptive.json not written: {err}");
        }
    }
}

fn decode_key(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(STANDARD.decode(text).ok()?);
    let mut key = Zeroizing::new([0u8; 32]);
    (bytes.len() == 32).then(|| {
        key.copy_from_slice(&bytes);
        key
    })
}

fn fresh_key() -> Option<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    match getrandom::fill(key.as_mut_slice()) {
        Ok(()) => Some(key),
        Err(err) => {
            tracing::warn!("adaptive: OS random source failed ({err}); learning off this run");
            None
        }
    }
}

/// HMAC-SHA256, base64url without padding.
fn mac(key: &[u8; 32], data: &[u8]) -> String {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else {
        unreachable!("HMAC accepts keys of any length")
    };
    mac.update(data);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests;
