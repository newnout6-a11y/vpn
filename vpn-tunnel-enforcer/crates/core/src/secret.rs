//! A string secret that is stored DPAPI-wrapped and only ever held in plaintext in memory.
//!
//! Stored form: `dpapi:v1:` + base64(`CryptProtectData(utf8, entropy = "VPNTE/secret/v1")`), CurrentUser
//! scope. A stored value that cannot be opened (copied from another PC or account, DPAPI master key lost
//! after a password reset, unknown prefix) becomes [`Secret::is_locked`] and is written back byte-for-byte,
//! so the document stays usable and nothing is lost until the user re-imports (storage B29).
use std::fmt;
use std::sync::OnceLock;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::dpapi;

const PREFIX: &str = "dpapi:v1:";
const ENTROPY: &[u8] = b"VPNTE/secret/v1";

/// Why a secret could not be sealed, opened or interpreted.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// The stored value cannot be decrypted by this Windows account.
    #[error("secret is locked: it cannot be decrypted by this Windows account")]
    Locked,
    /// DPAPI refused the operation.
    #[error("DPAPI call failed")]
    Dpapi(#[from] windows::core::Error),
    /// Sealing and opening again did not give the original value back.
    #[error("secret did not survive a seal/open round trip")]
    RoundTrip,
    /// The plaintext is not the JSON the caller expected.
    #[error("secret payload is not the expected JSON")]
    Json(#[from] serde_json::Error),
}

/// A secret string: plaintext in memory (wiped on drop), DPAPI ciphertext on disk. Serialise the
/// documents holding it by reference: a serialised clone (`serde(into)`) caches the ciphertext on
/// the clone, and the next save encrypts again.
#[derive(Clone)]
pub struct Secret(Inner);

#[derive(Clone)]
enum Inner {
    /// `sealed` caches the ciphertext so an unchanged document re-serialises to identical bytes
    /// (DPAPI output is salted: sealing twice gives two different strings).
    Open {
        plain: Zeroizing<String>,
        sealed: OnceLock<String>,
    },
    Locked {
        sealed: String,
    },
}

impl Secret {
    /// Wraps a plaintext value; it is sealed lazily, on first serialisation.
    pub fn new(plain: impl Into<String>) -> Self {
        Self(Inner::Open {
            plain: Zeroizing::new(plain.into()),
            sealed: OnceLock::new(),
        })
    }

    /// Serialises `value` to JSON text and wraps it (outbound fragments, whole-object secrets).
    pub fn from_json<T: Serialize + ?Sized>(value: &T) -> Result<Self, SecretError> {
        Ok(Self::new(serde_json::to_string(value)?))
    }

    /// Opens a stored value; anything that does not decrypt becomes a locked secret.
    pub fn from_stored(stored: String) -> Self {
        match open(&stored) {
            Some(plain) => Self(Inner::Open {
                plain,
                sealed: OnceLock::from(stored),
            }),
            None => Self(Inner::Locked { sealed: stored }),
        }
    }

    /// The plaintext, or `None` when the stored value could not be decrypted.
    pub fn expose(&self) -> Option<&str> {
        match &self.0 {
            Inner::Open { plain, .. } => Some(plain.as_str()),
            Inner::Locked { .. } => None,
        }
    }

    /// Parses the plaintext as JSON (the counterpart of [`Secret::from_json`]).
    pub fn expose_json<T: DeserializeOwned>(&self) -> Result<T, SecretError> {
        let plain = self.expose().ok_or(SecretError::Locked)?;
        Ok(serde_json::from_str(plain)?)
    }

    /// True when the stored value could not be decrypted on this machine / account.
    pub fn is_locked(&self) -> bool {
        matches!(self.0, Inner::Locked { .. })
    }

    /// The stored form (`dpapi:v1:…`), sealing once and caching the result.
    pub fn sealed(&self) -> Result<&str, SecretError> {
        match &self.0 {
            Inner::Locked { sealed } => Ok(sealed),
            Inner::Open { plain, sealed } => {
                if let Some(done) = sealed.get() {
                    return Ok(done);
                }
                let sealed_bytes = dpapi::protect(plain.as_bytes(), Some(ENTROPY))?;
                let fresh = format!("{PREFIX}{}", B64.encode(sealed_bytes));
                // A concurrent first serialisation may have won the race; both values are valid.
                Ok(sealed.get_or_init(|| fresh))
            }
        }
    }

    /// Seals, opens the result again and compares: proves a re-wrapped secret is readable before an
    /// import commits it (storage §3.2 read-back rule). A locked secret fails with [`SecretError::Locked`].
    pub fn verify(&self) -> Result<(), SecretError> {
        let plain = self.expose().ok_or(SecretError::Locked)?;
        match open(self.sealed()?) {
            Some(back) if back.as_str() == plain => Ok(()),
            _ => Err(SecretError::RoundTrip),
        }
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Inner::Open { plain: a, .. }, Inner::Open { plain: b, .. }) => a == b,
            (Inner::Locked { sealed: a }, Inner::Locked { sealed: b }) => a == b,
            _ => false,
        }
    }
}

impl Eq for Secret {}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(if self.is_locked() {
            "Secret(<locked>)"
        } else {
            "Secret(<redacted>)"
        })
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<secret>")
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Fail closed: if DPAPI cannot seal, the whole document write fails; never plaintext.
        let sealed = self
            .sealed()
            .map_err(|e| serde::ser::Error::custom(format_args!("cannot seal secret: {e}")))?;
        serializer.serialize_str(sealed)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Secret::from_stored)
    }
}

/// Decrypts a stored value; `None` for an unknown prefix, bad base64, a DPAPI refusal or non-UTF-8.
fn open(stored: &str) -> Option<Zeroizing<String>> {
    let payload = stored.strip_prefix(PREFIX)?;
    let blob = B64.decode(payload).ok()?;
    let plain = dpapi::unprotect(&blob, Some(ENTROPY)).ok()?;
    let text = std::str::from_utf8(&plain).ok()?;
    Some(Zeroizing::new(text.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AT-01-001: the stored form never carries the plaintext and opens again (real DPAPI).
    #[test]
    fn round_trip_through_dpapi() {
        let s = Secret::new("FAKE-PASSWORD");
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.starts_with("\"dpapi:v1:"), "{json}");
        assert!(!json.contains("FAKE-PASSWORD"));
        let back: Secret = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expose(), Some("FAKE-PASSWORD"));
        assert!(!back.is_locked());
        assert_eq!(back, s);
        s.verify().unwrap();
    }

    /// AT-01-001: whole-object secrets hold JSON text.
    #[test]
    fn json_helper_round_trips() {
        let value = serde_json::json!({"uuid": "FAKE-UUID", "tls": {"enabled": true}});
        let s = Secret::from_json(&value).unwrap();
        let stored = serde_json::to_value(&s).unwrap();
        let back: Secret = serde_json::from_value(stored).unwrap();
        assert_eq!(back.expose_json::<serde_json::Value>().unwrap(), value);
    }

    /// AT-09-013: serialising an unchanged secret again (also after a clone) does not re-encrypt.
    #[test]
    fn sealed_form_is_cached() {
        let s = Secret::new("FAKE-TOKEN");
        let first = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::to_string(&s).unwrap(), first);
        assert_eq!(serde_json::to_string(&s.clone()).unwrap(), first);
        // DPAPI is salted: a fresh secret with the same plaintext seals differently.
        assert_ne!(
            serde_json::to_string(&Secret::new("FAKE-TOKEN")).unwrap(),
            first
        );
        // A value read from disk keeps its original bytes.
        let read: Secret = serde_json::from_str(&first).unwrap();
        assert_eq!(serde_json::to_string(&read).unwrap(), first);
    }

    /// B29 / AT-01-010: undecryptable values stay locked and are written back byte-for-byte.
    #[test]
    fn locked_values_round_trip_unchanged() {
        let foreign = format!(
            "{PREFIX}{}",
            B64.encode(b"not a DPAPI blob from this account")
        );
        for stored in [
            foreign.as_str(),
            "dpapi:v1:invalid!",
            "dpapi:v2:QUJD",
            "plain text",
            "",
        ] {
            let s: Secret = serde_json::from_value(serde_json::json!(stored)).unwrap();
            assert!(s.is_locked(), "{stored}");
            assert_eq!(s.expose(), None);
            assert!(matches!(
                s.expose_json::<serde_json::Value>(),
                Err(SecretError::Locked)
            ));
            assert!(matches!(s.verify(), Err(SecretError::Locked)));
            assert_eq!(serde_json::to_value(&s).unwrap(), serde_json::json!(stored));
        }
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let json = serde_json::to_string(&Secret::new("")).unwrap();
        let back: Secret = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expose(), Some(""));
    }

    #[test]
    fn non_string_is_a_decode_error() {
        assert!(serde_json::from_str::<Secret>("42").is_err());
    }

    #[test]
    fn never_printed() {
        let s = Secret::new("FAKE-PASSWORD");
        assert_eq!(format!("{s}"), "<secret>");
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        let locked = Secret::from_stored("x".into());
        assert_eq!(format!("{locked:?}"), "Secret(<locked>)");
    }
}
