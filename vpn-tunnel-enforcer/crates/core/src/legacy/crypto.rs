//! Chromium `safeStorage` as the old Electron build used it on Windows (OSCrypt): an AES-256 key
//! wrapped with DPAPI in `Local State`, `v10` AES-GCM blobs, and the old app's secret envelopes.
use std::path::Path;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Nonce};
use base64::Engine as _;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use serde_json::Value;
use vpnte_base::{AppError, ErrorKind, Msg};
use zeroize::{Zeroize, Zeroizing};

use crate::dpapi;

/// `__vpnteSecretRef` tag of the old envelope `{"__vpnteSecretRef": .., "ciphertext": ..}`.
const SECRET_REF_KIND: &str = "vpnte-safe-storage-v1";
/// Prefix written since PR #21; older builds stored bare base64 (storage §2.6).
const DPAPI_PREFIX: &str = "enc:dpapi:v1:";
/// Plaintext "cipher" of the old unit tests; a real install must never accept it.
const TEST_PREFIX: &str = "test:";
const V10: &[u8] = b"v10";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Header Chromium puts in front of the DPAPI blob in `Local State`.
const KEY_HEADER: &[u8] = b"DPAPI";
const KEY_LEN: usize = 32;
/// `Local State` is a few KB; anything this large is not Chromium's file.
const MAX_LOCAL_STATE_BYTES: u64 = 8 << 20;

/// Node's `Buffer.from(s, "base64")` accepts missing padding and stray trailing bits; so do we.
const NODE_BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// The AES-256 key of the old app's Chromium `safeStorage`, wiped on drop.
pub struct ChromiumKey(Zeroizing<[u8; KEY_LEN]>);

impl std::fmt::Debug for ChromiumKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChromiumKey(..)")
    }
}

#[cfg(test)]
impl ChromiumKey {
    pub(super) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub(super) fn bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// Why the `safeStorage` key could not be loaded from `Local State`.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("`Local State` does not exist")]
    Missing,
    #[error("`Local State` could not be read: {0}")]
    Io(std::io::ErrorKind),
    #[error("`Local State` is not Chromium's JSON document")]
    Malformed,
    #[error("`Local State` has no os_crypt.encrypted_key")]
    NoKey,
    #[error("os_crypt.encrypted_key is not base64")]
    Encoding,
    #[error("os_crypt.encrypted_key does not start with the DPAPI header")]
    Header,
    #[error("DPAPI could not unwrap the key: {0}")]
    Dpapi(windows::core::Error),
    #[error("the unwrapped key has {0} bytes instead of 32")]
    Length(usize),
}

impl From<KeyError> for AppError {
    fn from(err: KeyError) -> Self {
        let kind = match &err {
            KeyError::Io(std::io::ErrorKind::PermissionDenied) | KeyError::Dpapi(_) => {
                ErrorKind::Permission
            }
            KeyError::Missing | KeyError::Io(_) => ErrorKind::Internal,
            _ => ErrorKind::Validation,
        };
        AppError::msg(kind, Msg::new("core.legacy.keyUnavailable")).with_source(err)
    }
}

/// Why one stored secret can never be opened (retrying later does not help).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SecretFault {
    #[error("test cipher (only valid in the old unit tests)")]
    TestCipher,
    #[error("ciphertext is not base64")]
    Encoding,
    #[error("blob is not a well-formed v10 blob")]
    Format,
    #[error("authentication failed (wrong key or damaged blob)")]
    Auth,
    #[error("plaintext is not UTF-8")]
    Utf8,
    #[error("plaintext is not the JSON this position holds")]
    Json,
}

impl From<SecretFault> for AppError {
    fn from(err: SecretFault) -> Self {
        AppError::validation(Msg::new("core.legacy.secretUnreadable")).with_source(err)
    }
}

/// What a secret position of an old document holds. `Debug` never shows the secret.
#[derive(Clone, PartialEq)]
pub enum LegacyValue {
    /// Missing or `null`.
    Absent,
    /// Not an envelope: plaintext from a build before encryption (kept as stored).
    Plain(Value),
    /// Decrypted text.
    Opened(String),
    /// Well-formed ciphertext, but the key is not available now; a later attempt may succeed.
    Locked,
    /// Ciphertext that will never open.
    Invalid(SecretFault),
}

impl std::fmt::Debug for LegacyValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LegacyValue::Absent => f.write_str("Absent"),
            LegacyValue::Plain(_) => f.write_str("Plain(..)"),
            LegacyValue::Opened(text) => write!(f, "Opened({} bytes)", text.len()),
            LegacyValue::Locked => f.write_str("Locked"),
            LegacyValue::Invalid(fault) => write!(f, "Invalid({fault:?})"),
        }
    }
}

/// Loads the `safeStorage` key of the old app: `Local State` → `os_crypt.encrypted_key` → base64 →
/// `DPAPI` header → `CryptUnprotectData` (current user, no entropy, as Chromium wraps it) → 32 bytes.
pub fn chromium_key(legacy: &Path) -> Result<ChromiumKey, KeyError> {
    let bytes = read_local_state(&legacy.join("Local State"))?;
    let state: Value = super::json::parse(&bytes).map_err(|_| KeyError::Malformed)?;
    let encoded = state
        .pointer("/os_crypt/encrypted_key")
        .and_then(Value::as_str)
        .ok_or(KeyError::NoKey)?;
    let wrapped = NODE_BASE64
        .decode(encoded)
        .map_err(|_| KeyError::Encoding)?;
    let sealed = wrapped.strip_prefix(KEY_HEADER).ok_or(KeyError::Header)?;
    // Chromium wraps its data for the current user without entropy.
    let raw = dpapi::unprotect(sealed, None).map_err(KeyError::Dpapi)?;
    if raw.len() != KEY_LEN {
        return Err(KeyError::Length(raw.len()));
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&raw);
    Ok(ChromiumKey(key))
}

fn read_local_state(path: &Path) -> Result<Vec<u8>, KeyError> {
    let io = |e: std::io::Error| match e.kind() {
        std::io::ErrorKind::NotFound => KeyError::Missing,
        kind => KeyError::Io(kind),
    };
    let len = std::fs::metadata(path).map_err(io)?.len();
    if len > MAX_LOCAL_STATE_BYTES {
        return Err(KeyError::Malformed);
    }
    std::fs::read(path).map_err(io)
}

/// Opens a `v10` blob: `b"v10" ‖ nonce[12] ‖ ciphertext ‖ tag[16]`, AES-256-GCM without AAD, UTF-8.
pub fn open_v10(key: &ChromiumKey, blob: &[u8]) -> Result<String, SecretFault> {
    let body = blob.strip_prefix(V10).ok_or(SecretFault::Format)?;
    if body.len() < NONCE_LEN + TAG_LEN {
        return Err(SecretFault::Format);
    }
    let (nonce, sealed) = body.split_at(NONCE_LEN);
    let nonce = Nonce::<Aes256Gcm>::try_from(nonce).map_err(|_| SecretFault::Format)?;
    let cipher = Aes256Gcm::new_from_slice(key.0.as_slice()).map_err(|_| SecretFault::Format)?;
    let plain = cipher
        .decrypt(&nonce, sealed)
        .map_err(|_| SecretFault::Auth)?;
    String::from_utf8(plain).map_err(|err| {
        err.into_bytes().zeroize();
        SecretFault::Utf8
    })
}

/// The `ciphertext` of an old secret envelope, if `v` is one: a non-array object with the exact
/// `__vpnteSecretRef` tag and a string `ciphertext` (storage §2.6).
pub fn secret_ref_ciphertext(v: &Value) -> Option<&str> {
    let obj = v.as_object()?;
    match (obj.get("__vpnteSecretRef"), obj.get("ciphertext")) {
        (Some(Value::String(kind)), Some(Value::String(ct))) if kind == SECRET_REF_KIND => Some(ct),
        _ => None,
    }
}

/// True for an encrypted migration backup `{"__vpnteEncryptedBackup": 1, "contents": ..}`; backups
/// are never imported.
pub fn is_encrypted_backup(v: &Value) -> bool {
    v.get("__vpnteEncryptedBackup").and_then(Value::as_f64) == Some(1.0)
}

/// Classifies a position that holds an envelope in current files and plaintext in files written
/// before encryption. Decided by JSON type, never by `schemaVersion` (storage §2.4 A1).
pub fn legacy_secret(key: Option<&ChromiumKey>, v: Option<&Value>) -> LegacyValue {
    match v {
        None | Some(Value::Null) => LegacyValue::Absent,
        Some(v) => match secret_ref_ciphertext(v) {
            Some(ciphertext) => open_ciphertext(key, ciphertext),
            None => LegacyValue::Plain(v.clone()),
        },
    }
}

/// Opens a bare ciphertext string (an envelope's `ciphertext`, or the adaptive-bypass install
/// secret): optional `enc:dpapi:v1:` prefix, then base64 of a `v10` blob or, before Chromium 80,
/// of a raw DPAPI blob.
pub fn open_ciphertext(key: Option<&ChromiumKey>, text: &str) -> LegacyValue {
    if text.starts_with(TEST_PREFIX) {
        return LegacyValue::Invalid(SecretFault::TestCipher);
    }
    let payload = text.strip_prefix(DPAPI_PREFIX).unwrap_or(text);
    let Some(blob) = decode_payload(payload) else {
        return LegacyValue::Invalid(SecretFault::Encoding);
    };
    if blob.starts_with(V10) {
        return match key {
            Some(key) => match open_v10(key, &blob) {
                Ok(text) => LegacyValue::Opened(text),
                Err(fault) => LegacyValue::Invalid(fault),
            },
            None if blob.len() < V10.len() + NONCE_LEN + TAG_LEN => {
                LegacyValue::Invalid(SecretFault::Format)
            }
            None => LegacyValue::Locked,
        };
    }
    // Pre-v10 blobs are plain DPAPI. Never observed in this app's files (storage §2.6), but Electron's
    // own decryptString accepts them, so the import does too.
    match dpapi::unprotect(&blob, None) {
        Ok(plain) => match std::str::from_utf8(&plain) {
            Ok(text) => LegacyValue::Opened(text.to_owned()),
            Err(_) => LegacyValue::Invalid(SecretFault::Utf8),
        },
        // The Chromium key was unwrapped, so DPAPI works and the blob itself is bad. Without the key
        // DPAPI may be unusable right now (profile not loaded), so a later attempt may succeed.
        Err(_) if key.is_some() => LegacyValue::Invalid(SecretFault::Format),
        Err(_) => LegacyValue::Locked,
    }
}

/// Base64 as the old app checked it (`^[A-Za-z0-9+/]+={0,2}$`) and as Node decoded it.
fn decode_payload(payload: &str) -> Option<Vec<u8>> {
    let data = payload.trim_end_matches('=');
    let well_formed = !data.is_empty()
        && payload.len() - data.len() <= 2
        && data
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
    if !well_formed {
        return None;
    }
    NODE_BASE64.decode(payload).ok()
}
