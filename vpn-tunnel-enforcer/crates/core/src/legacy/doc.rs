//! One electron-store document of the old app: schema admission and secret opening.
use serde_json::{Map, Value};
use vpnte_base::{AppError, ErrorKind, Msg};

use super::crypto::{
    ChromiumKey, LegacyValue, SecretFault, is_encrypted_backup, open_ciphertext,
    secret_ref_ciphertext,
};
use super::json;

/// Old stores the import may read, with the newest `schemaVersion` the old app wrote (storage §2.3).
/// `live-server-checks` is plain JSON with its own reader; the others are electron-store files.
pub const STORES: &[(&str, u64)] = &[
    ("settings", 2),
    ("server-picker", 2),
    ("server-groups", 0),
    ("adaptive-bypass", 0),
    ("connection-history", 0),
    ("dns-profiles", 0),
    ("domain-intelligence", 0),
    ("domain-routing", 0),
    ("external-proxy-leases", 0),
    ("granular-kill-switch", 0),
    ("i18n", 0),
    ("notification-prefs", 0),
    ("profile-rotation", 0),
    ("scheduler", 0),
    ("smart-route-rule-sets", 0),
    ("speed-test", 0),
    ("split-tunnel", 0),
    ("themes", 0),
    ("traffic-domains", 0),
    ("url-availability", 0),
    ("live-server-checks", 1),
];

/// Secret positions whose plaintext is JSON text (`encryptJsonSecret`, storage §2.6); every other
/// envelope holds a plain string. `*` matches any array index.
const JSON_POSITIONS: &[(&str, &[&str])] = &[
    ("settings", &["settings", "directVpnCachedProfiles"]),
    ("server-picker", &["profiles", "*", "outbound"]),
    ("server-groups", &["groups", "*"]),
];

/// Ciphertext stored as a bare string, without an envelope (storage §2.4 H7).
const BARE_POSITIONS: &[(&str, &[&str])] = &[("adaptive-bypass", &["encryptedInstallSecret"])];

/// Key of the object that stands in for a secret whose key is not available (see [`is_locked`]).
pub const LOCKED_MARKER: &str = "__vpnteLocked";

/// True for the stand-in [`LegacyDoc::open`] leaves where a secret could not be opened yet.
pub fn is_locked(v: &Value) -> bool {
    v.get(LOCKED_MARKER) == Some(&Value::Bool(true))
}

/// Why an old document is not imported.
#[derive(Debug, thiserror::Error)]
pub enum DocError {
    #[error("{0:?} is not a known store of the old app")]
    Unregistered(String),
    #[error("the file could not be read: {0}")]
    Io(#[from] std::io::Error),
    #[error("the file is larger than {} MiB", super::dir::MAX_DOC_BYTES >> 20)]
    TooLarge,
    #[error("the file is not a JSON object")]
    Corrupt,
    #[error("the file is an encrypted migration backup")]
    Backup,
    #[error("schemaVersion is not a non-negative integer")]
    InvalidVersion,
    #[error("schemaVersion {found} is newer than {supported}")]
    Newer { found: u64, supported: u64 },
}

impl DocError {
    /// Short reason for the import report (`Skipped(reason)`).
    pub fn reason(&self) -> &'static str {
        match self {
            DocError::Unregistered(_) => "unregistered",
            DocError::Io(_) => "unreadable",
            DocError::TooLarge => "too-large",
            DocError::Corrupt => "corrupt",
            DocError::Backup => "backup",
            DocError::InvalidVersion => "invalid",
            DocError::Newer { .. } => "newer",
        }
    }
}

impl From<DocError> for AppError {
    fn from(err: DocError) -> Self {
        let (kind, key) = match &err {
            DocError::Unregistered(_) => return AppError::internal(err),
            // Same category as any other I/O failure (the base mapping), with an import message.
            DocError::Io(io) => (
                AppError::from(std::io::Error::from(io.kind())).kind,
                "core.legacy.fileUnreadable",
            ),
            DocError::Newer { .. } => (ErrorKind::Conflict, "core.legacy.fileNewer"),
            _ => (ErrorKind::Validation, "core.legacy.fileInvalid"),
        };
        AppError::msg(kind, Msg::new(key)).with_source(err)
    }
}

/// An admitted document of one old store, exactly as stored (envelopes intact). Never written back.
/// `Debug` omits the content: files from before encryption hold keys in plaintext.
#[derive(Clone, PartialEq)]
pub struct LegacyDoc {
    store: &'static str,
    version: u64,
    raw: Value,
}

impl std::fmt::Debug for LegacyDoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LegacyDoc")
            .field("store", &self.store)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// A document with its secrets opened, plus what could not be opened. `Debug` omits `value`.
#[derive(Clone, PartialEq)]
pub struct OpenedDoc {
    /// Every secret replaced: decrypted text, parsed JSON at the JSON positions, the locked
    /// stand-in ([`is_locked`]) when the key is unavailable, or `null` when it can never open.
    pub value: Value,
    /// Number of secrets decrypted.
    pub opened: u32,
    /// JSON pointers (RFC 6901) of the secrets that wait for the key.
    pub locked: Vec<String>,
    /// JSON pointers of the secrets that can never be opened, with the reason.
    pub invalid: Vec<(String, SecretFault)>,
}

impl std::fmt::Debug for OpenedDoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedDoc")
            .field("opened", &self.opened)
            .field("locked", &self.locked)
            .field("invalid", &self.invalid)
            .finish_non_exhaustive()
    }
}

impl LegacyDoc {
    /// Parses the bytes of `<store>.json` leniently and admits them (see [`LegacyDoc::from_value`]).
    pub fn parse(store: &str, bytes: &[u8]) -> Result<Self, DocError> {
        let raw = json::parse(bytes).map_err(|_| DocError::Corrupt)?;
        Self::from_value(store, raw)
    }

    /// Admits a parsed document the way the old app did: a JSON object whose `schemaVersion` is
    /// absent (0) or a non-negative integer no newer than the store's (storage §2.2-2.3).
    pub fn from_value(store: &str, raw: Value) -> Result<Self, DocError> {
        let (store, supported) = STORES
            .iter()
            .find(|(name, _)| *name == store)
            .copied()
            .ok_or_else(|| DocError::Unregistered(store.to_owned()))?;
        let Value::Object(obj) = &raw else {
            return Err(DocError::Corrupt);
        };
        if is_encrypted_backup(&raw) {
            return Err(DocError::Backup);
        }
        let version = schema_version(obj)?;
        if version > supported {
            return Err(DocError::Newer {
                found: version,
                supported,
            });
        }
        Ok(Self {
            store,
            version,
            raw,
        })
    }

    /// Store name, e.g. `server-picker`.
    pub fn store(&self) -> &'static str {
        self.store
    }

    /// Stored `schemaVersion` (absent = 0). Says nothing about encryption: decide by JSON type.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The document as stored.
    pub fn raw(&self) -> &Value {
        &self.raw
    }

    /// Returns the document with every secret envelope (and the bare ciphertext of
    /// `adaptive-bypass`) opened with `key`; plaintext from builds before encryption stays as is.
    pub fn open(&self, key: Option<&ChromiumKey>) -> OpenedDoc {
        let mut opener = Opener {
            store: self.store,
            key,
            path: Vec::new(),
            opened: 0,
            locked: Vec::new(),
            invalid: Vec::new(),
        };
        let mut value = self.raw.clone();
        opener.walk(&mut value);
        OpenedDoc {
            value,
            opened: opener.opened,
            locked: opener.locked,
            invalid: opener.invalid,
        }
    }
}

/// `schemaVersion`: absent → 0; anything but a non-negative safe integer (JS `Number.isSafeInteger`,
/// so `2.0` counts as 2) is invalid, including `null`.
fn schema_version(obj: &Map<String, Value>) -> Result<u64, DocError> {
    /// JS `Number.MAX_SAFE_INTEGER`.
    const MAX_SAFE: u64 = (1 << 53) - 1;
    let Some(v) = obj.get("schemaVersion") else {
        return Ok(0);
    };
    let n = match (v.as_u64(), v.as_f64()) {
        (Some(n), _) => n,
        (None, Some(f)) if f.fract() == 0.0 && (0.0..=MAX_SAFE as f64).contains(&f) => f as u64,
        _ => return Err(DocError::InvalidVersion),
    };
    if n <= MAX_SAFE {
        Ok(n)
    } else {
        Err(DocError::InvalidVersion)
    }
}

/// Walks a document copy and replaces every secret in place, tracking the JSON path.
struct Opener<'k> {
    store: &'static str,
    key: Option<&'k ChromiumKey>,
    path: Vec<String>,
    opened: u32,
    locked: Vec<String>,
    invalid: Vec<(String, SecretFault)>,
}

impl Opener<'_> {
    fn walk(&mut self, v: &mut Value) {
        // Positions are fixed by the old code, so nested envelopes inside opened JSON do not exist.
        // An empty install secret counted as absent in the old app (`if (encrypted)`).
        let found = match v {
            Value::String(text) if !text.is_empty() && self.at(BARE_POSITIONS) => {
                Some(open_ciphertext(self.key, text))
            }
            _ => secret_ref_ciphertext(v).map(|text| open_ciphertext(self.key, text)),
        };
        if let Some(found) = found {
            *v = self.settle(found);
            return;
        }
        match v {
            Value::Object(map) => {
                for (key, child) in map.iter_mut() {
                    self.path.push(key.clone());
                    self.walk(child);
                    self.path.pop();
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter_mut().enumerate() {
                    self.path.push(index.to_string());
                    self.walk(child);
                    self.path.pop();
                }
            }
            _ => {}
        }
    }

    fn settle(&mut self, found: LegacyValue) -> Value {
        match found {
            LegacyValue::Opened(text) if self.at(JSON_POSITIONS) => {
                match json::parse(text.as_bytes()) {
                    Ok(value) => {
                        self.opened += 1;
                        value
                    }
                    Err(_) => self.fail(SecretFault::Json),
                }
            }
            LegacyValue::Opened(text) => {
                self.opened += 1;
                Value::String(text)
            }
            LegacyValue::Locked => {
                self.locked.push(self.pointer());
                serde_json::json!({ LOCKED_MARKER: true })
            }
            LegacyValue::Invalid(fault) => self.fail(fault),
            LegacyValue::Plain(value) => value,
            LegacyValue::Absent => Value::Null,
        }
    }

    fn fail(&mut self, fault: SecretFault) -> Value {
        self.invalid.push((self.pointer(), fault));
        Value::Null
    }

    /// True when the current path matches one of the store's patterns in `table`.
    fn at(&self, table: &[(&str, &[&str])]) -> bool {
        table.iter().any(|(store, pattern)| {
            *store == self.store
                && pattern.len() == self.path.len()
                && pattern
                    .iter()
                    .zip(&self.path)
                    .all(|(want, have)| *want == "*" || want == have)
        })
    }

    /// RFC 6901 pointer of the current path.
    fn pointer(&self) -> String {
        self.path
            .iter()
            .map(|seg| format!("/{}", seg.replace('~', "~0").replace('/', "~1")))
            .collect()
    }
}
