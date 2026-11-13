//! Test helpers of the updater: throw-away signing keys, signed feeds, temp folders.
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest, Sha256};
use vpnte_update::feed::{AppChannels, Feed, PublicKey, SCHEMA, ServiceEntry};
use vpnte_update::version::Version;

/// A throw-away minisign key pair (never the owner's).
pub struct TestKey(minisign::KeyPair);

impl TestKey {
    pub fn new() -> Self {
        Self(minisign::KeyPair::generate_unencrypted_keypair().expect("key pair"))
    }

    /// The public key as `'static` slice, the way the compiled keys are handed around.
    pub fn keys(&self) -> &'static [PublicKey] {
        let key = PublicKey::from_base64(&self.0.pk.to_base64()).expect("public key");
        Box::leak(vec![key].into_boxed_slice())
    }

    /// The `.minisig` text over `bytes` (prehashed, as `minisign -S` writes it).
    pub fn sign(&self, bytes: &[u8]) -> String {
        minisign::sign(Some(&self.0.pk), &self.0.sk, Cursor::new(bytes), None, None)
            .expect("signature")
            .into_string()
    }
}

/// A feed with no app release, no engines and the service entry `service`.
pub fn feed(seq: u64, service: Option<ServiceEntry>) -> Feed {
    Feed {
        schema: SCHEMA,
        seq,
        issued: "2026-11-13T08:00:00Z".into(),
        app: AppChannels {
            stable: None,
            beta: None,
            warn_below: None,
        },
        engines: Vec::new(),
        service,
    }
}

/// The service entry of `version` for `bytes`.
pub fn service_entry(version: Version, bytes: &[u8]) -> ServiceEntry {
    ServiceEntry {
        version,
        size: bytes.len() as u64,
        sha256: sha(bytes),
        urls: vec![format!(
            "https://example.invalid/vpnte-service-{version}.exe"
        )],
    }
}

pub fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A temp folder removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "vpnte-svc-update-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
