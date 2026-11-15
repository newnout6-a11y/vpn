//! Synthetic old directories: obvious fake values and a fake key, wrapped with this user's DPAPI
//! the way Chromium wraps its `safeStorage` key. This machine's real old data is never read.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use vpnte_core::paths::DataDirs;

/// A throw-away directory under %TEMP%, removed on drop.
pub(super) struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("vpnte-app-import-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A new data root plus an old Electron directory, both empty at first.
pub(super) struct Fixture {
    pub new: TempDir,
    pub old: TempDir,
    key: [u8; 32],
    nonce: std::cell::Cell<u8>,
}

impl Fixture {
    pub fn new(name: &str) -> Self {
        Self {
            new: TempDir::new(&format!("{name}-new")),
            old: TempDir::new(&format!("{name}-old")),
            key: [0x5a; 32],
            nonce: std::cell::Cell::new(0),
        }
    }

    pub fn dirs(&self) -> DataDirs {
        DataDirs::new(
            self.new.0.clone(),
            self.old.0.clone(),
            self.new.0.join("resources"),
        )
    }

    /// `Local State` holding the fake key as Chromium stores it: `"DPAPI" ‖ CryptProtectData(key)`.
    pub fn local_state(&self) {
        let wrapped = [b"DPAPI".as_slice(), &dpapi_protect(&self.key)].concat();
        let state = json!({ "os_crypt": { "encrypted_key": B64.encode(wrapped) } });
        self.write_file("Local State", state.to_string().as_bytes());
    }

    /// The old `SecretRef` envelope of `plain`: `v10 ‖ nonce ‖ AES-256-GCM(plain) ‖ tag`.
    pub fn seal(&self, plain: &str) -> Value {
        self.nonce.set(self.nonce.get() + 1);
        let nonce = [self.nonce.get(); 12];
        let cipher = Aes256Gcm::new_from_slice(&self.key).unwrap();
        let sealed = cipher
            .encrypt(
                &Nonce::<Aes256Gcm>::try_from(&nonce[..]).unwrap(),
                plain.as_bytes(),
            )
            .unwrap();
        let blob = [b"v10".as_slice(), &nonce, &sealed].concat();
        json!({ "__vpnteSecretRef": "vpnte-safe-storage-v1",
                "ciphertext": format!("enc:dpapi:v1:{}", B64.encode(blob)) })
    }

    /// The envelope of a whole JSON value (`encryptJsonSecret`).
    pub fn seal_json(&self, value: &Value) -> Value {
        self.seal(&value.to_string())
    }

    /// `<store>.json` in the old directory.
    pub fn store(&self, store: &str, value: &Value) {
        self.write_file(&format!("{store}.json"), value.to_string().as_bytes());
    }

    pub fn write_file(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.old.0.join(name), bytes).unwrap();
    }

    /// Every file of the old directory with its bytes (the "untouched" check).
    pub fn old_files(&self) -> BTreeMap<String, Vec<u8>> {
        files(&self.old.0)
    }

    /// A new document as JSON (panics when missing).
    pub fn doc(&self, file: &str) -> Value {
        let bytes = std::fs::read(self.new.0.join(file)).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Every new file's text, joined (the "no plaintext secret on disk" check).
    pub fn new_text(&self) -> String {
        let files = files(&self.new.0);
        files
            .values()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect()
    }
}

fn files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name().to_string_lossy().into_owned();
            for (inner, bytes) in files(&path) {
                out.insert(format!("{name}/{inner}"), bytes);
            }
        } else {
            out.insert(
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(&path).unwrap(),
            );
        }
    }
    out
}

/// `CryptProtectData` for this user without entropy, as Chromium wraps its key.
fn dpapi_protect(plain: &[u8]) -> Vec<u8> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(plain.len()).unwrap(),
        pbData: plain.as_ptr().cast_mut(),
    };
    let mut out = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` points to `plain`, which outlives the call; DPAPI only reads it and puts a
    // LocalAlloc buffer into `out`.
    unsafe {
        CryptProtectData(
            &input,
            windows::core::PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    }
    .unwrap();
    // SAFETY: after success `out` holds `cbData` bytes that only we reference; copied, then freed
    // exactly once.
    unsafe {
        let bytes = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(Some(HLOCAL(out.pbData.cast())));
        bytes
    }
}
