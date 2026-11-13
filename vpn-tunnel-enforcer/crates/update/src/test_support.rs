//! Shared test helpers: throw-away signing keys, a sample feed, temp folders.
use std::io::Cursor;
use std::path::{Path, PathBuf};

use crate::feed::{
    AppChannels, AppRelease, ArchiveEntry, EngineEntry, Feed, FileEntry, MemberEntry, Severity,
};
use crate::version::Version;

/// A throw-away minisign key pair (never the owner's).
pub(crate) struct TestKey {
    pair: minisign::KeyPair,
}

impl TestKey {
    pub(crate) fn new() -> Self {
        Self {
            pair: minisign::KeyPair::generate_unencrypted_keypair().unwrap(),
        }
    }

    /// The public key as the app reads it.
    pub(crate) fn public(&self) -> minisign_verify::PublicKey {
        minisign_verify::PublicKey::from_base64(&self.pair.pk.to_base64()).unwrap()
    }

    /// The `.minisig` text over `bytes` (prehashed, as `minisign -S` writes it).
    pub(crate) fn sign(&self, bytes: &[u8]) -> String {
        minisign::sign(
            Some(&self.pair.pk),
            &self.pair.sk,
            Cursor::new(bytes),
            None,
            None,
        )
        .unwrap()
        .into_string()
    }
}

/// A feed with app 2.0.1, sing-box 1.14.5 and Xray 26.11.20, issued now.
pub(crate) fn sample_feed(seq: u64) -> Feed {
    let issued = jiff::Timestamp::now().to_string();
    let file = FileEntry {
        name: "VPN-Tunnel-Enforcer-Setup-2.0.1.exe".into(),
        size: 1024,
        sha256: "00".repeat(32),
        urls: vec!["https://example.invalid/setup.exe".into()],
    };
    let engine = |id: &str, version: Version, member: &str| EngineEntry {
        id: id.into(),
        version,
        app: ">=2.0.0 <2.1.0".parse().unwrap(),
        severity: Severity::Normal,
        notes: [("ru".to_owned(), "Исправления".to_owned())].into(),
        tested_on: Some("2026-11-12".into()),
        tested: None,
        archive: ArchiveEntry {
            url: format!("https://example.invalid/{id}.zip"),
            size: 2048,
            sha256: "11".repeat(32),
        },
        files: vec![MemberEntry {
            path: format!("dir/{member}"),
            name: member.into(),
            sha256: "22".repeat(32),
        }],
    };
    Feed {
        schema: crate::feed::SCHEMA,
        seq,
        issued,
        app: AppChannels {
            stable: Some(AppRelease {
                version: Version(2, 0, 1),
                severity: Severity::Normal,
                notes: [("ru".to_owned(), "Что нового".to_owned())].into(),
                file,
                rollback_to: Some(Version(2, 0, 0)),
                rollback_file: None,
            }),
            beta: None,
            warn_below: None,
        },
        engines: vec![
            engine("sing-box", Version(1, 14, 5), "sing-box.exe"),
            engine("xray", Version(26, 11, 20), "xray.exe"),
        ],
        service: None,
    }
}

/// A temp folder removed on drop.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "vpnte-update-{tag}-{}-{}",
            std::process::id(),
            fastrand::u64(..)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A file served by [`Server`].
#[derive(Clone, Default)]
pub(crate) struct Served {
    pub body: Vec<u8>,
    /// Honour `Range: bytes=N-` with 206.
    pub ranges: bool,
    /// The first answer stops after this many body bytes (a dropped connection).
    pub cut_after: Option<usize>,
}

/// One request a [`Server`] saw: the path and the start of its `Range`, if any.
pub(crate) type Request = (String, Option<u64>);

/// A tiny HTTP/1.1 server on 127.0.0.1 (never another address: no firewall prompt).
pub(crate) struct Server {
    pub base: String,
    /// Every request as `(path, range start)`.
    pub log: std::sync::Arc<parking_lot::Mutex<Vec<Request>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    pub(crate) async fn start(files: Vec<(&str, Served)>) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        let files: std::collections::HashMap<String, Served> = files
            .into_iter()
            .map(|(p, s)| (format!("/{p}"), s))
            .collect();
        let files = std::sync::Arc::new(parking_lot::Mutex::new(files));
        let log = std::sync::Arc::new(parking_lot::Mutex::new(Vec::new()));
        let task_log = log.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let (files, log) = (files.clone(), task_log.clone());
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&buf[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&head).into_owned();
                    let path = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
                    let range = head.lines().find_map(|l| {
                        let l = l.to_ascii_lowercase();
                        l.strip_prefix("range: bytes=")?
                            .strip_suffix('-')?
                            .parse::<u64>()
                            .ok()
                    });
                    log.lock().push((path.clone(), range));
                    let served = files.lock().get(&path).cloned();
                    let Some(served) = served else {
                        let _ = sock.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                        return;
                    };
                    if served.cut_after.is_some() {
                        // Only the first answer is cut.
                        if let Some(s) = files.lock().get_mut(&path) {
                            s.cut_after = None;
                        }
                    }
                    let total = served.body.len();
                    let (status, from) = match range {
                        Some(n) if served.ranges && (n as usize) < total => {
                            ("206 Partial Content", n as usize)
                        }
                        _ => ("200 OK", 0),
                    };
                    let mut out = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
                        total - from
                    );
                    if from > 0 {
                        out += &format!("Content-Range: bytes {from}-{}/{total}\r\n", total - 1);
                    }
                    out += "\r\n";
                    let body = &served.body[from..];
                    let body = match served.cut_after {
                        Some(cut) => &body[..cut.min(body.len())],
                        None => body,
                    };
                    let _ = sock.write_all(out.as_bytes()).await;
                    let _ = sock.write_all(body).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        Self { base, log, task }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
