//! The downloader (research §4.6): every URL of a feed entry through every way, into a
//! `CREATE_NEW` `.part` file with a random name, capped at the size the signed feed gives,
//! hashed while it streams, resumed with `Range` after a dropped connection when the server
//! allows it. The finished file is renamed to its name, opened again without write or delete
//! sharing and hashed once more through that handle: what the caller holds is what was checked.
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use futures_util::StreamExt;
use reqwest::StatusCode;
use reqwest::header::{CONTENT_RANGE, RANGE};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;

use crate::net::{Way, download_client};

/// What to fetch: the size cap and SHA-256 come from the signed feed.
#[derive(Debug, Clone)]
pub struct Wanted<'a> {
    pub urls: &'a [String],
    pub size: u64,
    pub sha256: &'a str,
    /// File name in the target folder (`VPN-Tunnel-Enforcer-Setup-2.0.1.exe`).
    pub name: &'a str,
}

/// A verified download, held open with read sharing only until dropped.
#[derive(Debug)]
pub struct Verified {
    pub path: PathBuf,
    pub file: File,
}

/// Why a download did not produce the file.
#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    /// No URL answered on any way, or every transfer broke off.
    #[error("no source delivered the file")]
    Unreachable,
    /// A source sent more than the feed's size.
    #[error("the file is larger than the feed says")]
    TooLarge,
    /// The bytes are not the ones the feed signed.
    #[error("the file does not match its SHA-256")]
    Mismatch,
    #[error("download cancelled")]
    Cancelled,
    #[error("file error: {0}")]
    Io(#[from] io::Error),
}

/// Downloads `wanted` into `dir` (created when missing). `progress` gets the bytes received so
/// far. Leftover `.part` files of earlier runs in `dir` are removed first.
pub async fn download(
    wanted: &Wanted<'_>,
    ways: &[Way],
    dir: &Path,
    progress: Option<&watch::Sender<u64>>,
    cancel: &CancellationToken,
) -> Result<Verified, DownloadError> {
    let pin = parse_sha(wanted.sha256).ok_or(DownloadError::Mismatch)?;
    if wanted.name.contains(['/', '\\', ':']) || wanted.name.starts_with('.') {
        return Err(DownloadError::Io(io::ErrorKind::InvalidInput.into()));
    }
    std::fs::create_dir_all(dir)?;
    sweep_parts(dir);
    let part_path = dir.join(format!("{:016x}.part", fastrand::u64(..)));
    let mut part = Part {
        file: OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ.0)
            .open(&part_path)?,
        len: 0,
        hasher: Sha256::new(),
    };
    let result = fill(&mut part, wanted, pin, ways, progress, cancel).await;
    drop(part.file);
    let outcome = match result {
        Ok(()) => finish(&part_path, &dir.join(wanted.name), pin),
        Err(err) => Err(err),
    };
    let _ = std::fs::remove_file(&part_path);
    outcome
}

struct Part {
    file: File,
    len: u64,
    hasher: Sha256,
}

impl Part {
    /// Back to an empty file: the next source sends the whole body.
    fn reset(&mut self) -> io::Result<()> {
        self.file.set_len(0)?;
        self.file.seek(SeekFrom::Start(0))?;
        self.len = 0;
        self.hasher = Sha256::new();
        Ok(())
    }
}

/// Tries every (url, way) pair; a transfer that broke off after some bytes is retried once on
/// the same pair before moving on, resuming where it stopped. A source that sends too much or
/// the wrong bytes is passed over (the next one may be honest); the last such reason is the
/// error when none delivers.
async fn fill(
    part: &mut Part,
    wanted: &Wanted<'_>,
    pin: [u8; 32],
    ways: &[Way],
    progress: Option<&watch::Sender<u64>>,
    cancel: &CancellationToken,
) -> Result<(), DownloadError> {
    let mut failure = DownloadError::Unreachable;
    for url in wanted.urls {
        for way in ways {
            for _ in 0..2 {
                let before = part.len;
                match attempt(part, url, way, wanted.size, progress, cancel).await {
                    Ok(()) if part.len == wanted.size => {
                        if <[u8; 32]>::from(part.hasher.clone().finalize()) == pin {
                            return Ok(());
                        }
                        tracing::warn!(via = ?way.via, "download does not match its SHA-256");
                        failure = DownloadError::Mismatch;
                        part.reset()?;
                        break;
                    }
                    Ok(()) | Err(Fail::Retry) => {}
                    Err(Fail::TooLarge) => {
                        tracing::warn!(via = ?way.via, "download larger than the feed says");
                        failure = DownloadError::TooLarge;
                        part.reset()?;
                        break;
                    }
                    Err(Fail::Fatal(err)) => return Err(err),
                }
                if part.len == before {
                    break;
                }
            }
        }
    }
    Err(failure)
}

enum Fail {
    /// Try the same pair again (when it made progress) or the next one.
    Retry,
    /// More bytes than the feed's size: this source is not serving our file.
    TooLarge,
    Fatal(DownloadError),
}

/// One request: a `Range` from where the part stops; a 206 that starts exactly there is
/// appended, any other success restarts the part from zero.
async fn attempt(
    part: &mut Part,
    url: &str,
    way: &Way,
    size: u64,
    progress: Option<&watch::Sender<u64>>,
    cancel: &CancellationToken,
) -> Result<(), Fail> {
    let client = download_client(way).map_err(|_| Fail::Retry)?;
    let mut request = client.get(url);
    if part.len > 0 {
        request = request.header(RANGE, format!("bytes={}-", part.len));
    }
    let response = tokio::select! {
        r = request.send() => r.map_err(|_| Fail::Retry)?,
        () = cancel.cancelled() => return Err(Fail::Fatal(DownloadError::Cancelled)),
    };
    let resumed = response.status() == StatusCode::PARTIAL_CONTENT
        && range_start(&response) == Some(part.len);
    if !resumed {
        if !response.status().is_success() || response.status() == StatusCode::PARTIAL_CONTENT {
            return Err(Fail::Retry);
        }
        part.reset().map_err(|e| Fail::Fatal(e.into()))?;
    }
    if response
        .content_length()
        .is_some_and(|n| part.len + n > size)
    {
        return Err(Fail::TooLarge);
    }
    let mut stream = response.bytes_stream();
    loop {
        let chunk = tokio::select! {
            c = stream.next() => c,
            () = cancel.cancelled() => return Err(Fail::Fatal(DownloadError::Cancelled)),
        };
        let bytes = match chunk {
            None => return Ok(()),
            Some(Ok(bytes)) => bytes,
            Some(Err(_)) => return Err(Fail::Retry),
        };
        if part.len + bytes.len() as u64 > size {
            return Err(Fail::TooLarge);
        }
        part.file
            .write_all(&bytes)
            .map_err(|e| Fail::Fatal(e.into()))?;
        part.hasher.update(&bytes);
        part.len += bytes.len() as u64;
        if let Some(progress) = progress {
            progress.send_replace(part.len);
        }
    }
}

/// `bytes <start>-<end>/<total>` of a 206.
fn range_start(response: &reqwest::Response) -> Option<u64> {
    let value = response.headers().get(CONTENT_RANGE)?.to_str().ok()?;
    value
        .strip_prefix("bytes ")?
        .split('-')
        .next()?
        .parse()
        .ok()
}

/// Renames the finished part and opens it again (read sharing only), hashing that very handle.
fn finish(part: &Path, path: &Path, pin: [u8; 32]) -> Result<Verified, DownloadError> {
    std::fs::rename(part, path)?;
    let mut file = open_held(path)?;
    if sha256_of(&mut file)? != pin {
        return Err(DownloadError::Mismatch);
    }
    Ok(Verified {
        path: path.to_owned(),
        file,
    })
}

/// Opens `path` for reading so that nobody can write, rename or delete it while it is open.
pub fn open_held(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .open(path)
}

/// SHA-256 of everything `reader` yields from its current position.
pub fn sha256_of(reader: &mut impl Read) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Ok(hasher.finalize().into()),
            Ok(n) => hasher.update(&buf[..n]),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
}

/// A lowercase or uppercase 64-digit hex SHA-256.
pub fn parse_sha(text: &str) -> Option<[u8; 32]> {
    hex::decode(text.trim()).ok()?.try_into().ok()
}

/// Leftovers of a run that ended mid-download (crash, power loss).
fn sweep_parts(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "part") {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests;
