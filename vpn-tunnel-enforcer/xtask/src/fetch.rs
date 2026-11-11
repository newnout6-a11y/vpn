//! Pinned downloads: `target/download-cache/<sha256>.zip` is fetched once and verified before every use; zip
//! members are read by exact name and checked against their own pin before anything is written.
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use zip::ZipArchive;

use crate::manifest::{RelPath, Sha256Hex};

/// An opened, verified zip archive held in memory.
pub type Zip = ZipArchive<Cursor<Vec<u8>>>;

/// Returns the verified archive bytes, downloading them only when the cache has no valid copy.
pub fn cached(
    root: &Path,
    id: &str,
    url: &str,
    sha256: &Sha256Hex,
    offline: bool,
) -> Result<Vec<u8>> {
    let cache = root.join("target/download-cache");
    let path = cache.join(format!("{sha256}.zip"));
    if let Ok(bytes) = fs::read(&path) {
        if Sha256Hex::of(&bytes) == *sha256 {
            return Ok(bytes);
        }
        println!(
            "  stale    {} (cached copy does not match the pin, fetching again)",
            path.display()
        );
    }
    if offline {
        bail!("{id}: not in the download cache and --offline was given");
    }
    println!("  download {id} <- {url}");
    let bytes = ureq::get(url)
        .call()
        .with_context(|| format!("download {url}"))?
        .body_mut()
        .with_config()
        .limit(256 * 1024 * 1024)
        .read_to_vec()
        .with_context(|| format!("read {url}"))?;
    let actual = Sha256Hex::of(&bytes);
    // Checked before the bytes are cached or unpacked: a swapped release asset never reaches the disk.
    ensure!(
        actual == *sha256,
        "{id}: archive hash mismatch (pinned {sha256}, downloaded {actual})"
    );
    fs::create_dir_all(&cache)?;
    fs::write(&path, &bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(bytes)
}

/// Opens verified archive bytes.
pub fn open(id: &str, bytes: Vec<u8>) -> Result<Zip> {
    ZipArchive::new(Cursor::new(bytes)).with_context(|| format!("{id}: not a zip archive"))
}

/// Reads the member at exactly `path` and checks it against its pin.
pub fn member(zip: &mut Zip, id: &str, path: &RelPath, sha256: &Sha256Hex) -> Result<Vec<u8>> {
    let index = zip
        .index_for_name(path.as_str())
        .with_context(|| format!("{id}: {path} is missing in the archive"))?;
    let mut entry = zip.by_index(index)?;
    ensure!(!entry.is_dir(), "{id}: {path} is a directory");
    let mut data = Vec::with_capacity(usize::try_from(entry.size()).unwrap_or(0));
    entry
        .read_to_end(&mut data)
        .with_context(|| format!("{id}: read {path}"))?;
    let actual = Sha256Hex::of(&data);
    ensure!(
        actual == *sha256,
        "{id}: {path} hash mismatch (pinned {sha256}, extracted {actual})"
    );
    Ok(data)
}
