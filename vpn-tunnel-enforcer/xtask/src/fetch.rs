//! Pinned downloads: `target/download-cache/<sha256>.<ext>` is fetched once and verified before every use; zip
//! members are read by exact name and checked against their own pin before anything is written.
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use zip::ZipArchive;

use crate::manifest::{Download, RelPath, Sha256Hex};

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
    let pin = Pin {
        id,
        url,
        sha256,
        size: None,
        ext: "zip",
    };
    fetch_pinned(root, &pin, offline)
}

/// Returns the verified bytes of a `[[download]]` file (its size is checked too), from the cache when it
/// holds a valid copy.
pub fn download(root: &Path, file: &Download, offline: bool) -> Result<Vec<u8>> {
    let ext = Path::new(file.install.as_str())
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin");
    let pin = Pin {
        id: &file.id,
        url: &file.url,
        sha256: &file.sha256,
        size: Some(file.size),
        ext,
    };
    fetch_pinned(root, &pin, offline)
}

/// What one cached download must be.
struct Pin<'a> {
    id: &'a str,
    url: &'a str,
    sha256: &'a Sha256Hex,
    size: Option<u64>,
    /// Extension of the cache file (`<sha256>.<ext>`).
    ext: &'a str,
}

impl Pin<'_> {
    fn matches(&self, bytes: &[u8]) -> bool {
        self.size.is_none_or(|size| bytes.len() as u64 == size)
            && Sha256Hex::of(bytes) == *self.sha256
    }
}

fn fetch_pinned(root: &Path, pin: &Pin<'_>, offline: bool) -> Result<Vec<u8>> {
    let Pin {
        id, url, sha256, ..
    } = *pin;
    let cache = root.join("target/download-cache");
    let path = cache.join(format!("{sha256}.{}", pin.ext));
    if let Ok(bytes) = fs::read(&path) {
        if pin.matches(&bytes) {
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
        // One byte over the pinned size is enough to refuse a different file.
        .limit(pin.size.map_or(256 * 1024 * 1024, |size| size + 1))
        .read_to_vec()
        .with_context(|| format!("read {url}"))?;
    if let Some(size) = pin.size {
        ensure!(
            bytes.len() as u64 == size,
            "{id}: size mismatch (pinned {size} bytes, downloaded {})",
            bytes.len()
        );
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(bytes: &[u8], size: u64) -> Download {
        Download {
            id: "wv2".to_owned(),
            version: "1".to_owned(),
            url: "https://example.invalid/setup.exe".to_owned(),
            sha256: Sha256Hex::of(bytes),
            size,
            license: "Proprietary".to_owned(),
            source: None,
            install: RelPath::try_from("resources/setup.exe".to_owned()).unwrap(),
        }
    }

    /// A pinned single file comes from the cache only when both its size and its hash match; offline,
    /// anything else is refused instead of fetched.
    #[test]
    fn download_uses_only_a_cached_copy_of_the_pinned_size_and_hash() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/xtask/test-scratch/fetch-download");
        let _ = fs::remove_dir_all(&root);
        let bytes = b"bootstrapper";
        let file = pin(bytes, bytes.len() as u64);
        let err = format!("{:#}", download(&root, &file, true).unwrap_err());
        assert!(err.contains("not in the download cache"), "{err}");

        let cache = root.join("target/download-cache");
        fs::create_dir_all(&cache).unwrap();
        let cached = cache.join(format!("{}.exe", file.sha256));
        fs::write(&cached, bytes).unwrap();
        assert_eq!(download(&root, &file, true).unwrap(), bytes);
        // The same bytes under a pin of another size are not the pinned file.
        assert!(download(&root, &pin(bytes, 13), true).is_err());
        fs::write(&cached, b"swapped file").unwrap();
        assert!(download(&root, &file, true).is_err());
        fs::remove_dir_all(&root).unwrap();
    }
}
