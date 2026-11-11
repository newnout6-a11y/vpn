//! Pinned third-party binaries: `resources/engines.toml` names every archive and file with its
//! SHA-256. Nothing is used unless both the archive and the extracted file match their pins.
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Manifest {
    schema: u32,
    archive: Vec<Archive>,
}

#[derive(Deserialize)]
struct Archive {
    id: String,
    version: String,
    url: String,
    sha256: String,
    files: Vec<PinnedFile>,
}

#[derive(Deserialize)]
struct PinnedFile {
    /// Path inside the archive.
    path: String,
    /// File name under `resources/`.
    name: String,
    sha256: String,
}

fn load(root: &Path) -> Result<Manifest> {
    let path = root.join("resources/engines.toml");
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let manifest: Manifest = toml::from_str(&text).context("parse engines.toml")?;
    ensure!(manifest.schema == 1, "unsupported engines.toml schema {}", manifest.schema);
    for archive in &manifest.archive {
        ensure!(is_sha256(&archive.sha256), "{}: archive sha256 must be 64 lowercase hex chars", archive.id);
        for file in &archive.files {
            ensure!(is_sha256(&file.sha256), "{}: sha256 must be 64 lowercase hex chars", file.name);
            ensure!(
                !file.name.contains(['/', '\\']) && file.name != ".." && !file.name.is_empty(),
                "{}: name must be a plain file name",
                file.name
            );
        }
    }
    Ok(manifest)
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Downloads (or takes from the cache) every pinned archive and fills `resources/`.
pub fn fetch(root: &Path, offline: bool) -> Result<()> {
    let manifest = load(root)?;
    let cache = root.join("target/download-cache");
    fs::create_dir_all(&cache)?;
    let resources = root.join("resources");
    for archive in &manifest.archive {
        let bytes = archive_bytes(archive, &cache, offline)?;
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))
            .with_context(|| format!("{}: not a zip archive", archive.id))?;
        for file in &archive.files {
            let mut entry = zip
                .by_name(&file.path)
                .with_context(|| format!("{}: {} is missing in the archive", archive.id, file.path))?;
            let mut data = Vec::with_capacity(entry.size() as usize);
            entry.read_to_end(&mut data)?;
            let actual = sha256_hex(&data);
            ensure!(actual == file.sha256, "{}: hash mismatch (expected {}, got {actual})", file.name, file.sha256);
            let target = resources.join(&file.name);
            // Leave an identical file alone: a running engine keeps its exe locked.
            if fs::read(&target).is_ok_and(|old| old == data) {
                println!("  ok       {}", file.name);
                continue;
            }
            fs::write(&target, &data).with_context(|| format!("write {}", target.display()))?;
            println!("  written  {} ({} {})", file.name, archive.id, archive.version);
        }
    }
    Ok(())
}

fn archive_bytes(archive: &Archive, cache: &Path, offline: bool) -> Result<Vec<u8>> {
    let cached: PathBuf = cache.join(format!("{}.zip", archive.sha256));
    if let Ok(bytes) = fs::read(&cached)
        && sha256_hex(&bytes) == archive.sha256
    {
        return Ok(bytes);
    }
    if offline {
        bail!("{}: not in the download cache and --offline was given", archive.id);
    }
    println!("  download {} {}", archive.id, archive.version);
    let bytes = ureq::get(&archive.url)
        .call()
        .with_context(|| format!("download {}", archive.url))?
        .body_mut()
        .with_config()
        .limit(256 * 1024 * 1024)
        .read_to_vec()
        .with_context(|| format!("read {}", archive.url))?;
    let actual = sha256_hex(&bytes);
    ensure!(actual == archive.sha256, "{}: archive hash mismatch (expected {}, got {actual})", archive.id, archive.sha256);
    fs::write(&cached, &bytes)?;
    Ok(bytes)
}

/// Fails unless every pinned file is present in `resources/` with the pinned hash.
pub fn verify(root: &Path) -> Result<()> {
    let manifest = load(root)?;
    let resources = root.join("resources");
    let mut bad = Vec::new();
    for file in manifest.archive.iter().flat_map(|a| &a.files) {
        match fs::read(resources.join(&file.name)) {
            Ok(data) if sha256_hex(&data) == file.sha256 => println!("  ok       {}", file.name),
            Ok(_) => bad.push(format!("{}: hash differs from the pin", file.name)),
            Err(_) => bad.push(format!("{}: missing (run `cargo xtask engines`)", file.name)),
        }
    }
    ensure!(bad.is_empty(), "resources/ does not match engines.toml:\n  {}", bad.join("\n  "));
    Ok(())
}
