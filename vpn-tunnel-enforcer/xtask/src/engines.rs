//! The development drop: `resources/` of the workspace holds the pinned engine files (and the WebView2
//! bootstrapper) that tests and `cargo run` use (CONTRACT: engines resolve to `<exe dir>\resources` or
//! `VPNTE_RESOURCES_DIR`).
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};

use crate::fetch;
use crate::manifest::{DEV_DROP_PREFIX, Manifest, RelPath, Sha256Hex};

/// Downloads (or takes from the cache) every pinned archive and download and fills `resources/` with their
/// files.
pub fn fetch(root: &Path, offline: bool) -> Result<()> {
    let manifest = Manifest::load(root)?;
    for archive in &manifest.archive {
        let bytes = fetch::cached(root, &archive.id, &archive.url, &archive.sha256, offline)?;
        let mut zip = fetch::open(&archive.id, bytes)?;
        for file in archive
            .files
            .iter()
            .filter(|f| f.install.as_str().starts_with(DEV_DROP_PREFIX))
        {
            let data = fetch::member(&mut zip, &archive.id, &file.path, &file.sha256)?;
            put(root, &file.install, &data, &archive.id, &archive.version)?;
        }
    }
    for file in manifest
        .download
        .iter()
        .filter(|d| d.install.as_str().starts_with(DEV_DROP_PREFIX))
    {
        let data = fetch::download(root, file, offline)?;
        put(root, &file.install, &data, &file.id, &file.version)?;
    }
    Ok(())
}

fn put(root: &Path, install: &RelPath, data: &[u8], id: &str, version: &str) -> Result<()> {
    let target = root.join(install.as_str());
    // Leave an identical file alone: a running engine keeps its exe locked.
    if fs::read(&target).is_ok_and(|old| old == data) {
        println!("  ok       {install}");
        return Ok(());
    }
    fs::write(&target, data).with_context(|| format!("write {}", target.display()))?;
    println!("  written  {install} ({id} {version})");
    Ok(())
}

/// Fails unless every pinned file of the dev drop is present in `resources/` with its pinned hash.
pub fn verify(root: &Path) -> Result<()> {
    let manifest = Manifest::load(root)?;
    let mut bad = Vec::new();
    let members = manifest.archive.iter().flat_map(|a| &a.files);
    let pins = members
        .map(|f| (&f.install, &f.sha256))
        .chain(manifest.download.iter().map(|d| (&d.install, &d.sha256)));
    for (install, sha256) in pins.filter(|(i, _)| i.as_str().starts_with(DEV_DROP_PREFIX)) {
        match fs::read(root.join(install.as_str())) {
            Ok(data) if Sha256Hex::of(&data) == *sha256 => println!("  ok       {install}"),
            Ok(_) => bad.push(format!("{install}: hash differs from the pin")),
            Err(_) => bad.push(format!("{install}: missing (run `cargo xtask engines`)")),
        }
    }
    ensure!(
        bad.is_empty(),
        "resources/ does not match {}:\n  {}",
        crate::manifest::PATH,
        bad.join("\n  ")
    );
    Ok(())
}
