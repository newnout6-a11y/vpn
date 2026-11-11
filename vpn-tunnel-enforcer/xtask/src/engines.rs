//! The development drop: `resources/` of the workspace holds the pinned engine files that tests and
//! `cargo run` use (CONTRACT: engines resolve to `<exe dir>\resources` or `VPNTE_RESOURCES_DIR`).
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};

use crate::fetch;
use crate::manifest::{DEV_DROP_PREFIX, Manifest, Sha256Hex};

/// Downloads (or takes from the cache) every pinned archive and fills `resources/` with its engine files.
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
            let target = root.join(file.install.as_str());
            // Leave an identical file alone: a running engine keeps its exe locked.
            if fs::read(&target).is_ok_and(|old| old == data) {
                println!("  ok       {}", file.install);
                continue;
            }
            fs::write(&target, &data).with_context(|| format!("write {}", target.display()))?;
            println!(
                "  written  {} ({} {})",
                file.install, archive.id, archive.version
            );
        }
    }
    Ok(())
}

/// Fails unless every pinned engine file is present in `resources/` with its pinned hash.
pub fn verify(root: &Path) -> Result<()> {
    let manifest = Manifest::load(root)?;
    let mut bad = Vec::new();
    let engines = manifest.archive.iter().flat_map(|a| &a.files);
    for file in engines.filter(|f| f.install.as_str().starts_with(DEV_DROP_PREFIX)) {
        let install = &file.install;
        match fs::read(root.join(install.as_str())) {
            Ok(data) if Sha256Hex::of(&data) == file.sha256 => println!("  ok       {install}"),
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
