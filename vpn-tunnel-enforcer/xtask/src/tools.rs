//! Build tools pinned as `[[tool]]` in the manifest, unpacked to `target/tools/<id>` (never shipped).
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use crate::fetch;
use crate::manifest::Manifest;

const MARKER: &str = ".pinned-sha256";

/// Makes sure the pinned NSIS is unpacked and returns the path of `makensis.exe`.
pub fn nsis(root: &Path) -> Result<PathBuf> {
    ensure_tool(root, &Manifest::load(root)?, "nsis")
}

/// Unpacks the tool unless `target/tools/<id>` already holds this exact pin; returns its executable.
fn ensure_tool(root: &Path, manifest: &Manifest, id: &str) -> Result<PathBuf> {
    let tool = manifest.tool(id)?;
    let dir = root.join("target/tools").join(&tool.id);
    let exe = dir.join(tool.exe.as_str());
    let marker = dir.join(MARKER);
    if exe.is_file()
        && fs::read_to_string(&marker).is_ok_and(|m| m.trim() == tool.sha256.to_string())
    {
        println!(
            "  ok       {} {} ({})",
            tool.id,
            tool.version,
            dir.display()
        );
        return Ok(exe);
    }
    let bytes = fetch::cached(root, &tool.id, &tool.url, &tool.sha256, false)?;
    let mut zip = fetch::open(&tool.id, bytes)?;
    if dir.exists() {
        fs::remove_dir_all(&dir).with_context(|| format!("remove {}", dir.display()))?;
    }
    let prefix = format!("{}/", tool.root);
    let mut written = 0usize;
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index)?;
        // enclosed_name rejects absolute paths and `..` escapes (zip-slip).
        let name = entry
            .enclosed_name()
            .with_context(|| format!("{}: unsafe path in archive", tool.id))?;
        let name = name.to_string_lossy().replace('\\', "/");
        let Some(rel) = name.strip_prefix(&prefix) else {
            ensure!(
                name.trim_end_matches('/') == tool.root,
                "{}: {name} is outside `{}`",
                tool.id,
                tool.root
            );
            continue;
        };
        let target = dir.join(rel);
        if entry.is_dir() {
            fs::create_dir_all(&target)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out =
            fs::File::create(&target).with_context(|| format!("create {}", target.display()))?;
        std::io::copy(&mut entry, &mut out).with_context(|| format!("unpack {name}"))?;
        written += 1;
    }
    ensure!(
        exe.is_file(),
        "{}: {} is missing after unpacking",
        tool.id,
        tool.exe
    );
    // The marker is written last, so an interrupted unpack is redone on the next run.
    fs::write(&marker, format!("{}\n", tool.sha256))?;
    println!(
        "  unpacked {} {} ({written} files) -> {}",
        tool.id,
        tool.version,
        dir.display()
    );
    Ok(exe)
}
