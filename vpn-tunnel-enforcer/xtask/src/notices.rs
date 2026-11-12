//! `licenses/THIRD-PARTY-NOTICES.txt`: the bundled engines (from the pin manifest), the hand-kept UI asset
//! notices, and the licence texts of every crates.io crate linked into the two shipped binaries, read from the
//! crate sources that `cargo metadata` points at (no extra tool to pin).
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

use crate::manifest::{self, Manifest};

/// Packages whose binaries ship; their linked dependency closure is listed.
const ROOTS: [&str; 2] = ["vpnte-app", "vpnte-proxies"];
const ASSETS: &str = "installer/third-party-assets.txt";
const LICENCE_PREFIXES: [&str; 6] = [
    "LICENSE",
    "LICENCE",
    "COPYING",
    "NOTICE",
    "COPYRIGHT",
    "UNLICENSE",
];

/// The parts of `cargo metadata --format-version 1` used here.
#[derive(Deserialize)]
pub struct Metadata {
    pub packages: Vec<Package>,
    pub resolve: Resolve,
    pub target_directory: PathBuf,
}

/// A package of the resolved graph.
#[derive(Deserialize)]
pub struct Package {
    pub id: String,
    pub name: String,
    pub version: String,
    pub license: Option<String>,
    pub license_file: Option<String>,
    pub repository: Option<String>,
    pub manifest_path: PathBuf,
    /// `None` for path (workspace) packages.
    pub source: Option<String>,
}

/// The resolved dependency graph.
#[derive(Deserialize)]
pub struct Resolve {
    pub nodes: Vec<Node>,
}

/// One package's resolved dependencies.
#[derive(Deserialize)]
pub struct Node {
    pub id: String,
    pub deps: Vec<NodeDep>,
}

/// An edge of the graph with its kinds (normal = `kind: null`, else "dev" / "build").
#[derive(Deserialize)]
pub struct NodeDep {
    pub pkg: String,
    pub dep_kinds: Vec<DepKind>,
}

/// The kind of a dependency edge.
#[derive(Deserialize)]
pub struct DepKind {
    pub kind: Option<String>,
}

/// `cargo metadata` of the workspace for the Windows target (reads Cargo.lock, builds nothing).
pub fn metadata(root: &Path) -> Result<Metadata> {
    let args = [
        "metadata",
        "--format-version",
        "1",
        "--locked",
        "--filter-platform",
        "x86_64-pc-windows-msvc",
    ];
    let out = Command::new(crate::dist::cargo())
        .args(args)
        .current_dir(root)
        .output()
        .context("start cargo metadata")?;
    ensure!(
        out.status.success(),
        "cargo metadata failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).context("parse cargo metadata output")
}

/// crates.io (non-workspace) packages reachable from the shipped roots through normal dependencies:
/// dev- and build-dependencies never end up in the binaries.
fn shipped(meta: &Metadata) -> Result<Vec<&Package>> {
    let packages: BTreeMap<&str, &Package> =
        meta.packages.iter().map(|p| (p.id.as_str(), p)).collect();
    let nodes: BTreeMap<&str, &Node> = meta
        .resolve
        .nodes
        .iter()
        .map(|n| (n.id.as_str(), n))
        .collect();
    let mut todo = Vec::new();
    for name in ROOTS {
        let root = meta
            .packages
            .iter()
            .find(|p| p.name == name && p.source.is_none());
        todo.push(
            root.with_context(|| format!("workspace package `{name}` not found"))?
                .id
                .as_str(),
        );
    }
    let mut seen = BTreeSet::new();
    while let Some(id) = todo.pop() {
        if !seen.insert(id) {
            continue;
        }
        let node = nodes
            .get(id)
            .with_context(|| format!("{id} is missing from the resolve graph"))?;
        let linked = node
            .deps
            .iter()
            .filter(|d| d.dep_kinds.iter().any(|k| k.kind.is_none()));
        todo.extend(linked.map(|d| d.pkg.as_str()));
    }
    let mut out: Vec<&Package> = seen
        .into_iter()
        .filter_map(|id| packages.get(id).copied())
        .filter(|p| p.source.is_some())
        .collect();
    out.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    Ok(out)
}

/// Licence files shipped inside a crate package: (file name, LF-normalised text), sorted by name.
fn licence_texts(pkg: &Package) -> Vec<(String, String)> {
    let Some(dir) = pkg.manifest_path.parent() else {
        return Vec::new();
    };
    let mut names: BTreeSet<String> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| {
            LICENCE_PREFIXES
                .iter()
                .any(|p| n.to_ascii_uppercase().starts_with(p))
        })
        .collect();
    names.extend(pkg.license_file.clone());
    let read = |name: String| {
        let bytes = fs::read(dir.join(&name)).ok()?;
        let text = String::from_utf8_lossy(&manifest::normalize_text(&bytes))
            .trim()
            .to_owned();
        (!text.is_empty()).then_some((name, text))
    };
    names.into_iter().filter_map(read).collect()
}

/// The whole notices text (LF line endings; the caller stages it with CRLF).
pub fn render(root: &Path, manifest: &Manifest, meta: &Metadata, version: &str) -> Result<String> {
    let mut out = format!("VPN Tunnel Enforcer {version}: third-party notices\n\n");
    out.push_str("Bundled programs (licence texts in this folder):\n");
    for archive in &manifest.archive {
        let mut texts: Vec<&str> = archive
            .files
            .iter()
            .filter_map(|f| f.install.as_str().strip_prefix("licenses/"))
            .collect();
        // A GPL archive may ship no licence member of its own (mihomo): the full text covers it.
        if archive.license.starts_with("GPL") {
            texts.push("GPL-3.0.txt");
        }
        out.push_str(&format!(
            "- {} {}: {}; licence file: {}",
            archive.id,
            archive.version,
            archive.license,
            texts.join(", ")
        ));
        match &archive.source {
            Some(source) => out.push_str(&format!("; complete corresponding source: {source}\n")),
            None => out.push('\n'),
        }
    }
    let assets = fs::read(root.join(ASSETS)).with_context(|| format!("read {ASSETS}"))?;
    out.push('\n');
    out.push_str(String::from_utf8_lossy(&manifest::normalize_text(&assets)).trim_end());
    out.push_str("\n\n");

    let crates = shipped(meta)?;
    out.push_str("Rust crates compiled into VPN Tunnel Enforcer.exe and vpnte-proxy.exe:\n");
    // Identical texts (most Apache-2.0 copies) are printed once with every crate that ships them.
    let mut by_text: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for pkg in &crates {
        let licence = pkg.license.as_deref().unwrap_or("see licence text");
        let repo = pkg
            .repository
            .as_deref()
            .map(|r| format!(" <{r}>"))
            .unwrap_or_default();
        out.push_str(&format!(
            "- {} {}: {licence}{repo}\n",
            pkg.name, pkg.version
        ));
        let texts = licence_texts(pkg);
        if texts.is_empty() {
            let note = format!(
                "No licence file in the package; the standard text of `{licence}` applies."
            );
            by_text
                .entry(note)
                .or_default()
                .push(format!("{} {}", pkg.name, pkg.version));
        }
        for (file, text) in texts {
            by_text
                .entry(text)
                .or_default()
                .push(format!("{} {} ({file})", pkg.name, pkg.version));
        }
    }
    out.push_str("\nLicence texts:\n");
    for (text, users) in by_text {
        out.push_str(&format!("\n==== {} ====\n\n{text}\n", users.join(", ")));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(id: &str, source: bool, dir: &Path) -> Package {
        fs::create_dir_all(dir).unwrap();
        Package {
            id: id.into(),
            name: id.into(),
            version: "1.0.0".into(),
            license: Some("MIT".into()),
            license_file: None,
            repository: None,
            manifest_path: dir.join("Cargo.toml"),
            source: source.then(|| "registry+https://github.com/rust-lang/crates.io-index".into()),
        }
    }

    fn node(id: &str, deps: &[(&str, Option<&str>)]) -> Node {
        let deps = deps
            .iter()
            .map(|(pkg, kind)| NodeDep {
                pkg: (*pkg).into(),
                dep_kinds: vec![DepKind {
                    kind: kind.map(Into::into),
                }],
            })
            .collect();
        Node {
            id: id.into(),
            deps,
        }
    }

    /// AT-11-006: only linked crates.io dependencies of the shipped binaries are listed, each licence text once.
    #[test]
    fn lists_linked_registry_crates_with_grouped_texts() {
        let base =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/xtask/test-scratch/notices");
        let _ = fs::remove_dir_all(&base);
        let names = [
            "vpnte-app",
            "vpnte-proxies",
            "vpnte-base",
            "linked",
            "deep",
            "dev-only",
            "build-only",
        ];
        let packages: Vec<Package> = names
            .iter()
            .map(|n| pkg(n, !n.starts_with("vpnte-"), &base.join(n)))
            .collect();
        fs::write(base.join("linked/LICENSE-MIT"), "MIT text\r\n").unwrap();
        fs::write(base.join("deep/LICENSE"), "MIT text\n").unwrap();
        let nodes = vec![
            node(
                "vpnte-app",
                &[
                    ("linked", None),
                    ("dev-only", Some("dev")),
                    ("build-only", Some("build")),
                ],
            ),
            node("vpnte-proxies", &[("vpnte-base", None)]),
            node("vpnte-base", &[("linked", None)]),
            node("linked", &[("deep", None)]),
            node("deep", &[]),
            node("dev-only", &[]),
            node("build-only", &[]),
        ];
        let meta = Metadata {
            packages,
            resolve: Resolve { nodes },
            target_directory: base.clone(),
        };
        let shipped: Vec<&str> = shipped(&meta)
            .unwrap()
            .iter()
            .map(|p| p.name.as_str())
            .collect();
        assert_eq!(shipped, ["deep", "linked"]);

        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let manifest = Manifest::load(root).unwrap();
        let text = render(root, &manifest.composition(true), &meta, "2.0.0").unwrap();
        assert!(
            text.contains("- mihomo 1.19.34: GPL-3.0; licence file: GPL-3.0.txt;"),
            "{text}"
        );
        let manifest = Manifest::load(root).unwrap().composition(false);
        let text = render(root, &manifest, &meta, "2.0.0").unwrap();
        assert!(!text.contains("mihomo"), "a release lists no lab engine");
        assert!(
            text.contains(
                "- sing-box 1.14.4: GPL-3.0-or-later; licence file: sing-box.txt, GPL-3.0.txt"
            ),
            "{text}"
        );
        assert!(text.contains("source: https://github.com/SagerNet/sing-box/tree/v1.14.4"));
        assert!(text.contains("flag-icons"));
        assert!(
            text.contains(
                "==== deep 1.0.0 (LICENSE), linked 1.0.0 (LICENSE-MIT) ====\n\nMIT text\n"
            ),
            "{text}"
        );
        assert!(
            !text.contains("dev-only")
                && !text.contains("build-only")
                && !text.contains("vpnte-base")
        );
        fs::remove_dir_all(&base).unwrap();
    }
}
