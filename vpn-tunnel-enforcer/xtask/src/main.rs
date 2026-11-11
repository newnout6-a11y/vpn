//! `cargo xtask <command>`: build automation that must behave the same locally and in CI.
mod engines;

use std::path::PathBuf;

use anyhow::{Result, bail};

const USAGE: &str = "\
cargo xtask <command>

  engines [--offline]   download the pinned engines, verify every hash, fill resources/
  verify                check that resources/ holds exactly the pinned engine files
";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = workspace_root()?;
    match args.first().map(String::as_str) {
        Some("engines") => engines::fetch(&root, args.iter().any(|a| a == "--offline")),
        Some("verify") => engines::verify(&root),
        _ => {
            print!("{USAGE}");
            Ok(())
        }
    }
}

/// The workspace root is the parent of this crate's directory.
fn workspace_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    match manifest.parent() {
        Some(root) if root.join("Cargo.toml").is_file() => Ok(root.to_path_buf()),
        _ => bail!("cannot locate the workspace root above {}", manifest.display()),
    }
}
