//! `cargo xtask <command>`: build automation that must behave the same locally and in CI.
mod dist;
mod engines;
mod feed;
mod fetch;
mod manifest;
mod notices;
#[cfg(all(test, windows))]
mod nsis_webview2;
#[cfg(windows)]
mod smoke;
mod tools;

use std::path::PathBuf;

use anyhow::{Result, bail};

const USAGE: &str = "\
cargo xtask <command>

  engines [--offline]   download the pinned engines, verify every hash, fill the dev drop resources/
                        (the WP-12 lab engine mihomo included: tests use it; also the WebView2 bootstrapper)
  verify                check that resources/ holds exactly the pinned engine files
  nsis                  fetch and verify the pinned NSIS, unpack it to target/tools/nsis
  dist [--skip-build] [--bin-dir DIR] [--lab]
                        build the two shipped binaries (release, --locked), stage the installed layout in
                        target/stage, check its exact file set, compile installer/vpnte.nsi and write
                        target/dist/{VPN-Tunnel-Enforcer-Setup-<version>.exe,
                        VPN-Tunnel-Enforcer-<version>-portable.zip (no installation, no administrator), checksums.txt};
                        --skip-build takes vpn-tunnel-enforcer.exe, vpnte_proxy.exe and
                        THIRD-PARTY-NOTICES.txt from DIR (default target/release) instead of running cargo;
                        --lab (WP-12 lab package, never a release): the app's `lab` feature, the lab engines
                        staged, every artifact named `...-lab`
  smoke-install         CI only (requires CI=true): install the built per-user installer silently, check files,
                        HKCU registry, links and app start, that nothing machine-wide was written, upgrade over
                        itself, uninstall, check that nothing is left
  version               print the workspace version (release tags must be v<version>)
  feed [--dist DIR | --base update.json] [--engines FILE] [--out DIR] [--seq N] [--severity S]
       [--notes-ru FILE] [--notes-en FILE] [--warn-below V] [--rollback-to V --rollback-checksums FILE
       --rollback-size N] [--pubkey RW...]
                        build the signed update feed (update.json + update.json.minisig, default target/feed)
                        with the key in UPDATE_SIGNING_KEY (+ UPDATE_SIGNING_PASSWORD); --verify checks one
";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = workspace_root()?;
    let flag = |name: &str| args.iter().any(|a| a == name);
    match args.first().map(String::as_str) {
        Some("engines") => engines::fetch(&root, flag("--offline")),
        Some("verify") => engines::verify(&root),
        Some("nsis") => tools::nsis(&root).map(drop),
        Some("dist") => {
            let bin_dir = match args.iter().position(|a| a == "--bin-dir") {
                Some(i) => Some(PathBuf::from(
                    args.get(i + 1)
                        .ok_or_else(|| anyhow::anyhow!("--bin-dir needs a value"))?,
                )),
                None => None,
            };
            dist::run(&root, flag("--skip-build"), bin_dir, flag("--lab"))
        }
        #[cfg(windows)]
        Some("smoke-install") => smoke::run(&root),
        #[cfg(not(windows))]
        Some("smoke-install") => bail!("smoke-install runs only on Windows"),
        Some("feed") => feed::run(&root, &args[1..]),
        Some("version") => {
            println!("{}", dist::workspace_version(&root)?);
            Ok(())
        }
        Some(other) => bail!("unknown command `{other}`\n\n{USAGE}"),
        None => {
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
        _ => bail!(
            "cannot locate the workspace root above {}",
            manifest.display()
        ),
    }
}
