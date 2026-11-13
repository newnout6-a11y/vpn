//! `cargo xtask dist`: release build, the installed layout in `target/stage`, the installer, the portable archive
//! and `checksums.txt`.
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};

use crate::manifest::{self, Manifest, Sha256Hex};
use crate::{fetch, notices, tools};

/// Stage files produced by the build, not pinned: (path in the stage, file name in the build output dir).
/// `vpnte-service.exe` sits next to the app: its `install` verb copies itself and the pinned engine files of
/// `resources\` into Program Files (installer, Settings button, portable archive alike).
pub const BUILT: [(&str, &str); 4] = [
    ("VPN Tunnel Enforcer.exe", "vpn-tunnel-enforcer.exe"),
    ("vpnte-service.exe", "vpnte-service.exe"),
    ("vpnte-proxy.exe", "vpnte_proxy.exe"),
    (
        "licenses/THIRD-PARTY-NOTICES.txt",
        "THIRD-PARTY-NOTICES.txt",
    ),
];
const SCRIPT: &str = "installer/vpnte.nsi";
/// Top-level folder inside the portable archive.
const PORTABLE_ROOT: &str = "VPN Tunnel Enforcer";

/// Installer file name for a version (old electron-builder naming kept).
pub fn installer_name(version: &str) -> String {
    format!("VPN-Tunnel-Enforcer-Setup-{version}.exe")
}

/// Portable archive file name for a version: the staged layout as a zip; needs no installation and no administrator.
pub fn portable_name(version: &str) -> String {
    format!("VPN-Tunnel-Enforcer-{version}-portable.zip")
}

/// The release's helper service as an artifact of its own (p-svc-update): the bytes the installer carries,
/// listed in `checksums.txt`, so `cargo xtask feed` adds it as the feed's `service` entry. An installed service
/// takes it from the signed feed before the app runs the installer, which then finds the service current and
/// asks Windows nothing.
pub fn service_name(version: &str) -> String {
    format!("vpnte-service-{version}.exe")
}

/// Lab packages (WP-12) carry this suffix in every artifact name, so they cannot pass for a release.
const LAB_SUFFIX: &str = "-lab";

/// Runs the whole pipeline; with `skip_build` the build outputs are taken from `bin_dir` (default target/release).
/// `lab` builds the app with its `lab` feature and stages the lab archives (AT-12-002: only on request).
pub fn run(root: &Path, skip_build: bool, bin_dir: Option<PathBuf>, lab: bool) -> Result<()> {
    let version = workspace_version(root)?;
    let manifest = Manifest::load(root)?.composition(lab);
    let bin_dir = if skip_build {
        let dir = match bin_dir {
            Some(dir) => std::path::absolute(dir)?,
            None => root.join("target/release"),
        };
        println!(
            "  build    skipped: taking build outputs from {}",
            dir.display()
        );
        dir
    } else {
        ensure!(
            bin_dir.is_none(),
            "--bin-dir applies only with --skip-build"
        );
        build(root, &manifest, &version, lab)?
    };
    let stage = root.join("target/stage");
    stage_all(root, &manifest, &bin_dir, &stage)?;
    let built: Vec<&str> = BUILT.iter().map(|(staged, _)| *staged).collect();
    let expected = manifest.expected_stage(&built)?;
    manifest::verify_stage(&stage, &expected)?;
    println!(
        "  stage    exact file set verified ({} files)",
        expected.len()
    );

    let makensis = tools::nsis(root)?;
    let dist = root.join("target/dist");
    recreate(&dist)?;
    compile(root, &makensis, &version, &stage, &dist)?;
    let installer = dist.join(installer_name(&version));
    ensure!(
        installer.is_file(),
        "makensis reported success but {} is missing",
        installer.display()
    );
    let installer = if lab {
        let renamed = dist.join(lab_name(&installer_name(&version)));
        fs::rename(&installer, &renamed).context("name the lab installer")?;
        renamed
    } else {
        installer
    };
    let portable = portable_name(&version);
    let portable = dist.join(if lab { lab_name(&portable) } else { portable });
    write_portable(&stage, expected.keys().map(String::as_str), &portable)?;
    let service = copy_service(&stage, &dist, &version, lab)?;
    write_checksums(&dist)?;
    println!("  dist     {}", installer.display());
    println!("  dist     {}", portable.display());
    println!("  dist     {}", service.display());
    Ok(())
}

/// `vpnte-service.exe` of the stage as [`service_name`] in `dist` (lab builds marked: never a feed entry).
fn copy_service(stage: &Path, dist: &Path, version: &str, lab: bool) -> Result<PathBuf> {
    let name = service_name(version);
    let to = dist.join(if lab { lab_name(&name) } else { name });
    fs::copy(stage.join("vpnte-service.exe"), &to).context("copy the service exe into dist")?;
    Ok(to)
}

/// `[workspace.package] version` of the workspace `Cargo.toml`; must be plain `X.Y.Z` (NSIS version resource).
pub fn workspace_version(root: &Path) -> Result<String> {
    let text = fs::read_to_string(root.join("Cargo.toml")).context("read workspace Cargo.toml")?;
    let table: toml::Table = toml::from_str(&text).context("parse workspace Cargo.toml")?;
    let version = table
        .get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("version"))
        .and_then(|v| v.as_str())
        .context("workspace Cargo.toml has no [workspace.package] version")?;
    let parts: Vec<&str> = version.split('.').collect();
    let numeric = parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    ensure!(
        numeric,
        "workspace version `{version}` must be X.Y.Z (the installer version resource is numeric)"
    );
    Ok(version.to_owned())
}

/// `name` with [`LAB_SUFFIX`] before its extension.
pub fn lab_name(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) => format!("{stem}{LAB_SUFFIX}.{ext}"),
        None => format!("{name}{LAB_SUFFIX}"),
    }
}

/// Release build of the two shipped binaries plus the generated notices; returns the output directory.
fn build(root: &Path, manifest: &Manifest, version: &str, lab: bool) -> Result<PathBuf> {
    let args = [
        "build",
        "--release",
        "--locked",
        "-p",
        "vpnte-app",
        "-p",
        "vpnte-proxies",
        "-p",
        "vpnte-service",
    ];
    run_tool(
        Command::new(cargo())
            .args(args)
            .args(["--bin", "vpn-tunnel-enforcer", "--bin", "vpnte_proxy"])
            .args(["--bin", "vpnte-service"])
            .args(
                lab.then_some(["--features", "vpnte-app/lab"])
                    .into_iter()
                    .flatten(),
            )
            .current_dir(root),
    )?;
    let metadata = notices::metadata(root)?;
    let out = metadata.target_directory.join("release");
    let text = notices::render(root, manifest, &metadata, version)?;
    fs::write(
        out.join("THIRD-PARTY-NOTICES.txt"),
        manifest::to_crlf(text.as_bytes()),
    )
    .context("write THIRD-PARTY-NOTICES.txt")?;
    Ok(out)
}

/// Fresh `target/stage` with every pinned file (verified) and the build outputs under their installed names.
fn stage_all(root: &Path, manifest: &Manifest, bin_dir: &Path, stage: &Path) -> Result<()> {
    recreate(stage)?;
    let put = |install: &str, data: &[u8]| -> Result<()> {
        let target = stage.join(install);
        fs::create_dir_all(target.parent().context("install path has no parent")?)?;
        fs::write(&target, data).with_context(|| format!("write {}", target.display()))
    };
    for archive in &manifest.archive {
        let bytes = fetch::cached(root, &archive.id, &archive.url, &archive.sha256, false)?;
        let mut zip = fetch::open(&archive.id, bytes)?;
        for file in &archive.files {
            put(
                file.install.as_str(),
                &fetch::member(&mut zip, &archive.id, &file.path, &file.sha256)?,
            )?;
        }
    }
    for local in &manifest.local {
        let raw = fs::read(root.join(local.repo.as_str()))
            .with_context(|| format!("read {}", local.repo))?;
        let pinned = if local.text {
            manifest::normalize_text(&raw)
        } else {
            raw
        };
        let actual = Sha256Hex::of(&pinned);
        ensure!(
            actual == local.sha256,
            "{}: hash mismatch (pinned {}, found {actual})",
            local.repo,
            local.sha256
        );
        put(
            local.install.as_str(),
            &if local.text {
                manifest::to_crlf(&pinned)
            } else {
                pinned
            },
        )?;
    }
    for (staged, built) in BUILT {
        let source = bin_dir.join(built);
        let data = fs::read(&source)
            .with_context(|| format!("build output {} is missing", source.display()))?;
        put(staged, &data)?;
    }
    Ok(())
}

/// `makensis` with warnings as errors; every path goes in as a define, so the script holds no machine paths.
fn compile(root: &Path, makensis: &Path, version: &str, stage: &Path, dist: &Path) -> Result<()> {
    let mut cmd = Command::new(makensis);
    cmd.args(["/V2", "/WX", "/INPUTCHARSET", "UTF8"])
        .arg(format!("/DVERSION={version}"))
        .arg(format!("/DSTAGE={}", win(stage)))
        .arg(format!("/DOUTDIR={}", win(dist)))
        .arg(win(&root.join(SCRIPT)));
    run_tool(&mut cmd)
}

/// Zips the staged layout under one top-level folder. Entries are sorted and carry a fixed timestamp, so the same
/// stage always gives the same archive bytes.
fn write_portable<'a>(
    stage: &Path,
    files: impl Iterator<Item = &'a str>,
    out: &Path,
) -> Result<()> {
    let mut names: Vec<&str> = files.collect();
    names.sort_unstable();
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .last_modified_time(zip::DateTime::DEFAULT);
    let file = fs::File::create(out).with_context(|| format!("create {}", out.display()))?;
    let mut zip = zip::ZipWriter::new(file);
    for name in names {
        let data = fs::read(stage.join(name)).with_context(|| format!("read staged {name}"))?;
        zip.start_file(format!("{PORTABLE_ROOT}/{name}"), options)?;
        zip.write_all(&data)?;
    }
    zip.finish()?.flush().context("write the portable archive")
}

/// `checksums.txt`: `<sha256>  <file>` per artifact, sorted by name, the file itself not listed.
fn write_checksums(dist: &Path) -> Result<()> {
    let mut names: Vec<String> = fs::read_dir(dist)?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_, _>>()?;
    names.retain(|n| n != "checksums.txt");
    names.sort();
    let mut text = String::new();
    for name in names {
        let digest = Sha256Hex::of(&fs::read(dist.join(&name))?);
        text.push_str(&format!("{digest}  {name}\n"));
    }
    fs::write(dist.join("checksums.txt"), text).context("write checksums.txt")
}

/// Empties a build directory (only ever one of ours under target/).
fn recreate(dir: &Path) -> Result<()> {
    if dir.exists() {
        fs::remove_dir_all(dir).with_context(|| format!("remove {}", dir.display()))?;
    }
    fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))
}

/// Runs a tool with inherited output and fails on a non-zero exit.
pub fn run_tool(cmd: &mut Command) -> Result<()> {
    let shown = format!(
        "{} {}",
        cmd.get_program().to_string_lossy(),
        cmd.get_args()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!("  run      {shown}");
    let status = cmd.status().with_context(|| format!("start {shown}"))?;
    if !status.success() {
        bail!("`{shown}` failed with {status}");
    }
    Ok(())
}

/// The cargo that runs this xtask (`cargo xtask` sets CARGO), so the same toolchain builds the product.
pub fn cargo() -> PathBuf {
    std::env::var_os("CARGO")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("cargo"))
}

/// A path with Windows separators for tools that do not accept `/`.
fn win(path: &Path) -> String {
    path.to_string_lossy().replace('/', "\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
    }

    /// AT-11-004: the script installs and removes exactly what the stage holds. Root files are listed by
    /// name in both directions (the uninstaller never runs `RMDir /r $INSTDIR`); folders are copied whole.
    #[test]
    fn script_installs_and_removes_every_staged_root_entry() {
        let script = fs::read_to_string(root().join(SCRIPT)).unwrap();
        let script = script.replace("${EXE}", "VPN Tunnel Enforcer.exe");
        let manifest = Manifest::load(root()).unwrap();
        let built: Vec<&str> = BUILT.iter().map(|(staged, _)| *staged).collect();
        let stage = manifest.expected_stage(&built).unwrap();
        let mut folders = std::collections::BTreeSet::new();
        for path in stage.keys() {
            match path.split_once('/') {
                Some((folder, _)) => {
                    folders.insert(folder.to_owned());
                }
                None => {
                    let file = format!("File \"${{STAGE}}\\{path}\"");
                    let delete = format!("Delete \"$INSTDIR\\{path}\"");
                    assert!(script.contains(&file), "missing `{file}`");
                    assert!(script.contains(&delete), "missing `{delete}`");
                }
            }
        }
        assert_eq!(
            folders.iter().map(String::as_str).collect::<Vec<_>>(),
            ["licenses", "resources"]
        );
        for folder in folders {
            let copy = format!("File /r \"${{STAGE}}\\{folder}\\*\"");
            let remove = format!("RMDir /r \"$INSTDIR\\{folder}\"");
            assert!(
                script.contains(&copy) && script.contains(&remove),
                "{folder}"
            );
        }
        let unscoped = script
            .lines()
            .any(|l| l.trim().starts_with("RMDir /r \"$INSTDIR\""));
        assert!(
            !unscoped,
            "the uninstaller must not delete $INSTDIR recursively"
        );
    }

    /// NOADMIN: installer and uninstaller run with the user's own token. User level, the user's program folder
    /// and shell context, every registry write under HKCU (HKLM is only read: the old per-machine installation),
    /// no elevation verb, and the previous uninstaller is looked up in HKCU only (never the per-machine one).
    /// The helper service's one elevated step is not the script's: `vpnte-service.exe request-install` asks
    /// Windows for it (NOADMIN §0).
    #[test]
    fn script_needs_no_administrator_rights() {
        let script = fs::read_to_string(root().join(SCRIPT)).unwrap();
        let code: Vec<&str> = script
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with(';'))
            .collect();
        assert!(code.contains(&"RequestExecutionLevel user"));
        assert!(code.contains(&"InstallDir \"$LOCALAPPDATA\\Programs\\${PRODUCT}\""));
        assert!(code.contains(&"ReadRegStr $R0 HKCU \"${KEY_UNINSTALL}\" \"UninstallString\""));
        for line in &code {
            let lower = line.to_ascii_lowercase();
            let writes_registry = ["writereg", "deletereg"]
                .iter()
                .any(|w| lower.starts_with(w));
            assert!(
                !writes_registry || lower.contains(" hkcu "),
                "registry write outside HKCU: {line}"
            );
            for banned in [
                "requestexecutionlevel admin",
                "requestexecutionlevel highest",
                "setshellvarcontext all",
                "shctx",
                "$programfiles",
                "runas",
                "uac::",
            ] {
                assert!(!lower.contains(banned), "`{banned}` in: {line}");
            }
        }
    }

    #[test]
    fn workspace_version_is_plain_semver() {
        let version = workspace_version(root()).unwrap();
        assert_eq!(version.split('.').count(), 3);
        assert_eq!(
            installer_name("2.0.0"),
            "VPN-Tunnel-Enforcer-Setup-2.0.0.exe"
        );
    }

    /// AT-12-002: a lab package is named as one in every artifact.
    #[test]
    fn lab_artifacts_are_marked() {
        assert_eq!(
            lab_name(&installer_name("2.0.0")),
            "VPN-Tunnel-Enforcer-Setup-2.0.0-lab.exe"
        );
        assert_eq!(
            lab_name(&portable_name("2.0.0")),
            "VPN-Tunnel-Enforcer-2.0.0-portable-lab.zip"
        );
    }

    /// The portable archive holds exactly the staged files under one folder and is reproducible.
    #[test]
    fn portable_archive_is_the_stage_and_reproducible() {
        let dir = root().join("target/xtask/test-scratch/portable");
        recreate(&dir).unwrap();
        let stage = dir.join("stage");
        fs::create_dir_all(stage.join("resources")).unwrap();
        fs::write(stage.join("b.exe"), b"bbbb").unwrap();
        fs::write(stage.join("resources/a.dll"), b"aaaa").unwrap();
        let files = ["resources/a.dll", "b.exe"];
        let (one, two) = (dir.join("one.zip"), dir.join("two.zip"));
        write_portable(&stage, files.into_iter(), &one).unwrap();
        write_portable(&stage, files.into_iter().rev(), &two).unwrap();
        assert_eq!(fs::read(&one).unwrap(), fs::read(&two).unwrap());
        let mut zip = zip::ZipArchive::new(fs::File::open(&one).unwrap()).unwrap();
        let names: Vec<String> = (0..zip.len())
            .map(|i| zip.by_index(i).unwrap().name().unwrap().into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "VPN Tunnel Enforcer/b.exe",
                "VPN Tunnel Enforcer/resources/a.dll"
            ]
        );
        assert_eq!(
            portable_name("2.0.0"),
            "VPN-Tunnel-Enforcer-2.0.0-portable.zip"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    /// p-svc-update: the service artifact is the staged exe byte for byte (what the installer carries), named
    /// as `cargo xtask feed` looks for it; a lab build's is marked and so never becomes a feed entry.
    #[test]
    fn the_service_artifact_is_the_staged_exe() {
        let dir = root().join("target/xtask/test-scratch/service");
        recreate(&dir).unwrap();
        let (stage, dist) = (dir.join("stage"), dir.join("dist"));
        fs::create_dir_all(&stage).unwrap();
        fs::create_dir_all(&dist).unwrap();
        fs::write(stage.join("vpnte-service.exe"), b"service bytes").unwrap();
        let release = copy_service(&stage, &dist, "2.0.1", false).unwrap();
        assert_eq!(release, dist.join("vpnte-service-2.0.1.exe"));
        assert_eq!(fs::read(&release).unwrap(), b"service bytes");
        let lab = copy_service(&stage, &dist, "2.0.1", true).unwrap();
        assert_eq!(lab, dist.join("vpnte-service-2.0.1-lab.exe"));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// AT-11-006: one `<sha256>  <name>` line per artifact, sorted, the checksum file itself not listed.
    #[test]
    fn checksums_list_every_artifact_once() {
        let dir = root().join("target/xtask/test-scratch/checksums");
        recreate(&dir).unwrap();
        fs::write(dir.join("b.exe"), b"b").unwrap();
        fs::write(dir.join("VPN-Tunnel-Enforcer-Setup-2.0.0.exe"), b"setup").unwrap();
        write_checksums(&dir).unwrap();
        write_checksums(&dir).unwrap(); // a re-run must not list checksums.txt
        let text = fs::read_to_string(dir.join("checksums.txt")).unwrap();
        let expected = format!(
            "{}  VPN-Tunnel-Enforcer-Setup-2.0.0.exe\n{}  b.exe\n",
            Sha256Hex::of(b"setup"),
            Sha256Hex::of(b"b")
        );
        assert_eq!(text, expected);
        fs::remove_dir_all(&dir).unwrap();
    }
}
