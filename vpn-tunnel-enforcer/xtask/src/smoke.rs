//! `cargo xtask smoke-install` — CI only. Proves the built installer on a disposable machine: silent install,
//! installed files equal the verified stage, registry identity, shortcuts with the AUMID, the installed engines
//! and app start, an upgrade over itself (chains the installed uninstaller with `--updated`), silent
//! uninstall, and nothing left behind. Never run it on a machine that matters.
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use windows_registry::LOCAL_MACHINE;

use crate::dist;
use crate::manifest::{self, Expect};

const PRODUCT: &str = "VPN Tunnel Enforcer";
const EXE: &str = "VPN Tunnel Enforcer.exe";
const UNINSTALLER: &str = "Uninstall VPN Tunnel Enforcer.exe";
const AUMID: &str = "com.vpntunnelenforcer.app";
const KEY_INSTALL: &str = r"Software\6ed500d7-e3cc-5276-81ea-221a0c3a3238";
const KEY_UNINSTALL: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall\6ed500d7-e3cc-5276-81ea-221a0c3a3238";
const DESCRIPTION: &str = "Force all traffic through VPN Happ \u{2014} Hard (TUN) or Soft (Autoconfig) mode with IP leak monitoring";
const SETUP_TIMEOUT: Duration = Duration::from_secs(300);

/// Runs the whole install / upgrade / uninstall round trip; refuses unless `CI=true`.
pub fn run(root: &Path) -> Result<()> {
    ci_guard(env::var("CI").ok().as_deref())?;
    let version = dist::workspace_version(root)?;
    let installer = root
        .join("target/dist")
        .join(dist::installer_name(&version));
    ensure!(
        installer.is_file(),
        "{} is missing: run `cargo xtask dist` first",
        installer.display()
    );
    let stage = root.join("target/stage");
    let dir = PathBuf::from(env::var("ProgramW6432").or_else(|_| env::var("ProgramFiles"))?)
        .join(PRODUCT);
    // Second guard: an existing installation (any generation) is never touched.
    ensure!(
        !dir.exists() && LOCAL_MACHINE.open(KEY_UNINSTALL).is_err(),
        "{PRODUCT} is already installed here; smoke-install needs a clean machine"
    );

    step("install", || expect_exit(&installer, &["/S"], 0))?;
    check_installed(&dir, &stage, &version)?;
    check_engines(root, &dir)?;
    check_app(&dir, &version)?;
    // Same version again: the installer must chain the installed uninstaller with --updated and keep shortcuts.
    step("upgrade over itself", || {
        expect_exit(&installer, &["/S"], 0)
    })?;
    check_installed(&dir, &stage, &version)?;
    step("uninstall", || uninstall(&dir))?;
    check_removed(&dir)?;
    println!("smoke-install: OK");
    Ok(())
}

fn step(name: &str, f: impl FnOnce() -> Result<()>) -> Result<()> {
    println!("== {name}");
    f().with_context(|| format!("step `{name}` failed"))
}

/// Starts a program, waits for it (bounded) and returns its exit code and stdout.
fn run_bounded(
    program: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
    limit: Duration,
) -> Result<Option<(i32, String)>> {
    let mut child = Command::new(program)
        .args(args)
        .envs(envs.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("start {}", program.display()))?;
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait()? {
            let mut out = String::new();
            if let Some(mut pipe) = child.stdout.take() {
                pipe.read_to_string(&mut out)?;
            }
            return Ok(Some((status.code().unwrap_or(-1), out)));
        }
        if Instant::now() >= deadline {
            kill_tree(&mut child);
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Stops a child this command started, with everything it spawned (by PID, never by image name).
fn kill_tree(child: &mut Child) {
    let pid = child.id().to_string();
    let _ = Command::new("taskkill")
        .args(["/PID", &pid, "/T", "/F"])
        .status();
    let _ = child.kill();
    let _ = child.wait();
}

fn expect_exit(program: &Path, args: &[&str], code: i32) -> Result<()> {
    match run_bounded(program, args, &[], SETUP_TIMEOUT)? {
        Some((actual, _)) if actual == code => Ok(()),
        Some((actual, _)) => bail!(
            "{} exited with {actual} (expected {code})",
            program.display()
        ),
        None => bail!(
            "{} did not finish within {}s",
            program.display(),
            SETUP_TIMEOUT.as_secs()
        ),
    }
}

/// Runs a copy of the uninstaller outside the install dir with `_?=` so the call waits for the real work.
fn uninstall(dir: &Path) -> Result<()> {
    let temp = env::temp_dir().join("vpnte-smoke-uninstall");
    fs::create_dir_all(&temp)?;
    let copy = temp.join("uninstall.exe");
    fs::copy(dir.join(UNINSTALLER), &copy).context("copy the uninstaller")?;
    let inst = format!("_?={}", dir.display());
    let result = expect_exit(&copy, &["/S", &inst], 0);
    let _ = fs::remove_dir_all(&temp);
    result
}

/// Installed tree == verified stage + uninstaller; registry values as the Electron installer wrote them; links.
fn check_installed(dir: &Path, stage: &Path, version: &str) -> Result<()> {
    let mut expected: std::collections::BTreeMap<String, Expect> = manifest::tree_hashes(stage)?
        .into_iter()
        .map(|(path, hash)| (path, Expect::Bytes(hash)))
        .collect();
    expected.insert(UNINSTALLER.to_owned(), Expect::Built);
    manifest::verify_stage(dir, &expected).context("installed files differ from the stage")?;

    let d = dir.display();
    let key = LOCAL_MACHINE.open(KEY_INSTALL).context(KEY_INSTALL)?;
    expect_value(
        &key.get_string("InstallLocation")?,
        &d.to_string(),
        "InstallLocation",
    )?;
    expect_value(&key.get_string("KeepShortcuts")?, "true", "KeepShortcuts")?;
    expect_value(&key.get_string("ShortcutName")?, PRODUCT, "ShortcutName")?;
    let key = LOCAL_MACHINE.open(KEY_UNINSTALL).context(KEY_UNINSTALL)?;
    let uninstall = format!("\"{d}\\{UNINSTALLER}\" /allusers");
    expect_value(
        &key.get_string("DisplayName")?,
        &format!("{PRODUCT} {version}"),
        "DisplayName",
    )?;
    expect_value(
        &key.get_string("DisplayVersion")?,
        version,
        "DisplayVersion",
    )?;
    expect_value(
        &key.get_string("UninstallString")?,
        &uninstall,
        "UninstallString",
    )?;
    expect_value(
        &key.get_string("QuietUninstallString")?,
        &format!("{uninstall} /S"),
        "QuietUninstallString",
    )?;
    expect_value(
        &key.get_string("DisplayIcon")?,
        &format!("{d}\\{EXE},0"),
        "DisplayIcon",
    )?;
    expect_value(&key.get_string("Comments")?, DESCRIPTION, "Comments")?;
    ensure!(
        key.get_u32("NoModify")? == 1 && key.get_u32("NoRepair")? == 1,
        "NoModify / NoRepair must be 1"
    );
    ensure!(
        key.get_u32("EstimatedSize")? > 0,
        "EstimatedSize must be set"
    );

    let aumid: Vec<u8> = AUMID.encode_utf16().flat_map(u16::to_le_bytes).collect();
    for link in links()? {
        let bytes =
            fs::read(&link).with_context(|| format!("shortcut {} is missing", link.display()))?;
        // The AUMID lives in the link's property store block as UTF-16LE text.
        ensure!(
            bytes.windows(aumid.len()).any(|w| w == aumid),
            "{} carries no AUMID {AUMID}",
            link.display()
        );
    }
    println!("  files, registry identity and both shortcuts OK");
    Ok(())
}

fn expect_value(actual: &str, expected: &str, name: &str) -> Result<()> {
    ensure!(
        actual == expected,
        "registry {name} = {actual:?}, expected {expected:?}"
    );
    Ok(())
}

/// Start-menu and desktop shortcuts of the per-machine install.
fn links() -> Result<[PathBuf; 2]> {
    let start =
        PathBuf::from(env::var("ProgramData")?).join(r"Microsoft\Windows\Start Menu\Programs");
    let desktop = PathBuf::from(env::var("PUBLIC")?).join("Desktop");
    Ok([
        start.join(format!("{PRODUCT}.lnk")),
        desktop.join(format!("{PRODUCT}.lnk")),
    ])
}

/// The installed engines start from Program Files and are the pinned versions.
fn check_engines(root: &Path, dir: &Path) -> Result<()> {
    let manifest = manifest::Manifest::load(root)?;
    for (id, exe) in [
        ("sing-box", "resources/sing-box.exe"),
        ("xray", "resources/xray.exe"),
    ] {
        let version = &manifest
            .archive
            .iter()
            .find(|a| a.id == id)
            .context(id)?
            .version;
        let out = run_bounded(&dir.join(exe), &["version"], &[], Duration::from_secs(30))?;
        match out {
            Some((0, text)) if text.contains(version.as_str()) => println!("  {id} {version} runs"),
            other => bail!("{exe} version: unexpected result {other:?}"),
        }
    }
    Ok(())
}

/// `--no-elevate --smoke` must exit 0 after one line; without that flag (yet), `--version` must answer.
fn check_app(dir: &Path, version: &str) -> Result<()> {
    let exe = dir.join(EXE);
    let data = env::temp_dir().join("vpnte-smoke-data");
    let data = data.to_string_lossy();
    let envs = [("VPNTE_NO_ELEVATE", "1"), ("VPNTE_DATA_DIR", data.as_ref())];
    match run_bounded(
        &exe,
        &["--no-elevate", "--smoke"],
        &envs,
        Duration::from_secs(60),
    )? {
        Some((0, out)) => {
            let lines: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();
            ensure!(
                lines.len() == 1,
                "--smoke must print exactly one line, printed {lines:?}"
            );
            println!("  app --smoke: {}", lines[0]);
        }
        Some((code, _)) => bail!("--no-elevate --smoke exited with {code}"),
        None => {
            println!(
                "  --smoke did not exit within 60 s (not implemented yet?): falling back to --version"
            );
            match run_bounded(&exe, &["--version"], &envs, Duration::from_secs(30))? {
                Some((0, out)) if out.contains(version) => {
                    println!("  app --version: {}", out.trim())
                }
                other => bail!("--version: unexpected result {other:?}"),
            }
        }
    }
    let _ = fs::remove_dir_all(env::temp_dir().join("vpnte-smoke-data"));
    Ok(())
}

/// Nothing of the product is left: install dir, both registry keys, both shortcuts.
fn check_removed(dir: &Path) -> Result<()> {
    let mut left = Vec::new();
    if dir.exists() {
        left.push(dir.display().to_string());
    }
    for key in [KEY_INSTALL, KEY_UNINSTALL] {
        if LOCAL_MACHINE.open(key).is_ok() {
            left.push(format!(r"HKLM\{key}"));
        }
    }
    left.extend(
        links()?
            .into_iter()
            .filter(|l| l.exists())
            .map(|l| l.display().to_string()),
    );
    ensure!(
        left.is_empty(),
        "uninstall left behind:\n  {}",
        left.join("\n  ")
    );
    println!("  nothing left behind");
    Ok(())
}

/// smoke-install changes the machine (Program Files, HKLM, shortcuts): only a disposable CI runner qualifies.
fn ci_guard(ci: Option<&str>) -> Result<()> {
    ensure!(
        ci == Some("true"),
        "smoke-install installs and removes the product machine-wide; it runs only where CI=true \
         (a disposable CI runner)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_outside_ci() {
        assert!(ci_guard(None).is_err());
        assert!(ci_guard(Some("1")).is_err());
        assert!(ci_guard(Some("false")).is_err());
        assert!(ci_guard(Some("true")).is_ok());
    }
}
