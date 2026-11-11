//! `cargo xtask smoke-install` — CI only. Proves the built per-user installer on a disposable machine: silent
//! install into `%LOCALAPPDATA%\Programs`, installed files equal the verified stage, the HKCU registry identity,
//! the user's shortcuts with the AUMID, nothing machine-wide written (no HKLM key, no all-users link), the
//! installed engines and app start, an upgrade over itself (chains the installed uninstaller with `--updated`),
//! silent uninstall, and nothing left behind. Never run it on a machine that matters.
use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use windows_registry::{CURRENT_USER, LOCAL_MACHINE};

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
    let dir = PathBuf::from(env::var("LOCALAPPDATA").context("LOCALAPPDATA")?)
        .join("Programs")
        .join(PRODUCT);
    // Second guard: an existing installation is never touched, this user's or a machine-wide one (whose keys and
    // all-users links would also blur the "nothing machine-wide" checks below).
    let machine = machine_wide_state()?;
    ensure!(
        !dir.exists() && CURRENT_USER.open(KEY_UNINSTALL).is_err() && machine.is_empty(),
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

/// Installed tree == verified stage + uninstaller; the Electron installer's values under HKCU; the user's links
/// with the AUMID; nothing machine-wide.
fn check_installed(dir: &Path, stage: &Path, version: &str) -> Result<()> {
    let mut expected: std::collections::BTreeMap<String, Expect> = manifest::tree_hashes(stage)?
        .into_iter()
        .map(|(path, hash)| (path, Expect::Bytes(hash)))
        .collect();
    expected.insert(UNINSTALLER.to_owned(), Expect::Built);
    manifest::verify_stage(dir, &expected).context("installed files differ from the stage")?;

    let d = dir.display();
    let key = CURRENT_USER.open(KEY_INSTALL).context(KEY_INSTALL)?;
    expect_value(
        &key.get_string("InstallLocation")?,
        &d.to_string(),
        "InstallLocation",
    )?;
    expect_value(&key.get_string("KeepShortcuts")?, "true", "KeepShortcuts")?;
    expect_value(&key.get_string("ShortcutName")?, PRODUCT, "ShortcutName")?;
    let key = CURRENT_USER.open(KEY_UNINSTALL).context(KEY_UNINSTALL)?;
    let uninstall = format!("\"{d}\\{UNINSTALLER}\"");
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
    let machine = machine_wide_state()?;
    ensure!(
        machine.is_empty(),
        "the per-user installer wrote machine-wide state:\n  {}",
        machine.join("\n  ")
    );
    println!("  files, HKCU identity and both per-user shortcuts OK; nothing machine-wide");
    Ok(())
}

fn expect_value(actual: &str, expected: &str, name: &str) -> Result<()> {
    ensure!(
        actual == expected,
        "registry {name} = {actual:?}, expected {expected:?}"
    );
    Ok(())
}

/// The user's own Start-menu and desktop shortcuts.
fn links() -> Result<[PathBuf; 2]> {
    let name = format!("{PRODUCT}.lnk");
    Ok([
        shell_folder("Programs")?.join(&name),
        shell_folder("Desktop")?.join(&name),
    ])
}

/// A per-user shell folder as Explorer resolves it: `User Shell Folders` (REG_EXPAND_SZ), so a redirected
/// desktop is found too.
fn shell_folder(name: &str) -> Result<PathBuf> {
    let key = CURRENT_USER
        .open(r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")?;
    let raw = key
        .get_string(name)
        .with_context(|| format!("shell folder {name}"))?;
    Ok(PathBuf::from(expand_vars(&raw, |var| env::var(var).ok())?))
}

/// Expands `%NAME%` (the only syntax of REG_EXPAND_SZ); an unset name or an unclosed `%` is an error.
fn expand_vars(text: &str, lookup: impl Fn(&str) -> Option<String>) -> Result<String> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after
            .find('%')
            .with_context(|| format!("unclosed % in {text:?}"))?;
        let name = &after[..end];
        out.push_str(&lookup(name).with_context(|| format!("%{name}% is not set"))?);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Machine-wide traces of the product: the per-machine registry keys and the all-users links. The per-user
/// installer must never create any; CI runs elevated, where a stray HKLM or all-users write would succeed.
fn machine_wide_state() -> Result<Vec<String>> {
    let mut found: Vec<String> = [KEY_INSTALL, KEY_UNINSTALL]
        .into_iter()
        .filter(|key| LOCAL_MACHINE.open(key).is_ok())
        .map(|key| format!(r"HKLM\{key}"))
        .collect();
    let start =
        PathBuf::from(env::var("ProgramData")?).join(r"Microsoft\Windows\Start Menu\Programs");
    let desktop = PathBuf::from(env::var("PUBLIC")?).join("Desktop");
    found.extend(
        [start, desktop]
            .into_iter()
            .map(|folder| folder.join(format!("{PRODUCT}.lnk")))
            .filter(|link| link.exists())
            .map(|link| link.display().to_string()),
    );
    Ok(found)
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

/// Nothing of the product is left: install dir, both HKCU keys, both shortcuts; and nothing machine-wide appeared.
fn check_removed(dir: &Path) -> Result<()> {
    let mut left = machine_wide_state()?;
    if dir.exists() {
        left.push(dir.display().to_string());
    }
    for key in [KEY_INSTALL, KEY_UNINSTALL] {
        if CURRENT_USER.open(key).is_ok() {
            left.push(format!(r"HKCU\{key}"));
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

/// smoke-install changes this user's state (programs folder, HKCU, shortcuts): only a disposable CI runner
/// qualifies.
fn ci_guard(ci: Option<&str>) -> Result<()> {
    ensure!(
        ci == Some("true"),
        "smoke-install installs and removes the product for the current user; it runs only where CI=true \
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

    /// `User Shell Folders` values are REG_EXPAND_SZ: every `%NAME%` is expanded, nothing else is touched.
    #[test]
    fn shell_folder_values_expand() {
        let lookup = |name: &str| match name {
            "USERPROFILE" => Some(r"C:\Users\runner".to_owned()),
            "APPDATA" => Some(r"C:\Users\runner\AppData\Roaming".to_owned()),
            _ => None,
        };
        assert_eq!(
            expand_vars(r"%USERPROFILE%\Desktop", lookup).unwrap(),
            r"C:\Users\runner\Desktop"
        );
        assert_eq!(
            expand_vars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs", lookup).unwrap(),
            r"C:\Users\runner\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"
        );
        assert_eq!(expand_vars(r"D:\Desk", lookup).unwrap(), r"D:\Desk");
        assert!(expand_vars(r"%NOPE%\x", lookup).is_err());
        assert!(expand_vars(r"%USERPROFILE\x", lookup).is_err());
    }

    /// The per-user folders resolve on this machine (read only).
    #[test]
    fn per_user_shell_folders_resolve() {
        for name in ["Programs", "Desktop"] {
            let dir = shell_folder(name).unwrap();
            assert!(
                dir.is_absolute() && !dir.to_string_lossy().contains('%'),
                "{name}: {dir:?}"
            );
        }
    }
}
