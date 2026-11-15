//! Link schemes at install, start and uninstall (RU-2026 item 4, `vpnte_winnet::url_scheme`): the
//! installer's `--setup register-links` and the installed copy's start register this user's free
//! schemes the first time and later only point ours at the current exe; `--setup uninstall`
//! removes exactly the schemes recorded for the installed exe. A portable copy registers nothing
//! by itself (it has no uninstaller, and a deleted folder would leave links pointing at nothing):
//! its link panel offers «open links here». Per user (HKCU), no rights needed.
use std::path::{Path, PathBuf};

use vpnte_winnet::registry::{Access, Hive, Key, View};
use vpnte_winnet::url_scheme::Registrar;

use super::{End, gate};

/// The area name in the helper's output.
pub const AREA: &str = "link schemes";

/// `--setup register-links --install-dir <dir>`: a failure is a warning for the installer (the
/// app registers again at its first start), never a failed installation.
pub(super) fn register(dir: &Path) -> End {
    End::Done(vec![ensure_line(
        &Registrar::current_user(),
        &dir.join(gate::MAIN_EXE),
    )])
}

/// Where the per-user installer recorded its installation (`vpnte.nsi`: `KEY_INSTALL`).
const KEY_INSTALL: &str = r"Software\6ed500d7-e3cc-5276-81ea-221a0c3a3238";

/// The installed copy's folder for this user, if the installer ran.
fn installed_dir() -> Option<PathBuf> {
    let key = Key::open(Hive::CurrentUser, KEY_INSTALL, Access::Read, View::Native).ok()??;
    key.string("InstallLocation").ok()?.map(PathBuf::from)
}

/// `true` unless `exe` runs from the folder the installer recorded: a portable copy.
pub fn is_portable(exe: &Path) -> bool {
    !installed_dir().is_some_and(|dir| same_dir(&dir, exe))
}

/// `exe` lies directly in `dir` (paths compared as Windows compares names).
fn same_dir(dir: &Path, exe: &Path) -> bool {
    let canonical = |p: &Path| std::fs::canonicalize(p).ok();
    match (canonical(dir), exe.parent().and_then(canonical)) {
        (Some(a), Some(b)) => a.as_os_str().eq_ignore_ascii_case(b.as_os_str()),
        _ => false,
    }
}

/// The installed copy's start (release builds; a debug exe is a build artifact): the same as the
/// installer's step, for a user the installer never saw. A portable copy leaves the schemes to its
/// link panel. Logged, never shown.
pub fn sync_at_start() {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(err) => {
            tracing::warn!(%err, "link schemes not synced: own path unknown");
            return;
        }
    };
    if is_portable(&exe) {
        tracing::info!("portable copy: link schemes are registered only from the links panel");
        return;
    }
    let registrar = Registrar::current_user();
    match registrar.ensure(&exe) {
        Ok(done) => {
            if done.changed() {
                registrar.notify_shell();
            }
            tracing::info!(
                registered = ?done.registered,
                repointed = done.repointed,
                released = ?done.released,
                "link schemes synced"
            );
        }
        Err(err) => tracing::warn!(%err, "link schemes not synced"),
    }
}

/// One output line of [`register`].
fn ensure_line(registrar: &Registrar, exe: &Path) -> String {
    match registrar.ensure(exe) {
        Ok(done) => {
            if done.changed() {
                registrar.notify_shell();
            }
            let names = if done.registered.is_empty() {
                "none new".to_owned()
            } else {
                done.registered.join(" ")
            };
            let released = if done.released.is_empty() {
                String::new()
            } else {
                format!("; given back: {}", done.released.join(" "))
            };
            format!(
                "{AREA}: done (registered: {names}; re-pointed: {}{released})",
                done.repointed
            )
        }
        Err(err) => format!("warning: {AREA}: FAILED ({})", code(&err)),
    }
}

/// `--setup uninstall`: the schemes recorded for `exe` go, the keys they replaced come back; a
/// failure is a warning (a leftover scheme only starts a missing exe; nothing is cut off).
pub(super) fn uninstall_line(registrar: &Registrar, exe: &Path) -> String {
    match registrar.unregister_for(exe) {
        Ok(removed) => {
            if !removed.is_empty() {
                registrar.notify_shell();
            }
            format!("{AREA}: done (removed {})", removed.len())
        }
        Err(err) => format!("warning: {AREA}: FAILED ({})", code(&err)),
    }
}

fn code(err: &windows::core::Error) -> String {
    format!("0x{:08X}", err.code().0.cast_unsigned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throw-away `HKCU\Software\VPNTE-Test-*` root, deleted on drop.
    struct Root(String);

    impl Root {
        fn new() -> Self {
            Self(format!(
                r"Software\VPNTE-Test-links-{}",
                uuid::Uuid::new_v4().simple()
            ))
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            let _ = vpnte_winnet::registry::delete_tree(
                vpnte_winnet::registry::Hive::CurrentUser,
                &self.0,
                vpnte_winnet::registry::View::Native,
            );
        }
    }

    /// phones-b7: a copy outside the installer's recorded folder counts as portable (it registers
    /// links only from its panel); the recorded key is the installer's own.
    #[test]
    fn a_copy_outside_the_installed_folder_is_portable() {
        let script = include_str!("../../../../installer/vpnte.nsi");
        let guid = KEY_INSTALL.rsplit('\\').next().unwrap_or_default();
        assert!(script.contains(&format!("!define APP_GUID \"{guid}\"")));
        assert!(script.contains(r#"!define KEY_INSTALL "Software\${APP_GUID}""#));
        let dir =
            std::env::temp_dir().join(format!("vpnte-portable-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join(gate::MAIN_EXE);
        std::fs::write(&exe, b"").unwrap();
        assert!(same_dir(&dir, &exe));
        let upper = std::path::PathBuf::from(dir.to_string_lossy().to_uppercase());
        assert!(
            same_dir(&upper, &exe),
            "names compare as Windows compares them"
        );
        assert!(!same_dir(&std::env::temp_dir(), &exe));
        // This test exe is no installed copy (the installer never recorded a test folder).
        assert!(is_portable(&exe));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The installer's register step and the uninstall step leave nothing of ours behind.
    #[test]
    fn install_then_uninstall_leaves_no_scheme_behind() {
        let root = Root::new();
        let registrar = Registrar::under(&root.0);
        let exe = Path::new(r"C:\Users\x\AppData\Local\Programs\VPN Tunnel Enforcer")
            .join(gate::MAIN_EXE);
        let line = ensure_line(&registrar, &exe);
        assert!(
            line.starts_with("link schemes: done (registered: vless vmess"),
            "{line}"
        );
        let again = ensure_line(&registrar, &exe);
        assert_eq!(
            again,
            "link schemes: done (registered: none new; re-pointed: 0)"
        );
        let line = uninstall_line(&registrar, &exe);
        assert_eq!(
            line,
            format!(
                "link schemes: done (removed {})",
                vpnte_winnet::url_scheme::SCHEMES.len()
            )
        );
        assert!(!registrar.initialized().unwrap());
        for state in registrar.states(&exe).unwrap() {
            assert_eq!(
                state.owner,
                vpnte_winnet::url_scheme::Owner::Free,
                "{}",
                state.scheme
            );
        }
    }
}
