//! Old files under `%ProgramData%\VPNTE` (spec §6.6 step 10): journals whose replay finished,
//! temp files, the old elevated scripts, quarantined copies and the boot report in
//! `manifests`, and the staged engine copies with their configs (credentials on disk) in
//! `runtime\<instance>\{tun-runtime, external-proxy-runtime}`. Kept: journals that were not
//! replayed (another user's proxy baseline, failed steps), `runtime\<instance>\traffic-forensics`
//! (old capture sessions, owned by the forensics crate) and the user's firewall backups
//! `windows-firewall-before-reset-*.wfw`. Empty folders go, up to `%ProgramData%\VPNTE`.
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

use super::journal::Trust;
use super::report::{Outcome, StepId, StepRecord};

/// Staged subtrees of a runtime instance that are deleted.
pub(crate) const STAGED: [&str; 2] = ["tun-runtime", "external-proxy-runtime"];

/// What happens to one file in `manifests`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileAction {
    Delete,
    /// A firewall backup the user may want: kept and reported.
    KeepBackup,
    /// A journal not (yet) replayed, or a file the old app did not write.
    Keep,
}

/// `finished` = journals whose replay completed in this run.
pub(crate) fn manifest_action(name: &str, finished: &[&str]) -> FileAction {
    let lower = name.to_lowercase();
    if finished.iter().any(|f| f.eq_ignore_ascii_case(name)) {
        FileAction::Delete
    } else if lower.starts_with("windows-firewall-before-reset-") && lower.ends_with(".wfw") {
        FileAction::KeepBackup
    } else if lower.starts_with("tmp-")
        || lower.ends_with(".ps1")
        || lower.contains(".corrupt-")
        || lower == "recovery-result.json"
    {
        FileAction::Delete
    } else {
        FileAction::Keep
    }
}

/// A directory that is not a reparse point (a junction planted in the path would redirect an
/// elevated delete elsewhere).
fn real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .is_ok_and(|m| m.is_dir() && m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0)
}

fn real_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .is_ok_and(|m| m.is_file() && m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0)
}

#[derive(Default)]
struct Tally {
    deleted: usize,
    kept: Vec<String>,
    errors: Vec<String>,
}

impl Tally {
    fn remove(&mut self, path: &Path, dir: bool) {
        let result = match dir {
            true => std::fs::remove_dir_all(path),
            false => std::fs::remove_file(path),
        };
        match result {
            Ok(()) => self.deleted += 1,
            Err(e) => self.errors.push(format!("{}: {e}", path.display())),
        }
    }
}

/// Step 10 (deleting machine-wide files needs elevation). `root` = `%ProgramData%\VPNTE`.
/// Files in `manifests` go only when `root` and `manifests` pass the trust check (they belong
/// to the journals). The staged engine copies go whenever every folder on the way is a real
/// folder: the old app may have created `root` without its protected ACL, and leaving configs
/// with credentials on disk is the worse outcome; only fixed names are ever deleted there.
pub(crate) fn clean(root: &Path, finished: &[&str], trust: Trust) -> StepRecord {
    let step = StepId::Files;
    if !root.exists() {
        return StepRecord::new(step, Outcome::Done, "no old ProgramData folder");
    }
    if !real_dir(root) {
        let detail = format!("{} is not a plain folder: files kept", root.display());
        return StepRecord::new(step, Outcome::Skipped, detail);
    }
    let mut t = Tally::default();
    let manifests = root.join("manifests");
    let mut untrusted = None;
    if real_dir(&manifests) {
        match trust(root, true).and_then(|()| trust(&manifests, true)) {
            Ok(()) => {
                for path in entries(&manifests) {
                    let name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default();
                    match manifest_action(name, finished) {
                        FileAction::Delete if real_file(&path) => t.remove(&path, false),
                        FileAction::KeepBackup => t.kept.push(path.display().to_string()),
                        _ => {}
                    }
                }
            }
            Err(problem) => untrusted = Some(problem),
        }
    }
    let runtime = root.join("runtime");
    if real_dir(&runtime) {
        for instance in entries(&runtime).into_iter().filter(|p| real_dir(p)) {
            for staged in STAGED.map(|s| instance.join(s)) {
                if real_dir(&staged) {
                    t.remove(&staged, true);
                }
            }
            let _ = std::fs::remove_dir(&instance);
        }
    }
    // Only empty folders go; a folder that still holds something stays silently.
    for dir in [&runtime, &manifests, &root.to_path_buf()] {
        if real_dir(dir) {
            let _ = std::fs::remove_dir(dir);
        }
    }
    let mut detail = format!("{} old files or folders deleted", t.deleted);
    if !t.kept.is_empty() {
        detail.push_str(&format!("; firewall backups kept: {}", t.kept.join(", ")));
    }
    if let Some(problem) = untrusted {
        detail.push_str(&format!(
            "; manifests not trusted ({}), kept",
            problem.reason()
        ));
    }
    let outcome = match (t.errors.is_empty(), untrusted.is_none()) {
        (false, _) => {
            detail.push_str(&format!("; failed: {}", t.errors.join("; ")));
            Outcome::Failed
        }
        (true, false) => Outcome::Skipped,
        (true, true) => Outcome::Done,
    };
    StepRecord::new(step, outcome, detail).changed(t.deleted > 0)
}

fn entries(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .map(|it| it.filter_map(|e| e.ok().map(|e| e.path())).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::super::journal::{ADAPTERS, FIREWALL};
    use super::super::trust::Untrusted;
    use super::*;
    use crate::test_support::TempDir;

    #[test]
    fn manifest_file_policy() {
        let finished = [FIREWALL];
        assert_eq!(
            manifest_action("firewall.json", &finished),
            FileAction::Delete
        );
        assert_eq!(manifest_action(ADAPTERS, &finished), FileAction::Keep);
        assert_eq!(
            manifest_action("latest-tun-network-baseline.json", &finished),
            FileAction::Keep
        );
        for junk in [
            "tmp-0f1e2d3c",
            "script-1234-1700000000000-abc.ps1",
            "old.PS1",
            "firewall.json.corrupt-1234",
            "recovery-result.json",
        ] {
            assert_eq!(
                manifest_action(junk, &finished),
                FileAction::Delete,
                "{junk}"
            );
        }
        assert_eq!(
            manifest_action(
                "windows-firewall-before-reset-2026-10-01T10-00-00-000Z.wfw",
                &finished
            ),
            FileAction::KeepBackup
        );
        assert_eq!(manifest_action("notes.txt", &finished), FileAction::Keep);
    }

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"x").unwrap();
    }

    /// §7.10: `traffic-forensics` stays while `tun-runtime` and `external-proxy-runtime` go;
    /// journals that were not replayed and firewall backups stay.
    #[test]
    fn cleans_a_synthetic_tree() {
        let dir = TempDir::new("files");
        let root = dir.path();
        let m = root.join("manifests");
        for name in [
            FIREWALL,
            ADAPTERS,
            "tmp-1",
            "script-1.ps1",
            "x.corrupt-2",
            "recovery-result.json",
        ] {
            touch(&m.join(name));
        }
        let backup = m.join("windows-firewall-before-reset-2026.wfw");
        touch(&backup);
        let a = root.join("runtime").join("aaaa");
        touch(&a.join("tun-runtime").join("config.json"));
        touch(
            &a.join("external-proxy-runtime")
                .join("vpnte-external-proxy.exe"),
        );
        touch(&a.join("traffic-forensics").join("latest-session.json"));
        let b = root.join("runtime").join("bbbb");
        touch(&b.join("tun-runtime").join("vpnte-sing-box.exe"));

        // Untrusted manifests stay; the staged engine copies (credentials) still go.
        let untrusted = |_: &Path, _: bool| Err(Untrusted::Owner);
        let record = clean(root, &[FIREWALL], &untrusted);
        assert_eq!(record.outcome, Outcome::Skipped, "{}", record.detail);
        assert!(m.join(FIREWALL).exists() && m.join("tmp-1").exists());
        assert!(!b.exists() && !a.join("tun-runtime").exists());
        assert!(record.changed);

        let trusted = |_: &Path, _: bool| Ok(());
        let record = clean(root, &[FIREWALL], &trusted);
        assert_eq!(record.outcome, Outcome::Done, "{}", record.detail);
        assert!(record.changed);
        assert!(!m.join(FIREWALL).exists());
        assert!(m.join(ADAPTERS).exists());
        assert!(backup.exists());
        assert!(
            record
                .detail
                .contains("windows-firewall-before-reset-2026.wfw")
        );
        for gone in [
            "tmp-1",
            "script-1.ps1",
            "x.corrupt-2",
            "recovery-result.json",
        ] {
            assert!(!m.join(gone).exists(), "{gone}");
        }
        assert!(!a.join("tun-runtime").exists());
        assert!(!a.join("external-proxy-runtime").exists());
        assert!(
            a.join("traffic-forensics")
                .join("latest-session.json")
                .exists()
        );
        assert!(!b.exists());
        std::fs::remove_dir_all(root).unwrap();

        let record = clean(root, &[], &trusted);
        assert_eq!(record.outcome, Outcome::Done);
        assert!(!record.changed);
    }
}
