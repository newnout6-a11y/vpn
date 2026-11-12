//! One-time adoption of what the old Electron app may have left applied (spec §2.15, §6.8
//! "Legacy import"): its receipts become journal records, so the normal Soft rollback (startup
//! recovery outside Soft mode) cleans up exactly the old app's values. Old files are only read:
//! never deleted, restored whole, imported or executed. Whole-file backups serve only to tell
//! the user's lines from ours.
use std::path::{Path, PathBuf};

use serde_json::Value;
use vpnte_base::Msg;

use super::block;
use super::env_dir;
use super::journal::{
    Backend, BlockKind, EnvVar, Feature, GitKey, Journal, Record, StudioOption, Target, Val,
};
use super::studio;

/// Receipts are a few hundred bytes; anything far larger is not one.
const MAX_FILE: u64 = 1 << 20;
/// What the old app wrote into `NO_PROXY`.
const OLD_NO_PROXY: &str = "localhost,127.0.0.1,::1";

/// Where the old app kept its receipts and touched files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacySources {
    /// `%USERPROFILE%\.vpnte` (env and Git receipts).
    pub receipts_dir: Option<PathBuf>,
    /// `%USERPROFILE%\.gradle\gradle.properties` (the old app ignored `GRADLE_USER_HOME`).
    pub gradle_props: Option<PathBuf>,
    /// `%APPDATA%\Google` (every `AndroidStudio*` version the old app patched).
    pub studio_root: Option<PathBuf>,
}

impl LegacySources {
    /// The old app's locations for the account this process runs as.
    pub fn current_user() -> Self {
        let profile = env_dir("USERPROFILE");
        let appdata =
            env_dir("APPDATA").or_else(|| Some(profile.as_ref()?.join(r"AppData\Roaming")));
        Self {
            receipts_dir: profile.as_ref().map(|p| p.join(".vpnte")),
            gradle_props: profile.map(|p| p.join(".gradle").join("gradle.properties")),
            studio_root: appdata.map(|a| a.join("Google")),
        }
    }
}

/// Outcome of the one-time import.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyReport {
    /// Old obligations now in the journal.
    pub adopted: usize,
    /// For the user: an old "pending" marker without its receipt, listing the variables that
    /// still look like the old app's values (nothing is known about their originals).
    pub notice: Option<Msg>,
}

/// Runs once per data dir (a marker in the journal); later calls return an empty report.
/// `backend` reads current values (a `SoftSystem`); nothing is written to the system.
pub fn import(journal: &Journal, backend: &dyn Backend, src: &LegacySources) -> LegacyReport {
    if journal.legacy_imported() {
        return LegacyReport::default();
    }
    let mut records = Vec::new();
    let mut notice = None;
    if let Some(dir) = &src.receipts_dir {
        let receipt = dir.join("env-proxy-backup.json");
        match read_json(&receipt) {
            Some(json) => records.extend(env_records(&json, backend)),
            None if dir.join("env-proxy-backup.json.pending").is_file() => {
                notice = pending_notice(backend);
            }
            None => {}
        }
        if let Some(json) = read_json(&dir.join("git-proxy-backup.json")) {
            records.extend(git_records(&json, backend));
        }
    }
    if let Some(props) = &src.gradle_props {
        records.extend(gradle_record(props));
    }
    if let Some(root) = &src.studio_root {
        records.extend(studio_records(root, backend));
    }
    let adopted = match journal.adopt_legacy(records) {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "old app leftovers not adopted");
            0
        }
    };
    if adopted > 0 {
        tracing::info!(adopted, "old app leftovers adopted into the tweak journal");
    }
    LegacyReport { adopted, notice }
}

/// A small UTF-8 JSON file (BOM tolerated); anything else is ignored.
fn read_json(path: &Path) -> Option<Value> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes);
    serde_json::from_slice(bytes).ok()
}

/// A text file of at most [`MAX_FILE`] bytes, `None` when absent or unreadable.
fn read_text(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

/// Receipt value → baseline: `null` = was not set; `%` suggests an expandable original (the
/// receipt kept only the text).
fn receipt_baseline(json: &Value, field: &str) -> Option<Val> {
    match json.get(field)? {
        Value::Null => Some(Val::Absent),
        Value::String(s) if s.contains('%') => Some(Val::ExpandSz(s.clone())),
        Value::String(s) => Some(Val::Sz(s.clone())),
        _ => None,
    }
}

/// What the old app wrote: a `socks5h://` / `http://` URL, or its `NO_PROXY` list.
fn looks_old(var: EnvVar, text: &str) -> bool {
    match var {
        EnvVar::NoProxy => text == OLD_NO_PROXY,
        _ => text.starts_with("socks5h://") || text.starts_with("http://"),
    }
}

fn env_field(var: EnvVar) -> &'static str {
    match var {
        EnvVar::HttpProxy => "httpProxy",
        EnvVar::HttpsProxy => "httpsProxy",
        EnvVar::AllProxy => "allProxy",
        EnvVar::NoProxy => "noProxy",
    }
}

/// Env receipt → `SoftEnv` records, only for variables that still hold an old-app value.
fn env_records(json: &Value, backend: &dyn Backend) -> Vec<Record> {
    EnvVar::ALL
        .into_iter()
        .filter_map(|var| {
            let baseline = receipt_baseline(json, env_field(var))?;
            let target = Target::Env { var };
            let applied = backend.read(&target).ok()?;
            let (Val::Sz(text) | Val::ExpandSz(text)) = &applied else {
                return None;
            };
            if !looks_old(var, text) {
                return None;
            }
            Some(record(Feature::SoftEnv, target, baseline, applied, false))
        })
        .collect()
}

/// The old "unknown obligation" state (a pending marker, no receipt): nothing to restore, but
/// the user learns which variables still look like the old app's.
fn pending_notice(backend: &dyn Backend) -> Option<Msg> {
    let names: Vec<&str> = EnvVar::ALL
        .into_iter()
        .filter(|var| match backend.read(&Target::Env { var: *var }) {
            Ok(Val::Sz(t) | Val::ExpandSz(t)) => looks_old(*var, &t),
            _ => false,
        })
        .map(EnvVar::name)
        .collect();
    (!names.is_empty())
        .then(|| Msg::new("automation.tweaks.legacyLeftovers").arg("names", names.join(", ")))
}

/// Git receipt → `DevGit` records with the same rule (a Git that cannot be run adopts nothing).
fn git_records(json: &Value, backend: &dyn Backend) -> Vec<Record> {
    GitKey::ALL
        .into_iter()
        .filter_map(|key| {
            let field = match key {
                GitKey::HttpProxy => "httpProxy",
                GitKey::HttpsProxy => "httpsProxy",
            };
            let baseline = match json.get(field)? {
                Value::Null => Val::Absent,
                Value::String(s) => Val::Text(s.clone()),
                _ => return None,
            };
            let target = Target::Git { key };
            let applied = backend.read(&target).ok()?;
            let Val::Text(text) = &applied else {
                return None;
            };
            if !looks_old(EnvVar::HttpProxy, text) {
                return None;
            }
            Some(record(Feature::DevGit, target, baseline, applied, false))
        })
        .collect()
}

/// The old Gradle lines as one `Lines` record (the `.vpn-backup` is never restored, D-06).
fn gradle_record(props: &Path) -> Option<Record> {
    let content = read_text(props)?;
    let backup = read_text(&props.with_file_name("gradle.properties.vpn-backup"));
    let lines = block::legacy_gradle_lines(&content, backup.as_deref());
    if lines.is_empty() {
        return None;
    }
    let applied = Val::Text(lines.join("\n"));
    let target = Target::Lines {
        path: props.to_path_buf(),
        lines,
    };
    Some(record(
        Feature::DevGradle,
        target,
        Val::Absent,
        applied,
        false,
    ))
}

/// Every `AndroidStudio*` version: the old vmoptions block, and the `other.xml` options when the
/// old app left its provenance (`.vpn-created`, or `.vpn-backup` with the originals).
fn studio_records(root: &Path, backend: &dyn Backend) -> Vec<Record> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut records = Vec::new();
    for dir in entries.filter_map(Result::ok) {
        let named = dir
            .file_name()
            .to_string_lossy()
            .starts_with("AndroidStudio");
        if !named || !dir.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let dir = dir.path();
        let vm = Target::Block {
            kind: BlockKind::VmOptions,
            path: studio::vmoptions_file(&dir),
        };
        if let Ok(applied @ Val::Text(_)) = backend.read(&vm) {
            records.push(record(Feature::DevStudio, vm, Val::Absent, applied, false));
        }
        records.extend(other_xml_records(
            &dir.join("options").join("other.xml"),
            backend,
        ));
    }
    records
}

fn other_xml_records(path: &Path, backend: &dyn Backend) -> Vec<Record> {
    let sibling = |suffix: &str| path.with_file_name(format!("other.xml{suffix}"));
    let created = sibling(".vpn-created").is_file();
    let backup = sibling(".vpn-backup");
    if !created && !backup.is_file() {
        return Vec::new(); // no provenance: somebody else's proxy settings
    }
    StudioOption::ALL
        .into_iter()
        .filter_map(|option| {
            let target = Target::StudioOpt {
                path: path.to_path_buf(),
                option,
            };
            let applied @ Val::Text(_) = backend.read(&target).ok()? else {
                return None;
            };
            let baseline = if created {
                Val::Absent
            } else {
                studio::read_option(&backup, option).ok()?
            };
            Some(record(
                Feature::DevStudio,
                target,
                baseline,
                applied,
                created,
            ))
        })
        .collect()
}

fn record(feature: Feature, target: Target, baseline: Val, applied: Val, created: bool) -> Record {
    Record {
        feature,
        target,
        baseline,
        applied,
        created,
    }
}

#[cfg(test)]
mod tests;
