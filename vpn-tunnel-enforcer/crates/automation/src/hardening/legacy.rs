//! One-time adoption of what the old app's browser hardening and location privacy left applied
//! (spec §2.15, §6.8 "Legacy import"). Its manifests and `.reg` exports are only read: never
//! imported, executed, restored whole, moved or deleted (spec B1/L1). Exactly the values this
//! package owns are parsed out of the exact key section of an export, and a record is adopted
//! only while the value still holds what the old app wrote, so the normal rollback puts the old
//! baseline back.
use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use vpnte_base::Msg;
use vpnte_core::store::{Document, Store};

use super::admissible;
use super::browser::{WEBRTC_POLICY, canonical_key};
use super::location;
use super::system::System;
use crate::tweaks::env_dir;
use crate::tweaks::journal::{Feature, Journal, Record, RegHive, Target, Val};

/// Manifests and exports are a few KB (the HKCU location export with its per-app subkeys about
/// 40 KB); anything far larger is not one of them.
const MAX_FILE: u64 = 1 << 20;

/// `hardening.json` in the data dir: the old artefacts were looked at once. Its own marker,
/// because the tweak journal's flag belongs to the Soft-mode import.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardeningDoc {
    #[serde(default)]
    pub legacy_imported: bool,
}

impl Document for HardeningDoc {
    const FILE: &'static str = "hardening.json";
    const VERSION: u32 = 1;
}

/// Where the old app kept its manifests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacySources {
    /// `<old data dir>\browser-hardening\latest-browser-hardening.json`.
    pub browser_manifest: Option<PathBuf>,
    /// `%ProgramData%\VPN-Tunnel-Enforcer\privacy-backups\latest-location-backup.json`. The older
    /// copy under the old data dir is stale and ignored (the old code never read it either).
    pub location_manifest: Option<PathBuf>,
}

impl LegacySources {
    /// The real places; `legacy_dir` is the old Electron data dir (`DataDirs::legacy_electron`).
    pub fn new(legacy_dir: &Path) -> Self {
        let program_data =
            env_dir("ProgramData").unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        Self {
            browser_manifest: Some(
                legacy_dir.join(r"browser-hardening\latest-browser-hardening.json"),
            ),
            location_manifest: Some(
                program_data
                    .join(r"VPN-Tunnel-Enforcer\privacy-backups\latest-location-backup.json"),
            ),
        }
    }
}

/// Outcome of the import.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyReport {
    /// Journal records taken over.
    pub adopted: usize,
    /// For the user: old changes this import cannot put back by itself.
    pub notices: Vec<Msg>,
}

/// One value line of an export, as far as we care.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RegLine {
    Sz(String),
    Dword(u32),
    Other,
}

/// Text of a `.reg` export (`reg export` writes UTF-16LE with a BOM; UTF-8 is accepted too) with
/// the version 5 header, else `None`.
fn reg_text(bytes: &[u8]) -> Option<String> {
    let text = match bytes.strip_prefix(&[0xFF, 0xFE]) {
        Some(utf16) => {
            let units: Vec<u16> = utf16
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes(*pair))
                .collect();
            String::from_utf16_lossy(&units)
        }
        None => String::from_utf8_lossy(bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes))
            .into_owned(),
    };
    text.trim_start()
        .starts_with("Windows Registry Editor Version 5.00")
        .then_some(text)
}

/// The values of exactly the section `[section]` (ASCII case-insensitive), names lower-cased;
/// `None` when the section is missing. A subkey (`…\location\<app>`, with its own `"Value"`) is
/// another section, which is why the old exports are this large (LP:242-250).
fn section_values(text: &str, section: &str) -> Option<HashMap<String, RegLine>> {
    let mut inside = false;
    let mut found = false;
    let mut values = HashMap::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            inside = name.eq_ignore_ascii_case(section);
            found |= inside;
        } else if inside && let Some((name, value)) = value_line(trimmed) {
            values.entry(name.to_ascii_lowercase()).or_insert(value);
        }
    }
    found.then_some(values)
}

/// `"name"="text"` / `"name"=dword:0000001` / `"name"=<other type>`; anything else is `None`.
fn value_line(line: &str) -> Option<(String, RegLine)> {
    let (name, rest) = quoted(line.strip_prefix('"')?)?;
    let rest = rest.strip_prefix('=')?;
    let value = if let Some(body) = rest.strip_prefix('"') {
        match quoted(body) {
            Some((text, tail)) if tail.trim().is_empty() => RegLine::Sz(text),
            _ => RegLine::Other,
        }
    } else if let Some(hex) = rest.strip_prefix("dword:") {
        u32::from_str_radix(hex.trim(), 16).map_or(RegLine::Other, RegLine::Dword)
    } else {
        RegLine::Other
    };
    Some((name, value))
}

/// A quoted `reg export` string after its opening quote (`\\` and `\"` are escapes): the text and
/// what follows the closing quote.
fn quoted(s: &str) -> Option<(String, &str)> {
    let mut out = String::new();
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => out.push(chars.next()?.1),
            '"' => return Some((out, &s[i + 1..])),
            c => out.push(c),
        }
    }
    None
}

/// A small plain file (no symlink), else `None`.
fn small_file(path: &Path) -> Option<Vec<u8>> {
    let meta = fs::symlink_metadata(path).ok()?;
    (meta.is_file() && meta.len() <= MAX_FILE)
        .then(|| fs::read(path).ok())
        .flatten()
}

fn read_manifest(path: &Path) -> Option<Value> {
    let bytes = small_file(path)?;
    let json = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(&bytes);
    match serde_json::from_slice(json) {
        Ok(doc) => Some(doc),
        Err(e) => {
            tracing::warn!(error = %e, "old hardening manifest unreadable; ignored");
            None
        }
    }
}

/// The export a manifest names, read only when it lies inside the manifest's own directory:
/// absolute, no `..`, a `.reg` plain file.
fn export_text(path: &str, manifest: &Path) -> Option<String> {
    let path = Path::new(path);
    let lower = |p: &Path| -> Vec<String> {
        p.components()
            .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
            .collect()
    };
    let (file, dir) = (lower(path), lower(manifest.parent()?));
    let inside = path.is_absolute()
        && !path.components().any(|c| c == Component::ParentDir)
        && path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("reg"))
        && file.len() > dir.len()
        && file.starts_with(&dir);
    if !inside {
        tracing::warn!("old registry export outside its backup folder; ignored");
        return None;
    }
    reg_text(&small_file(path)?)
}

fn root_name(hive: RegHive) -> &'static str {
    match hive {
        RegHive::Hklm => "HKEY_LOCAL_MACHINE",
        RegHive::Hkcu => "HKEY_CURRENT_USER",
    }
}

/// `HKLM\…` / `HKCU\…` (or the long root names) of an old manifest.
fn split_hive(full: &str) -> Option<(RegHive, &str)> {
    let (root, key) = full.split_once('\\')?;
    let hive = [RegHive::Hklm, RegHive::Hkcu].into_iter().find(|h| {
        root.eq_ignore_ascii_case(root_name(*h))
            || root.eq_ignore_ascii_case(match h {
                RegHive::Hklm => "HKLM",
                RegHive::Hkcu => "HKCU",
            })
    })?;
    Some((hive, key))
}

/// The baseline of `name` from an export's section values: the line's value when its type is
/// the expected one, `Absent` without a line, `None` (unknown) for anything else.
fn exported(values: &HashMap<String, RegLine>, name: &str, dword: bool) -> Option<Val> {
    match (values.get(&name.to_ascii_lowercase()), dword) {
        (None, _) => Some(Val::Absent),
        (Some(RegLine::Sz(s)), false) => Some(Val::Sz(s.clone())),
        (Some(RegLine::Dword(v)), true) => Some(Val::Dword(*v)),
        _ => None,
    }
}

/// A record for `target` if it still holds `ours` and its baseline is known and admissible;
/// `Err(())` when it holds ours but cannot be adopted (a leftover for the user to check).
fn adopt(
    sys: &dyn System,
    feature: Feature,
    target: Target,
    ours: Val,
    baseline: Option<Val>,
    created: bool,
) -> Result<Option<Record>, ()> {
    if sys.read(&target).ok().as_ref() != Some(&ours) {
        return Ok(None); // put back or changed since: not ours any more
    }
    match baseline {
        Some(baseline) if admissible(&target, &baseline) => Ok(Some(Record {
            feature,
            target,
            baseline,
            applied: ours,
            created,
        })),
        _ => Err(()),
    }
}

/// Records from the browser manifest (`registryBackups`); its `fileBackups` (Chromium
/// `Preferences`, Firefox `user.js`) are not edited any more and only reported.
fn browser_records(manifest: &Path, sys: &dyn System, out: &mut Vec<Record>) -> Vec<Msg> {
    let Some(doc) = read_manifest(manifest) else {
        return Vec::new();
    };
    let ours = Val::Sz(WEBRTC_POLICY.1.to_owned());
    let mut leftover = false;
    let backups = doc.get("registryBackups").and_then(Value::as_array);
    for backup in backups.into_iter().flatten() {
        let key = backup.get("key").and_then(Value::as_str);
        let Some((hive, key)) = key
            .and_then(split_hive)
            .and_then(|(hive, key)| Some((hive, canonical_key(key)?)))
        else {
            continue;
        };
        // The old app never wrote a key whose prior state it could not save (BH:205-216, 277-281).
        if backup.get("safeToModify").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        let export = backup.get("backupPath").and_then(Value::as_str);
        let baseline = match export {
            // Export failed because nothing was there: confirmed absent.
            None => Some(Val::Absent),
            Some(path) => export_text(path, manifest)
                .and_then(|text| section_values(&text, &format!(r"{}\{key}", root_name(hive))))
                .and_then(|values| exported(&values, WEBRTC_POLICY.0, false)),
        };
        let target = Target::Reg {
            hive,
            key: key.to_owned(),
            name: WEBRTC_POLICY.0.to_owned(),
        };
        let created = export.is_none();
        match adopt(
            sys,
            Feature::BrowserWebRtc,
            target,
            ours.clone(),
            baseline,
            created,
        ) {
            Ok(record) => out.extend(record),
            Err(()) => leftover = true,
        }
    }
    let mut notices = Vec::new();
    if leftover {
        notices.push(Msg::new("automation.hardening.legacy.browserLeftover"));
    }
    let files = doc.get("fileBackups").and_then(Value::as_array);
    if files.is_some_and(|f| !f.is_empty()) {
        notices.push(Msg::new("automation.hardening.legacy.browserFiles"));
    }
    notices
}

/// Records from the location manifest: the consent, and the two machine policies only in an
/// elevated process (unelevated they could never be rolled back: one notice instead, while one
/// the old app set is still set). Who set a machine policy is read from the manifest as the
/// elevated branch reads it: a value that was already there before the old app (an
/// administrator's policy) is nobody's leftover.
fn location_records(manifest: &Path, sys: &dyn System, out: &mut Vec<Record>) -> Vec<Msg> {
    let Some(doc) = read_manifest(manifest) else {
        return Vec::new();
    };
    let mut leftover = false;
    let mut machine_policy = false;
    for (feature, target, ours) in location::old_plan() {
        let Target::Reg { hive, key, name } = &target else {
            continue;
        };
        let (backup, existed) = match hive {
            RegHive::Hkcu => ("hkcuBackup", "hkcuKeyExisted"),
            RegHive::Hklm => ("hklmBackup", "hklmKeyExisted"),
        };
        let existed = doc.get(existed).and_then(Value::as_bool);
        let baseline = if existed == Some(false) {
            Some(Val::Absent)
        } else {
            doc.get(backup)
                .and_then(Value::as_str)
                .and_then(|path| export_text(path, manifest))
                .and_then(|text| section_values(&text, &format!(r"{}\{key}", root_name(*hive))))
                .and_then(|values| exported(&values, name, matches!(ours, Val::Dword(_))))
        };
        if *hive == RegHive::Hklm && !sys.elevated() {
            if sys.read(&target).is_ok_and(|v| v == ours) {
                match &baseline {
                    Some(before) if *before == ours => {}
                    Some(_) => machine_policy = true,
                    // Who set it cannot be told: the hedged notice, as elevated.
                    None => leftover = true,
                }
            }
            continue;
        }
        let created = existed == Some(false);
        match adopt(sys, feature, target.clone(), ours, baseline, created) {
            Ok(record) => out.extend(record),
            Err(()) => leftover = true,
        }
    }
    let mut notices = Vec::new();
    if leftover {
        notices.push(Msg::new("automation.hardening.legacy.locationLeftover"));
    }
    if machine_policy {
        notices.push(Msg::new("automation.hardening.legacy.locationPolicy"));
    }
    notices
}

/// Adopts the old values still in place as journal records; nothing is written to the system.
/// Runs once per data dir (marker `hardening.json` under `root`). Call it on a blocking thread
/// at start, after `tweaks::legacy::import` (adopting records also sets the tweak journal's own
/// import flag) and before the startup recovery.
pub fn import(
    journal: &Journal,
    root: &Path,
    sys: &dyn System,
    src: &LegacySources,
) -> LegacyReport {
    let marker = Store::<HardeningDoc>::open(root);
    if marker.read(|d| d.legacy_imported) {
        return LegacyReport::default();
    }
    let mut records = Vec::new();
    let mut notices = Vec::new();
    if let Some(path) = &src.browser_manifest {
        notices.extend(browser_records(path, sys, &mut records));
    }
    if let Some(path) = &src.location_manifest {
        notices.extend(location_records(path, sys, &mut records));
    }
    let mut adopted = 0;
    if !records.is_empty() {
        match journal.adopt_legacy(records) {
            Ok(n) => adopted = n,
            Err(e) => {
                // Not marked: the next start tries again.
                tracing::warn!(error = %e, "old hardening values not adopted");
                return LegacyReport { adopted, notices };
            }
        }
    }
    if let Err(e) = marker.update(|d| d.legacy_imported = true) {
        tracing::warn!(error = %e, "hardening import marker not saved");
    }
    tracing::info!(adopted, "old hardening values looked at");
    LegacyReport { adopted, notices }
}

#[cfg(test)]
mod tests;
