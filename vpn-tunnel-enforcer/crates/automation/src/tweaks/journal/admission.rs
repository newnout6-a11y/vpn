//! Load-time admission: which records may be acted on (spec B1/L1).
use std::path::{Component, Path, Prefix};

use super::model::{BlockKind, Feature, Record, RegHive, Target, Val};
use crate::tweaks::{block, sysproxy};

/// Load-time admission of [`Target::Reg`] records: `(hive, key, name, value) -> allowed`. The
/// package that writes registry values supplies it; records it does not admit are dropped.
pub type RegAdmit = fn(RegHive, &str, &str, &Val) -> bool;

/// Admits no registry value (for an app or a test without registry-based tweaks).
pub fn no_registry(_: RegHive, _: &str, _: &str, _: &Val) -> bool {
    false
}

/// Whether a record may be acted on (see the module comment).
pub(crate) fn admitted(r: &Record, admit_reg: RegAdmit) -> bool {
    let vals = [&r.baseline, &r.applied];
    let all = |ok: &dyn Fn(&Val) -> bool| vals.iter().all(|v| ok(v));
    let feature_ok = match &r.target {
        Target::Env { .. } => r.feature == Feature::SoftEnv,
        Target::Git { .. } => r.feature == Feature::DevGit,
        Target::Block { kind, .. } => {
            r.feature
                == match kind {
                    BlockKind::Gradle => Feature::DevGradle,
                    BlockKind::VmOptions => Feature::DevStudio,
                }
        }
        Target::StudioOpt { .. } => r.feature == Feature::DevStudio,
        Target::Lines { .. } => r.feature == Feature::DevGradle,
        Target::Reg { .. } => true,
        Target::SystemProxy => r.feature == Feature::SoftProxy,
    };
    feature_ok
        && match &r.target {
            Target::Env { .. } => {
                all(&|v| matches!(v, Val::Absent | Val::Sz(_) | Val::ExpandSz(_)))
            }
            Target::Git { .. } => all(&|v| match v {
                Val::Absent => true,
                Val::Text(t) => t.len() <= 4096 && !t.chars().any(char::is_control),
                _ => false,
            }),
            Target::Block { kind, path } => {
                safe_path(path, &[kind.file_name()])
                    && r.baseline == Val::Absent
                    && match &r.applied {
                        Val::Absent => true,
                        Val::Text(t) => block::is_block(*kind, t),
                        _ => false,
                    }
            }
            Target::StudioOpt { path, .. } => {
                safe_path(path, &["proxy.settings.xml", "other.xml"])
                    && all(&|v| match v {
                        Val::Absent => true,
                        Val::Text(t) => t.len() <= 255 && !t.chars().any(char::is_control),
                        _ => false,
                    })
            }
            Target::Lines { path, lines } => {
                safe_path(path, &[BlockKind::Gradle.file_name()])
                    && r.baseline == Val::Absent
                    && !lines.is_empty()
                    && lines.iter().all(|l| block::is_legacy_gradle_line(l))
                    && matches!(r.applied, Val::Absent | Val::Text(_))
            }
            Target::Reg { hive, key, name } => all(&|v| admit_reg(*hive, key, name, v)),
            // Settings only ever go back to WinINet (no file, no other user): well-formed is enough.
            Target::SystemProxy => all(&|v| sysproxy::decode(v).is_some()),
        }
}

/// A local absolute path (`X:\…`, no `..`) whose file name is one of `names` (ASCII case-insensitive).
fn safe_path(path: &Path, names: &[&str]) -> bool {
    let mut parts = path.components();
    let disk = matches!(
        parts.next(),
        Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_))
    );
    let name_ok = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| names.iter().any(|want| n.eq_ignore_ascii_case(want)));
    disk && name_ok && path.is_absolute() && !path.components().any(|c| c == Component::ParentDir)
}
