//! Split tunnelling: executable names and paths, their sing-box regexes, the stored entry and
//! its resolution into `process_path_regex` lists at connect time.
//!
//! Names and paths are both emitted as `process_path_regex`, never `process_name`: sing-box
//! 1.14 matches `process_name` case-sensitively against the on-disk spelling, so `Telegram.exe`
//! added as `telegram.exe` silently never matched in the old app.
use std::fmt;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vpnte_base::{AppError, Msg};

/// Longest name / path the UI accepts.
pub const MAX_INPUT_LEN: usize = 4096;

/// Third-party VPN clients and cores (local-proxy mode only): their own upstream traffic must
/// leave directly or it loops back into our tunnel. Verbatim from the old app; matching is
/// case-insensitive now, so mixed-case twins (`FlClash.exe`) are covered by one entry.
pub const THIRD_PARTY_CORES: &[&str] = &[
    "Happ.exe",
    "happd.exe",
    "xray.exe",
    "v2ray.exe",
    "v2rayN.exe",
    "sing-box.exe",
    "singbox.exe",
    "sing-tun.exe",
    "mihomo.exe",
    "clash.exe",
    "clash-meta.exe",
    "clash-verge.exe",
    "clash-verge-service.exe",
    "flclash.exe",
    "FlClash.exe",
    "mihomo-party.exe",
    "verge-mihomo.exe",
    "hiddify.exe",
    "Hiddify.exe",
    "HiddifyN.exe",
    "nekoray.exe",
    "nekobox.exe",
    "shadowsocks.exe",
    "ss-local.exe",
    "shadowsocks-rust.exe",
    "trojan.exe",
    "outline.exe",
    "Outline.exe",
    "wireguard.exe",
    "openvpn.exe",
    "karing.exe",
    "streisand.exe",
    "surfboard.exe",
];

/// Why a split-tunnel input was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SplitError {
    #[error("invalid process name")]
    BadName,
    #[error("invalid absolute executable path")]
    BadPath,
}

impl SplitError {
    /// User-facing explanation.
    pub fn msg(self) -> Msg {
        Msg::new(match self {
            SplitError::BadName => "engine.routing.split.badName",
            SplitError::BadPath => "engine.routing.split.badPath",
        })
    }
}

impl From<SplitError> for AppError {
    fn from(err: SplitError) -> Self {
        AppError::validation(err.msg()).with_source(err)
    }
}

/// An executable file name (`curl.exe`) in the user's spelling; compared case-insensitively.
#[derive(Debug, Clone, Eq)]
pub struct ProcessName(String);

impl ProcessName {
    /// The leaf of the input with `.exe` appended unless it already ends in `.exe` (so
    /// `python3.11` → `python3.11.exe`, the old end-to-end result); quotes are stripped,
    /// characters Windows forbids in file names and whitespace are refused.
    pub fn parse(raw: &str) -> Result<Self, SplitError> {
        let s = unquote(raw);
        let leaf = s.rsplit(['\\', '/']).next().unwrap_or_default();
        let forbidden = |c: char| "<>:\"/\\|?*".contains(c) || c.is_whitespace() || c.is_control();
        if leaf.is_empty() || s.len() > MAX_INPUT_LEN || leaf.chars().any(forbidden) {
            return Err(SplitError::BadName);
        }
        if leaf.to_ascii_lowercase().ends_with(".exe") {
            Ok(Self(leaf.to_owned()))
        } else {
            Ok(Self(format!("{leaf}.exe")))
        }
    }

    /// The name as the user spelled it (with `.exe`).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Case-insensitive, anchored at a path separator: `(?i)(?:^|\\)curl\.exe$`.
    pub fn regex(&self) -> String {
        format!(r"(?i)(?:^|\\){}$", escape(&self.0))
    }
}

impl PartialEq for ProcessName {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_lowercase() == other.0.to_lowercase()
    }
}

impl fmt::Display for ProcessName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An absolute executable path `X:\…\name.ext` or `\\server\share\…\name.ext`, normalised.
#[derive(Debug, Clone, Eq)]
pub struct AppPath(String);

impl AppPath {
    /// `normalizeProcessPath` (`splitTunnelPath.ts:8-21`): quotes stripped, `/` → `\`, repeated
    /// separators collapsed; relative paths, `.` / `..` parts, wildcard / pipe / quote / angle
    /// characters and names without an extension are refused.
    pub fn parse(raw: &str) -> Result<Self, SplitError> {
        let s = unquote(raw).replace('/', "\\");
        if s.is_empty() || s.len() > MAX_INPUT_LEN {
            return Err(SplitError::BadPath);
        }
        let unc = s.starts_with(r"\\");
        let body = if unc { &s[2..] } else { s.as_str() };
        let b = s.as_bytes();
        if !unc && !(b.len() > 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\') {
            return Err(SplitError::BadPath);
        }
        let checked = if unc { body } else { &body[2..] };
        if checked.contains(['<', '>', '"', '|', '?', '*']) {
            return Err(SplitError::BadPath);
        }
        let parts: Vec<&str> = body
            .split('\\')
            .enumerate()
            .filter(|(i, p)| *i == 0 || !p.is_empty())
            .map(|(_, p)| p)
            .collect();
        if parts.iter().any(|p| *p == "." || *p == "..") {
            return Err(SplitError::BadPath);
        }
        let joined = format!("{}{}", if unc { r"\\" } else { "" }, parts.join("\\"));
        if !has_extension(&joined) {
            return Err(SplitError::BadPath);
        }
        Ok(Self(joined))
    }

    /// The normalised path.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path for file-system calls.
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    /// Case-insensitive exact match of the whole path: `(?i)^C:\\App\\app\.exe$`.
    pub fn regex(&self) -> String {
        format!("(?i)^{}$", escape(&self.0))
    }
}

impl PartialEq for AppPath {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_lowercase() == other.0.to_lowercase()
    }
}

impl fmt::Display for AppPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn unquote(raw: &str) -> &str {
    raw.trim().trim_matches(['"', '\'']).trim()
}

/// Ends with `.` + ASCII letters / digits (`/\.[a-z0-9]+$/i`).
fn has_extension(s: &str) -> bool {
    s.rsplit_once('.')
        .is_some_and(|(_, ext)| !ext.is_empty() && ext.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Escapes the metacharacters the old generator escaped (`.*+?^${}()|[]\`) for Go RE2.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if r".*+?^${}()|[]\".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// What a split-tunnel entry matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitTarget {
    /// One executable by its exact absolute path (a copy elsewhere does not match).
    App(AppPath),
    /// Every executable with this file name (CLI tools without a fixed path).
    Command(ProcessName),
}

impl SplitTarget {
    /// Classifies user input: an absolute path is an app entry (a pasted path must never
    /// silently widen into a name rule), anything else a command name.
    pub fn parse(raw: &str) -> Result<Self, SplitError> {
        let s = unquote(raw).replace('/', "\\");
        let looks_absolute = s.starts_with(r"\\") || s.as_bytes().get(1) == Some(&b':');
        if looks_absolute {
            AppPath::parse(&s).map(SplitTarget::App)
        } else {
            ProcessName::parse(raw).map(SplitTarget::Command)
        }
    }

    fn regex(&self) -> String {
        match self {
            SplitTarget::App(p) => p.regex(),
            SplitTarget::Command(n) => n.regex(),
        }
    }
}

/// Where an entry's traffic goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppRule {
    /// Forced into the tunnel, before domain rules and Smart RU.
    Vpn,
    /// Leaves directly with the real address.
    Direct,
    /// Listed but not routed (discovered apps start here).
    #[default]
    None,
}

/// One stored split-tunnel entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawSplitApp", into = "RawSplitApp")]
pub struct SplitApp {
    pub id: Uuid,
    /// Display name (original case).
    pub name: String,
    pub target: SplitTarget,
    pub rule: AppRule,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum TargetKind {
    App,
    Process,
}

/// On disk: `{id, name, kind: "app"|"process", target, rule}`.
#[derive(Serialize, Deserialize)]
struct RawSplitApp {
    id: Uuid,
    name: String,
    kind: TargetKind,
    target: String,
    rule: AppRule,
}

impl TryFrom<RawSplitApp> for SplitApp {
    type Error = SplitError;
    fn try_from(r: RawSplitApp) -> Result<Self, SplitError> {
        let target = match r.kind {
            TargetKind::App => SplitTarget::App(AppPath::parse(&r.target)?),
            TargetKind::Process => SplitTarget::Command(ProcessName::parse(&r.target)?),
        };
        Ok(Self {
            id: r.id,
            name: r.name,
            target,
            rule: r.rule,
        })
    }
}

impl From<SplitApp> for RawSplitApp {
    fn from(a: SplitApp) -> Self {
        let (kind, target) = match a.target {
            SplitTarget::App(p) => (TargetKind::App, p.0),
            SplitTarget::Command(n) => (TargetKind::Process, n.0),
        };
        Self {
            id: a.id,
            name: a.name,
            kind,
            target,
            rule: a.rule,
        }
    }
}

/// What the file system says about an app path at connect time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// A regular file; `canonical` is its long spelling when it differs (8.3 names, links).
    File {
        canonical: Option<AppPath>,
    },
    Missing,
    NotAFile,
}

/// Probes the real file system: existence, then `GetFinalPathNameByHandleW` (through
/// `std::fs::canonicalize`) for the spelling the OS reports in process image paths.
pub fn probe_fs(path: &AppPath) -> Probe {
    match std::fs::metadata(path.as_path()) {
        Ok(m) if m.is_file() => Probe::File {
            canonical: std::fs::canonicalize(path.as_path())
                .ok()
                .and_then(|c| long_spelling(path, &c.to_string_lossy())),
        },
        Ok(_) => Probe::NotAFile,
        // A file whose metadata we may not read (ACL) still exists: keep the stored spelling.
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => Probe::File { canonical: None },
        // Not found, invalid name, drive not ready…: no rule, and the user is told.
        Err(_) => Probe::Missing,
    }
}

/// The canonical form without the `\\?\` / `\\?\UNC\` prefix, when it differs from `path`
/// other than by case.
pub fn long_spelling(path: &AppPath, resolved: &str) -> Option<AppPath> {
    let plain = match resolved.strip_prefix(r"\\?\UNC\") {
        Some(rest) => format!(r"\\{rest}"),
        None => resolved
            .strip_prefix(r"\\?\")
            .unwrap_or(resolved)
            .to_owned(),
    };
    AppPath::parse(&plain).ok().filter(|long| long != path)
}

/// Why an app entry produced no rule (its traffic stays in the tunnel).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InactiveReason {
    FileMissing,
    NotAFile,
}

/// An entry whose path is unusable right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InactiveApp {
    pub name: String,
    pub path: String,
    pub reason: InactiveReason,
}

/// Split-tunnel entries resolved for one engine start.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedSplit {
    /// `process_path_regex` values leaving directly: app paths first, then command names.
    pub direct: Vec<String>,
    /// Values forced into the tunnel, same order.
    pub vpn: Vec<String>,
    pub inactive: Vec<InactiveApp>,
}

/// Resolves the stored entries: `none` entries are skipped, an app path gets one regex per
/// spelling (stored + canonical) and only while it is a file; duplicates are dropped.
pub fn resolve_split(apps: &[SplitApp], probe: impl Fn(&AppPath) -> Probe) -> ResolvedSplit {
    let mut out = ResolvedSplit::default();
    for rule in [AppRule::Direct, AppRule::Vpn] {
        let mut regexes: Vec<String> = Vec::new();
        let mut push = |r: String| {
            if !regexes.iter().any(|x| x.eq_ignore_ascii_case(&r)) {
                regexes.push(r);
            }
        };
        for app in apps.iter().filter(|a| a.rule == rule) {
            let SplitTarget::App(path) = &app.target else {
                continue;
            };
            let reason = match probe(path) {
                Probe::File { canonical } => {
                    push(path.regex());
                    if let Some(long) = canonical {
                        push(long.regex());
                    }
                    continue;
                }
                Probe::Missing => InactiveReason::FileMissing,
                Probe::NotAFile => InactiveReason::NotAFile,
            };
            out.inactive.push(InactiveApp {
                name: app.name.clone(),
                path: path.to_string(),
                reason,
            });
        }
        for app in apps.iter().filter(|a| a.rule == rule) {
            if let SplitTarget::Command(_) = &app.target {
                push(app.target.regex());
            }
        }
        match rule {
            AppRule::Direct => out.direct = regexes,
            _ => out.vpn = regexes,
        }
    }
    out
}

/// One regex per third-party core name, deduplicated case-insensitively.
pub fn third_party_core_regexes() -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for name in THIRD_PARTY_CORES {
        if let Ok(n) = ProcessName::parse(name)
            && !seen.contains(&n.0.to_lowercase())
        {
            seen.push(n.0.to_lowercase());
            out.push(n.regex());
        }
    }
    out
}

#[cfg(test)]
#[path = "process_tests.rs"]
mod tests;
