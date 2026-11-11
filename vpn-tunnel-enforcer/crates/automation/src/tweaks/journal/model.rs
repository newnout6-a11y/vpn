//! What the journal records: features, targets, values.
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Product name of a feature's tool (the same in every language).
pub fn tool_name(feature: Feature) -> &'static str {
    match feature {
        Feature::SoftEnv => "Environment",
        Feature::DevGit => "Git",
        Feature::DevGradle => "Gradle",
        Feature::DevStudio => "Android Studio",
        Feature::BrowserWebRtc => "Browser",
        Feature::LocationPrivacy => "Location",
    }
}

/// Which tweak a record belongs to; rollback and status work per feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Feature {
    /// Per-user proxy environment variables (Soft mode).
    SoftEnv,
    /// Git `http.proxy` / `https.proxy` in the user's global config.
    DevGit,
    /// Managed block in `gradle.properties`.
    DevGradle,
    /// Android Studio proxy options and JVM options.
    DevStudio,
    /// Browser WebRTC policy (package `automation-hardening`).
    BrowserWebRtc,
    /// Windows location consent and policy (package `automation-hardening`).
    LocationPrivacy,
}

/// The four Soft-mode variables (their key under the backend's environment key).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EnvVar {
    HttpProxy,
    HttpsProxy,
    AllProxy,
    NoProxy,
}

impl EnvVar {
    /// All four, in apply order.
    pub const ALL: [EnvVar; 4] = [
        EnvVar::HttpProxy,
        EnvVar::HttpsProxy,
        EnvVar::AllProxy,
        EnvVar::NoProxy,
    ];

    /// The variable name.
    pub fn name(self) -> &'static str {
        match self {
            EnvVar::HttpProxy => "HTTP_PROXY",
            EnvVar::HttpsProxy => "HTTPS_PROXY",
            EnvVar::AllProxy => "ALL_PROXY",
            EnvVar::NoProxy => "NO_PROXY",
        }
    }
}

/// Git configuration keys we set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GitKey {
    HttpProxy,
    HttpsProxy,
}

impl GitKey {
    /// Both keys, in apply order.
    pub const ALL: [GitKey; 2] = [GitKey::HttpProxy, GitKey::HttpsProxy];

    /// The `git config` key.
    pub fn name(self) -> &'static str {
        match self {
            GitKey::HttpProxy => "http.proxy",
            GitKey::HttpsProxy => "https.proxy",
        }
    }
}

/// Kind of a marker-delimited block we own inside a user file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlockKind {
    /// `gradle.properties` (`# >>> VPN Tunnel Enforcer (managed) >>>` … `# <<< VPN Tunnel Enforcer <<<`).
    Gradle,
    /// `studio64.exe.vmoptions` (the old app's markers, so its blocks stay recognisable).
    VmOptions,
}

impl BlockKind {
    /// The file name a block of this kind may live in.
    pub fn file_name(self) -> &'static str {
        match self {
            BlockKind::Gradle => "gradle.properties",
            BlockKind::VmOptions => "studio64.exe.vmoptions",
        }
    }
}

/// The `HttpConfigurable` options we edit in an Android Studio settings file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StudioOption {
    UseHttpProxy,
    ProxyHost,
    ProxyPort,
    ProxyTypeIsSocks,
}

impl StudioOption {
    /// All four, in apply order.
    pub const ALL: [StudioOption; 4] = [
        StudioOption::UseHttpProxy,
        StudioOption::ProxyHost,
        StudioOption::ProxyPort,
        StudioOption::ProxyTypeIsSocks,
    ];

    /// The `<option name="…">` attribute.
    pub fn name(self) -> &'static str {
        match self {
            StudioOption::UseHttpProxy => "USE_HTTP_PROXY",
            StudioOption::ProxyHost => "PROXY_HOST",
            StudioOption::ProxyPort => "PROXY_PORT",
            StudioOption::ProxyTypeIsSocks => "PROXY_TYPE_IS_SOCKS",
        }
    }
}

/// Registry root of a [`Target::Reg`] value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegHive {
    Hkcu,
    Hklm,
}

/// One system value we may change.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "camelCase")]
pub enum Target {
    /// A per-user environment variable.
    Env { var: EnvVar },
    /// A key of the user's global Git config.
    Git { key: GitKey },
    /// Our marker-delimited block in a user file (`Val::Text` = the whole block).
    Block { kind: BlockKind, path: PathBuf },
    /// One `HttpConfigurable` option in an Android Studio settings file (`Val::Text` = its value).
    StudioOpt { path: PathBuf, option: StudioOption },
    /// Lines the old app left in `gradle.properties` (legacy import); `Val::Text` = the lines
    /// still present, `\n`-joined. Removal deletes every occurrence of each line.
    Lines { path: PathBuf, lines: Vec<String> },
    /// A registry value (browser policy, location privacy); admitted by the caller's allow-list.
    Reg {
        hive: RegHive,
        key: String,
        name: String,
    },
}

impl Target {
    /// Log-safe label: no user paths (file name only) and never a value.
    pub fn label(&self) -> String {
        let file = |p: &Path| {
            p.file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
        };
        match self {
            Target::Env { var } => format!("env {}", var.name()),
            Target::Git { key } => format!("git {}", key.name()),
            Target::Block { path, .. } => format!("block in {}", file(path)),
            Target::StudioOpt { path, option } => format!("{} in {}", option.name(), file(path)),
            Target::Lines { path, .. } => format!("legacy lines in {}", file(path)),
            Target::Reg { hive, key, name } => format!("{hive:?}\\{key}\\{name}"),
        }
    }

    /// The baseline recorded when we first touch the target. A block between our markers is ours
    /// by definition, so a leftover one (journal lost in a crash) is never restored.
    pub(crate) fn fresh_baseline(&self, current: Val) -> Val {
        match self {
            Target::Block { .. } | Target::Lines { .. } => Val::Absent,
            _ => current,
        }
    }
}

/// A value as stored in the system.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "t", content = "v")]
pub enum Val {
    /// Not set (no value, no block, no option, no file).
    Absent,
    /// `REG_SZ`.
    Sz(String),
    /// `REG_EXPAND_SZ` (kept as such on restore, F-117).
    ExpandSz(String),
    /// `REG_DWORD`.
    Dword(u32),
    /// Text in a file or the Git config.
    Text(String),
}

/// One journalled change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub feature: Feature,
    pub target: Target,
    /// The value before our first change (kept across refreshes).
    pub baseline: Val,
    /// The value we wrote last.
    pub applied: Val,
    /// Our first write created the container (registry key or file): remove it on rollback if empty.
    #[serde(default)]
    pub created: bool,
}
