//! Config import / export: modes, sections and the import preview.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExportMode {
    /// Passwords and keys masked (the default button).
    #[default]
    Redacted,
    /// Everything, after a consent dialog shown by the app.
    WithSecrets,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImportMode {
    #[default]
    Replace,
    Merge,
}

/// A part of the config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ConfigSection {
    Profiles,
    ServerGroups,
    Schedules,
    SplitTunnel,
    Dns,
    DomainRouting,
    Themes,
    Rotation,
    KillSwitch,
    Notifications,
    AppSettings,
}

impl ConfigSection {
    /// File order.
    pub const ALL: [ConfigSection; 11] = [
        ConfigSection::Profiles,
        ConfigSection::ServerGroups,
        ConfigSection::Schedules,
        ConfigSection::SplitTunnel,
        ConfigSection::Dns,
        ConfigSection::DomainRouting,
        ConfigSection::Themes,
        ConfigSection::Rotation,
        ConfigSection::KillSwitch,
        ConfigSection::Notifications,
        ConfigSection::AppSettings,
    ];

    /// Catalog key of the label (every section has one; the old page showed «serverGroups», U-10).
    pub const fn label_key(self) -> &'static str {
        match self {
            ConfigSection::Profiles => "settings.sectionProfiles",
            ConfigSection::ServerGroups => "settings.sectionServerGroups",
            ConfigSection::Schedules => "settings.sectionSchedules",
            ConfigSection::SplitTunnel => "settings.sectionSplitTunnel",
            ConfigSection::Dns => "settings.sectionDns",
            ConfigSection::DomainRouting => "settings.sectionDomainRouting",
            ConfigSection::Themes => "settings.sectionThemes",
            ConfigSection::Rotation => "settings.sectionRotation",
            ConfigSection::KillSwitch => "settings.sectionKillSwitch",
            ConfigSection::Notifications => "settings.sectionNotifications",
            ConfigSection::AppSettings => "settings.sectionAppSettings",
        }
    }
}

/// A config file read and validated, waiting to be applied (single use: consumed by the first
/// apply, even a failed one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportPreview {
    pub file_name: String,
    pub sections: Vec<ConfigSection>,
    /// Sections that already hold data here.
    pub conflicts: Vec<ConfigSection>,
    /// Secrets in the file are masked: profiles need their keys entered again.
    pub redacted: bool,
    /// Entries dropped by validation.
    pub invalid_entries: u32,
}
