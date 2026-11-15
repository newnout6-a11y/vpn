//! Documents no library owns: kill-switch protection (`protection.json`), custom themes
//! (`themes.json`) and the Soft-mode dev targets (`soft.json`). Unknown keys written by a newer
//! version are kept (`extra`).
use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};
use vpnte_automation::tweaks::DevTargets;
use vpnte_core::settings::import_kill_switch;
use vpnte_core::store::Document;
use vpnte_ui::theme::{Palette, Theme, ThemeMode};
use vpnte_winnet::wfp::{
    ExceptionKind, KillSwitchException, ProtectionSettings, check_list, validate_exception,
};

/// Id of the built-in light theme.
pub const BUILTIN_LIGHT: &str = "builtin-light";
/// Id of the built-in dark theme.
pub const BUILTIN_DARK: &str = "builtin-dark";
/// Id of the built-in theme that follows Windows (also the fallback for unknown ids).
pub const BUILTIN_SYSTEM: &str = "builtin-system";

/// `protection.json`: kill-switch level, leak-protection switches and exceptions, in winnet's
/// model (`wfp::Protection::new` takes `settings`; its `Persist` callbacks write it back).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProtectionDoc {
    #[serde(flatten)]
    pub settings: ProtectionSettings,
    /// Keys written by a newer version, kept.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Document for ProtectionDoc {
    const FILE: &'static str = "protection.json";
    const VERSION: u32 = 1;
}

impl ProtectionDoc {
    /// The old `granular-kill-switch` store (`{killSwitchLevel, killSwitchExceptions}`) with the
    /// old settings boolean `firewallKillSwitch`: the level follows `import_kill_switch` (D-16,
    /// the same rule as `Settings::kill_switch`), every exception is validated again and an
    /// invalid one (bad address, missing program, duplicate, no id) is dropped. Returns the
    /// document and the number of dropped exceptions.
    pub fn from_legacy(
        granular: Option<&Value>,
        firewall_kill_switch: Option<bool>,
    ) -> (Self, usize) {
        let field = |name: &str| granular.and_then(|g| g.get(name));
        let level = field("killSwitchLevel").and_then(Value::as_str);
        let mut settings = ProtectionSettings {
            level: import_kill_switch(level, firewall_kill_switch),
            ..ProtectionSettings::default()
        };
        let mut dropped = 0;
        for entry in field("killSwitchExceptions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(exception) = legacy_exception(entry) else {
                dropped += 1;
                continue;
            };
            settings.exceptions.push(exception);
            // A duplicate (or one past the limit) is refused like a new entry would be.
            if check_list(&settings.exceptions).is_err() {
                settings.exceptions.pop();
                dropped += 1;
            }
        }
        let doc = Self {
            settings,
            extra: Map::new(),
        };
        (doc, dropped)
    }
}

/// One old exception `{id, type: "app" | "ip", value, label}`, validated like a new one.
fn legacy_exception(entry: &Value) -> Option<KillSwitchException> {
    let field = |name: &str| entry.get(name).and_then(Value::as_str);
    let kind = match field("type")? {
        "app" => ExceptionKind::App,
        "ip" => ExceptionKind::Ip,
        _ => return None,
    };
    let id = field("id").filter(|id| !id.trim().is_empty())?.to_owned();
    let (target, label) = validate_exception(kind, field("value")?, field("label")?).ok()?;
    Some(KillSwitchException { id, target, label })
}

/// `themes.json`: the user's custom themes. The active id lives in `Settings::active_theme_id`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ThemesDoc {
    #[serde(deserialize_with = "lenient")]
    pub custom_themes: Vec<CustomTheme>,
    /// Keys written by a newer version, kept.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Document for ThemesDoc {
    const FILE: &'static str = "themes.json";
    const VERSION: u32 = 1;
}

/// One custom theme in the old `ThemeConfig` shape (`colors`: level key -> `#rrggbb`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomTheme {
    pub id: String,
    pub name: String,
    /// `light` / `dark` / `system`; anything else reads as `system`.
    pub mode: String,
    #[serde(default)]
    pub colors: BTreeMap<String, String>,
}

impl CustomTheme {
    /// The stored mode (unknown values: `System`).
    pub fn mode(&self) -> ThemeMode {
        ThemeMode::from_name(&self.mode).unwrap_or_default()
    }

    /// The theme with its palette; missing or malformed levels come from the built-in palette
    /// of its mode (`Palette::complete`).
    pub fn theme(&self) -> Theme {
        let mode = self.mode();
        let custom = Palette::complete(mode, |key| self.colors.get(key).map(String::as_str));
        Theme {
            mode,
            custom: Some(custom),
        }
    }
}

impl ThemesDoc {
    /// The theme `id` names: a built-in, a custom theme, else the System built-in (a deleted or
    /// unknown id falls back to System, as the old app did).
    pub fn theme(&self, id: &str) -> Theme {
        match id {
            BUILTIN_LIGHT => Theme::builtin(ThemeMode::Light),
            BUILTIN_DARK => Theme::builtin(ThemeMode::Dark),
            _ => self
                .custom_themes
                .iter()
                .find(|t| t.id == id)
                .map_or(Theme::builtin(ThemeMode::System), CustomTheme::theme),
        }
    }

    /// The custom themes of the old `themes` store (`{activeThemeId, customThemes}`); invalid
    /// entries are dropped. The active id goes through `Settings::apply_legacy_stores`.
    pub fn from_legacy(old: &Value) -> Self {
        let custom_themes = old
            .get("customThemes")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();
        Self {
            custom_themes,
            extra: Map::new(),
        }
    }
}

/// `soft.json`: the dev tools a Soft session also points at the local proxy (opt-in, all off).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SoftDoc {
    pub dev_targets: DevTargets,
    /// Keys written by a newer version, kept.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Document for SoftDoc {
    const FILE: &'static str = "soft.json";
    const VERSION: u32 = 1;
}

/// A hand-edited entry that no longer parses is dropped instead of making the whole document
/// unreadable (the next write removes it for good).
fn lenient<'de, D: Deserializer<'de>, T: DeserializeOwned>(d: D) -> Result<Vec<T>, D::Error> {
    let raw = Vec::<Value>::deserialize(d)?;
    Ok(raw
        .into_iter()
        .filter_map(|v| match serde_json::from_value(v) {
            Ok(item) => Some(item),
            Err(err) => {
                tracing::warn!(%err, "invalid entry in themes.json dropped");
                None
            }
        })
        .collect())
}
