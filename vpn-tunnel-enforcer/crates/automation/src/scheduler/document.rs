//! The `schedules.json` document, the edit draft and the legacy import.
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use vpnte_base::types::UnixMs;
use vpnte_base::{AppError, AppResult, Msg};
use vpnte_core::store::Document;

use crate::schedule::{HhMm, ScheduleEntry, ScheduleMode};

/// The `schedules.json` document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Schedules {
    #[serde(default, deserialize_with = "lenient_entries")]
    pub schedules: Vec<ScheduleEntry>,
    /// An instant inside the run the user stopped or took over by hand; that run is left alone,
    /// also after an app restart (fix S8). Cleared once the run is over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppressed_at: Option<UnixMs>,
}

impl Document for Schedules {
    const FILE: &'static str = "schedules.json";
    const VERSION: u32 = 1;
}

/// One bad entry (a hand edit) must not make the whole file unreadable: it is skipped and logged.
fn lenient_entries<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<ScheduleEntry>, D::Error> {
    let mut entries: Vec<ScheduleEntry> = crate::lenient::list(d)?;
    entries.iter_mut().for_each(|e| normalize_days(&mut e.days));
    Ok(entries)
}

fn normalize_days(days: &mut Vec<u8>) {
    days.retain(|d| *d <= 6);
    days.sort_unstable();
    days.dedup();
}

const MAX_NAME_CHARS: usize = 200;

/// What the UI submits to create or edit a schedule (times are parsed with `HhMm::from_str`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleDraft {
    pub name: String,
    pub enabled: bool,
    /// 0 = Sunday … 6 = Saturday; stored sorted without duplicates. Empty = never active.
    pub days: Vec<u8>,
    pub start_time: HhMm,
    pub end_time: HhMm,
    /// Required for `Direct`, ignored by `Hard` / `Soft` (kept so the form can switch back).
    pub profile_id: String,
    pub mode: ScheduleMode,
}

impl ScheduleDraft {
    pub(super) fn into_entry(self, id: String) -> AppResult<ScheduleEntry> {
        let name = self.name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
            return Err(AppError::validation(Msg::new(
                "automation.scheduler.invalidName",
            )));
        }
        if self.days.iter().any(|d| *d > 6) {
            return Err(AppError::validation(Msg::new(
                "automation.scheduler.invalidDays",
            )));
        }
        let profile_id = self.profile_id.trim();
        if self.mode == ScheduleMode::Direct && profile_id.is_empty() {
            return Err(AppError::validation(Msg::new(
                "automation.scheduler.profileRequired",
            )));
        }
        if self.start_time == self.end_time {
            tracing::info!(%id, "schedule start == end: a 24-hour window");
        }
        let mut days = self.days;
        normalize_days(&mut days);
        Ok(ScheduleEntry {
            id,
            name: name.to_owned(),
            enabled: self.enabled,
            days,
            start_time: self.start_time,
            end_time: self.end_time,
            profile_id: profile_id.to_owned(),
            mode: self.mode,
        })
    }
}

impl From<ScheduleEntry> for ScheduleDraft {
    fn from(e: ScheduleEntry) -> Self {
        ScheduleDraft {
            name: e.name,
            enabled: e.enabled,
            days: e.days,
            start_time: e.start_time,
            end_time: e.end_time,
            profile_id: e.profile_id,
            mode: e.mode,
        }
    }
}

impl Schedules {
    /// One-time import of the old `scheduler.json` (`{"schedules": [...]}`): ids kept, times read
    /// with the old lenient rules and stored as `HH:MM`, unusable entries skipped with a warning.
    pub fn from_legacy(legacy: &Value) -> (Schedules, Vec<Msg>) {
        let mut doc = Schedules::default();
        let mut warnings = Vec::new();
        let items = legacy.get("schedules").and_then(Value::as_array);
        for (i, item) in items.into_iter().flatten().enumerate() {
            match legacy_entry(item) {
                Some(entry) => doc.schedules.push(entry),
                None => {
                    let label = item
                        .get("name")
                        .and_then(Value::as_str)
                        .map_or_else(|| format!("#{}", i + 1), |name| name.trim().to_owned());
                    tracing::warn!(index = i, "legacy schedule skipped");
                    warnings
                        .push(Msg::new("automation.scheduler.importSkipped").arg("name", label));
                }
            }
        }
        (doc, warnings)
    }
}

fn legacy_entry(v: &Value) -> Option<ScheduleEntry> {
    let text = |key: &str| v.get(key).and_then(Value::as_str);
    let name = text("name")?.trim();
    let mode = match text("mode")? {
        "hard" => ScheduleMode::Hard,
        "soft" => ScheduleMode::Soft,
        "direct" => ScheduleMode::Direct,
        _ => return None,
    };
    let mut days: Vec<u8> = (v.get("days")?.as_array()?.iter())
        .filter_map(|d| d.as_u64().and_then(|d| u8::try_from(d).ok()))
        .collect();
    normalize_days(&mut days);
    let id = text("id").map(str::trim).filter(|id| !id.is_empty());
    let entry = ScheduleEntry {
        id: id.map_or_else(|| uuid::Uuid::new_v4().to_string(), str::to_owned),
        name: name.to_owned(),
        // Unknown means off: an import must never switch protection on by itself.
        enabled: v.get("enabled").and_then(Value::as_bool).unwrap_or(false),
        days,
        start_time: HhMm::parse_lenient(text("startTime")?)?,
        end_time: HhMm::parse_lenient(text("endTime")?)?,
        profile_id: text("profileId").unwrap_or_default().trim().to_owned(),
        mode,
    };
    (!entry.name.is_empty()).then_some(entry)
}
