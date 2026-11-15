//! The `rotation.json` document, its limits, the UI patch and the legacy import.
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use vpnte_base::types::UnixMs;
use vpnte_core::store::Document;

/// Interval limits in minutes (old `MIN/MAX_INTERVAL_MINUTES`).
pub const INTERVAL_MINUTES: (u32, u32) = (5, 1440);
const DEFAULT_INTERVAL_MINUTES: u32 = 30;

/// Order in which the list is walked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RotationOrder {
    #[default]
    Sequential,
    Random,
}

/// The `rotation.json` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RotationConfig {
    pub enabled: bool,
    #[serde(deserialize_with = "lenient_interval")]
    pub interval_minutes: u32,
    pub order: RotationOrder,
    /// Rotation list in order, without duplicates (fix R7).
    #[serde(deserialize_with = "dedup_ids")]
    pub profile_ids: Vec<String>,
    /// Position of the profile rotation last moved to; changes only on success.
    pub current_index: usize,
    /// When the timer fires next; a future value survives restarts (fix R6).
    pub next_rotation_at: Option<UnixMs>,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_minutes: DEFAULT_INTERVAL_MINUTES,
            order: RotationOrder::Sequential,
            profile_ids: Vec::new(),
            current_index: 0,
            next_rotation_at: None,
        }
    }
}

impl Document for RotationConfig {
    const FILE: &'static str = "rotation.json";
    const VERSION: u32 = 1;
}

fn lenient_interval<'de, D: Deserializer<'de>>(d: D) -> Result<u32, D::Error> {
    let value = Value::deserialize(d)?;
    Ok(value
        .as_f64()
        .map_or(DEFAULT_INTERVAL_MINUTES, clamp_interval))
}

fn dedup_ids<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Ok(dedup(Vec::<String>::deserialize(d)?))
}

/// Order-preserving dedup; empty ids dropped.
pub(super) fn dedup(ids: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(ids.len());
    for id in ids {
        if !id.is_empty() && !out.contains(&id) {
            out.push(id);
        }
    }
    out
}

/// `[5, 1440]` minutes, rounded; a non-finite value becomes 5 (old `clampInterval`).
pub fn clamp_interval(minutes: f64) -> u32 {
    let (min, max) = INTERVAL_MINUTES;
    if !minutes.is_finite() || minutes < f64::from(min) {
        return min;
    }
    if minutes > f64::from(max) {
        return max;
    }
    // In range after the checks above, so the cast cannot truncate.
    minutes.round() as u32
}

impl RotationConfig {
    /// One-time import of the old `profile-rotation.json` (`{"rotation": {...}}`): interval
    /// clamped, ids deduplicated, `nextRotationAt` dropped (the countdown restarts).
    pub fn from_legacy(legacy: &Value) -> RotationConfig {
        let v = legacy.get("rotation").unwrap_or(legacy);
        let ids = v
            .get("profileIds")
            .and_then(Value::as_array)
            .into_iter()
            .flatten();
        let profile_ids = dedup(ids.filter_map(Value::as_str).map(str::to_owned).collect());
        let current_index = v.get("currentIndex").and_then(Value::as_u64).unwrap_or(0);
        let current_index = usize::try_from(current_index).unwrap_or(0);
        RotationConfig {
            enabled: v.get("enabled").and_then(Value::as_bool).unwrap_or(false),
            interval_minutes: v
                .get("intervalMinutes")
                .and_then(Value::as_f64)
                .map_or(DEFAULT_INTERVAL_MINUTES, clamp_interval),
            order: match v.get("order").and_then(Value::as_str) {
                Some("random") => RotationOrder::Random,
                _ => RotationOrder::Sequential,
            },
            current_index: if current_index < profile_ids.len() {
                current_index
            } else {
                0
            },
            profile_ids,
            next_rotation_at: None,
        }
    }

    pub(super) fn interval_ms(&self) -> i64 {
        i64::from(clamp_interval(f64::from(self.interval_minutes))) * 60_000
    }
}

/// What the UI may change (fix R7: never the index or the next instant).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RotationPatch {
    pub enabled: Option<bool>,
    pub interval_minutes: Option<f64>,
    pub order: Option<RotationOrder>,
    pub profile_ids: Option<Vec<String>>,
}
