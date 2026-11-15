//! History of speed tests: `history/speed-tests.json`, newest first, at most 50.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vpnte_core::store::Document;

use super::{Egress, SpeedResult};

/// Rows kept.
pub const MAX_HISTORY: usize = 50;

/// The persisted history document.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct SpeedTests {
    #[serde(default)]
    pub history: Vec<SpeedResult>,
}

impl Document for SpeedTests {
    const FILE: &'static str = "history/speed-tests.json";
    const VERSION: u32 = 1;
}

impl SpeedTests {
    /// Puts a result at the front and drops the oldest beyond [`MAX_HISTORY`].
    pub fn push(&mut self, result: SpeedResult) {
        self.history.insert(0, result);
        self.history.truncate(MAX_HISTORY);
    }

    /// Empties the history.
    pub fn clear(&mut self) {
        self.history.clear();
    }

    /// Imports the old `speed-test` store (`{history: [...]}`, already opened). Rows without a
    /// time or a download figure are skipped; `egressMismatch: true` becomes
    /// `Egress::Changed { seen: None }`, anything else "not checked" (the old store could not
    /// tell a match from a failed lookup); the old `"Unknown"` profile becomes `None`.
    pub fn from_legacy(legacy: &Value) -> SpeedTests {
        let rows = legacy.get("history").and_then(Value::as_array);
        let history = rows
            .into_iter()
            .flatten()
            .filter_map(legacy_row)
            .take(MAX_HISTORY)
            .collect();
        SpeedTests { history }
    }
}

fn number(row: &Value, key: &str) -> Option<f64> {
    row.get(key)?
        .as_f64()
        .filter(|n| n.is_finite() && *n >= 0.0)
}

fn legacy_row(row: &Value) -> Option<SpeedResult> {
    let text = |key: &str| {
        row.get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let egress = if row.get("egressMismatch").and_then(Value::as_bool) == Some(true) {
        Egress::Changed { seen: None }
    } else {
        Egress::NotChecked
    };
    Some(SpeedResult {
        id: text("id").unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        timestamp: row.get("timestamp")?.as_i64()?,
        download_mbps: number(row, "downloadMbps")?,
        upload_mbps: number(row, "uploadMbps"),
        latency_ms: number(row, "latencyMs")
            .map_or(0, |ms| ms.round().min(f64::from(u32::MAX)) as u32),
        server_name: text("serverName").unwrap_or_default(),
        profile_used: text("profileUsed").filter(|p| p != "Unknown"),
        egress,
        transport_warning: None,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn row(i: i64) -> SpeedResult {
        SpeedResult {
            id: format!("r{i}"),
            timestamp: i,
            download_mbps: 10.0,
            upload_mbps: Some(5.0),
            latency_ms: 40,
            server_name: "Cloudflare".into(),
            profile_used: None,
            egress: Egress::Match,
            transport_warning: None,
        }
    }

    #[test]
    fn push_keeps_newest_fifty() {
        let mut doc = SpeedTests::default();
        for i in 0..60 {
            doc.push(row(i));
        }
        assert_eq!(doc.history.len(), MAX_HISTORY);
        assert_eq!(doc.history[0].id, "r59");
        assert_eq!(doc.history[49].id, "r10");
        doc.clear();
        assert!(doc.history.is_empty());
    }

    /// storage §2.4 H3: the old rows, `egressMismatch` only ever `true`.
    #[test]
    fn legacy_rows() {
        let legacy = json!({"history": [
            {"id": "a", "timestamp": 1700000000000_i64, "downloadMbps": 93.41, "uploadMbps": 40.2,
             "latencyMs": 38, "serverName": "Cloudflare", "profileUsed": "poland1", "egressMismatch": true},
            {"id": "b", "timestamp": 1700000000001_i64, "downloadMbps": 12.5, "uploadMbps": 3.1,
             "latencyMs": 80.4, "serverName": "OVH", "profileUsed": "Unknown"},
            {"id": "broken", "downloadMbps": 1.0},
            "junk"
        ]});
        let doc = SpeedTests::from_legacy(&legacy);
        assert_eq!(doc.history.len(), 2);
        assert_eq!(doc.history[0].egress, Egress::Changed { seen: None });
        assert_eq!(doc.history[0].profile_used.as_deref(), Some("poland1"));
        assert_eq!(doc.history[1].egress, Egress::NotChecked);
        assert_eq!(doc.history[1].profile_used, None);
        assert_eq!(doc.history[1].latency_ms, 80);
        let json = serde_json::to_value(&doc).unwrap();
        assert_eq!(json["history"][0]["downloadMbps"], json!(93.41));
        assert_eq!(
            json["history"][0]["egress"],
            json!({"kind": "changed", "seen": null})
        );
        assert!(json["history"][0].get("transportWarning").is_none());
        assert_eq!(serde_json::from_value::<SpeedTests>(json).unwrap(), doc);
    }
}
