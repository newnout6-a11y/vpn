//! Tests of the live check (live-probe spec §7 vectors; AT tags in the doc comments).
use std::path::PathBuf;

use serde_json::{Value, json};
use vpnte_base::Msg;
use vpnte_base::types::{UnixMs, now_ms};

use super::model::LiveCheck;
use crate::live_stages::Text;

mod engine;
mod findings;
mod history;
mod locales;
mod pure;
mod runner;
mod socks;

/// A minimal valid row (old `makeMockCheck` shape, ISO timestamps like imported rows).
pub(crate) fn row_json(id: &str, profile: Option<&str>) -> Value {
    let mut v = json!({
        "id": id,
        "host": "vpn.example.com",
        "port": 443,
        "mode": "basic",
        "startedAt": "2026-09-20T10:00:00.000Z",
        "finishedAt": "2026-09-20T10:00:01.000Z",
        "durationMs": 1000,
        "dns": {"status": "ok", "durationMs": 5, "a": ["1.2.3.4"], "aaaa": [], "cnameChain": []},
        "reachability": {"status": "ok", "durationMs": 5, "tcpReachable": true, "port": 443},
        "latency": {"min": 40, "avg": 50, "median": 48, "max": 60, "jitter": 5, "loss": 0.0,
                    "samples": [40, 48, 52, 60], "samplesAttempted": 4, "method": "tcp"},
        "findings": []
    });
    if let Some(p) = profile {
        v["profileId"] = json!(p);
    }
    v
}

/// [`row_json`] as a row finished `age_ms` ago.
pub(crate) fn row(id: &str, profile: Option<&str>, age_ms: UnixMs) -> LiveCheck {
    let mut check: LiveCheck = serde_json::from_value(row_json(id, profile)).unwrap();
    check.finished_at = now_ms() - age_ms;
    check.started_at = check.finished_at - 1000;
    check
}

/// Applies a JSON merge patch to [`row_json`] and decodes the row.
pub(crate) fn patched(patch: Value) -> LiveCheck {
    let mut v = row_json("check-1", Some("p-1"));
    merge(&mut v, patch);
    serde_json::from_value(v).unwrap()
}

fn merge(base: &mut Value, patch: Value) {
    match (base, patch) {
        (Value::Object(b), Value::Object(p)) => {
            for (k, v) in p {
                if v.is_null() {
                    b.remove(&k);
                } else {
                    merge(b.entry(k).or_insert(Value::Null), v);
                }
            }
        }
        (b, p) => *b = p,
    }
}

/// The message inside a stored text.
pub(crate) fn msg(text: &Text) -> &Msg {
    match text {
        Text::Msg(m) => m,
        Text::Legacy(s) => panic!("legacy text {s}"),
    }
}

/// The value of argument `name` of a message.
pub(crate) fn arg<'a>(m: &'a Msg, name: &str) -> &'a str {
    m.args
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("{} has no argument {name}", m.key))
}

/// A throw-away data root, removed on drop.
pub(crate) struct Root(pub PathBuf);

impl Root {
    pub(crate) fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "vpnte-live-history-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Root(dir)
    }

    pub(crate) fn file(&self) -> PathBuf {
        self.0.join("history").join("live-checks.json")
    }

    pub(crate) fn write(&self, text: &str) {
        std::fs::create_dir_all(self.0.join("history")).unwrap();
        std::fs::write(self.file(), text).unwrap();
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
