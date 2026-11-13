//! `updates.json` (data dir): the user's update choices and what the last check found. Not part
//! of `settings.json`: that document belongs to core; this one is the update channel's own.
use serde::{Deserialize, Serialize};
use vpnte_base::types::UnixMs;
use vpnte_core::store::Document;
use vpnte_update::net::Via;

/// The update channel's document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdatesDoc {
    /// «Проверять автоматически» (on by default).
    pub auto_check: bool,
    /// «Скачивать заранее» (off by default: mobile data).
    pub download_ahead: bool,
    /// App versions the user skipped.
    pub skipped: Vec<String>,
    /// The highest feed `seq` accepted: a lower one is a replay or a stale mirror.
    pub max_seq: u64,
    pub last_check: Option<LastCheck>,
    /// The security release already announced in a notice (one notice per version, not per run).
    pub announced: Option<String>,
}

impl Default for UpdatesDoc {
    fn default() -> Self {
        Self {
            auto_check: true,
            download_ahead: false,
            skipped: Vec::new(),
            max_seq: 0,
            last_check: None,
            announced: None,
        }
    }
}

impl Document for UpdatesDoc {
    const FILE: &'static str = "updates.json";
    const VERSION: u32 = 1;
}

/// The last check: when, from which mirror and way, what it found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LastCheck {
    pub at: UnixMs,
    pub host: Option<String>,
    pub via: Option<Via>,
    pub result: Found,
}

/// What a check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Found {
    UpToDate,
    Newer,
    Stale,
    Failed,
}
