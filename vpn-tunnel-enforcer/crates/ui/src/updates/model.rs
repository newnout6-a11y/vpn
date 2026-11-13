//! View models of the update channel: display data only (no paths, no URLs, no secrets).
use std::collections::BTreeMap;

use vpnte_base::types::UnixMs;

/// Everything the banner, the «Обновления» section and the «Движки» block show.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UpdatesView {
    /// This build carries the owner's keys: without them nothing is checked and the section
    /// says so in one line.
    pub ready: bool,
    pub auto_check: bool,
    pub download_ahead: bool,
    /// Versions the user chose to skip.
    pub skipped: Vec<String>,
    pub last_check: Option<CheckLine>,
    /// A check runs now.
    pub checking: bool,
    /// A newer app version the banner offers (absent when skipped or put off for this run).
    pub app: Option<AppOffer>,
    /// Newer engine versions our CI tested.
    pub engines: Vec<EngineOffer>,
    /// Every engine with its version and origin (the «Движки» block).
    pub installed: Vec<EngineRow>,
    /// «Вернуть версию 2.0.0»: offered when the feed says the data format allows it.
    pub rollback_to: Option<String>,
    /// How the last update of the app went (shown once after the start that follows it).
    pub outcome: Option<UpdateOutcome>,
    /// A download in flight.
    pub progress: Option<Progress>,
    /// One calm line after an action: «Заработает после перезапуска приложения», a refusal…
    pub note: Option<Note>,
    /// The helper service, when it is installed and answers: its version and its own update.
    pub service: Option<ServiceLine>,
}

/// «Служба-помощник 2.0.1: актуальна».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceLine {
    pub version: String,
    pub state: ServiceState,
}

/// Where the helper service's own update stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceState {
    /// Not checked (no update keys in this build, or not yet): the version only.
    Unchecked,
    /// Its last check found nothing newer.
    Current,
    /// Checking or downloading.
    Working,
    /// `target` goes in once the VPN is off (or at the service's next start).
    Waiting { target: String },
    /// `target` goes in now.
    Restarting { target: String },
    /// The last check failed; the service tries again by itself.
    Failed,
}

/// The last check: when, from where, and what it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckLine {
    pub at: UnixMs,
    /// Mirror host the feed came from (`raw.githubusercontent.com`).
    pub host: Option<String>,
    /// Through the VPN session (else directly).
    pub via_vpn: bool,
    pub result: CheckResult,
}

/// What a check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckResult {
    UpToDate,
    Found,
    /// The newest feed any mirror had is older than 90 days: never "up to date".
    Stale,
    /// No mirror answered, or nothing verified.
    Failed,
}

/// A newer version of the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppOffer {
    pub version: String,
    /// Release notes by language code.
    pub notes: BTreeMap<String, String>,
    /// A security update: says so, and one tray notice went out.
    pub security: bool,
    /// «Пропустить» is offered: not for a security update or a build below the feed's
    /// `warn_below` (never forced either: «Позже» stays).
    pub can_skip: bool,
}

/// A newer engine version: «sing-box 1.14.4 → 1.14.5 (проверено нами 12.11)».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineOffer {
    pub id: String,
    pub name: String,
    pub from: String,
    pub to: String,
    /// Day our tests passed with it, `YYYY-MM-DD`.
    pub tested_on: Option<String>,
    pub notes: BTreeMap<String, String>,
}

/// One engine in the «Движки» block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineRow {
    pub id: String,
    pub name: String,
    pub version: String,
    /// `None` = built in; `Some(day)` = updated that day (`YYYY-MM-DD`).
    pub updated_on: Option<String>,
    /// «Вернуть предыдущую» goes back to this version (`None` = nothing to go back to).
    pub previous: Option<String>,
    /// «Вернуть встроенную» is offered (a downloaded version runs).
    pub can_restore_bundled: bool,
}

/// How the app's own update went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// «Обновлено до 2.0.1».
    Updated { version: String },
    /// The installer did not finish: it is kept and can be run again.
    Failed { version: String },
}

/// A download in flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    /// What is downloading (`VPN Tunnel Enforcer 2.0.1`, `sing-box 1.14.5`).
    pub what: String,
    pub done: u64,
    pub total: u64,
}

/// One calm line: a message key and its arguments (rendered by the UI).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub msg: vpnte_base::Msg,
    /// A refusal or failure (shown in the warning tone).
    pub warn: bool,
    /// An engine switch a running session can take at once: «Сейчас (переподключение на 1–3 с)»
    /// / «При следующем подключении» (p-follow).
    pub switch_now: bool,
}
