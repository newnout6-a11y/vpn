//! View models and the [`ScheduleApi`] of the Schedule page.
use std::fmt;

use async_trait::async_trait;
use tokio::sync::watch;
use vpnte_base::AppResult;
use vpnte_base::types::UnixMs;

use crate::widgets::Load;

/// What the page needs from the scheduler (automation §6.3). Every mutation publishes the new
/// [`ScheduleSnapshot`] before it returns, so the page never patches its list by itself.
#[async_trait(?Send)]
pub trait ScheduleApi: 'static {
    /// The schedules, the next event and the server list, pushed on every change.
    fn state(&self) -> watch::Receiver<ScheduleSnapshot>;
    /// Reads the schedules again after a failed read (the result arrives through `state`).
    async fn reload(&self) -> AppResult<()>;
    /// Adds a schedule.
    async fn create(&self, input: ScheduleInput) -> AppResult<()>;
    /// Replaces every field of schedule `id` (the id stays).
    async fn update(&self, id: String, input: ScheduleInput) -> AppResult<()>;
    /// Switches schedule `id` on or off.
    async fn set_enabled(&self, id: String, enabled: bool) -> AppResult<()>;
    /// Deletes schedule `id` (an unknown id is not an error).
    async fn delete(&self, id: String) -> AppResult<()>;
}

/// Pushed state of the page.
#[derive(Debug, Clone, PartialEq)]
pub struct ScheduleSnapshot {
    pub schedules: Load<Vec<ScheduleEntry>>,
    /// The next start or stop of an enabled schedule within the look-ahead, if any.
    pub next: Option<NextEvent>,
    /// Servers a Direct schedule may pick (name and protocol only).
    pub servers: Vec<ServerChoice>,
}

impl Default for ScheduleSnapshot {
    fn default() -> Self {
        Self {
            schedules: Load::Loading,
            next: None,
            servers: Vec::new(),
        }
    }
}

/// How a schedule connects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ScheduleMode {
    #[default]
    Hard,
    Soft,
    Direct,
}

impl ScheduleMode {
    pub const ALL: [ScheduleMode; 3] =
        [ScheduleMode::Hard, ScheduleMode::Soft, ScheduleMode::Direct];

    /// Catalog key of the mode name («Hard (TUN)», …).
    pub const fn label_key(self) -> &'static str {
        match self {
            ScheduleMode::Hard => "modes.hard",
            ScheduleMode::Soft => "modes.soft",
            ScheduleMode::Direct => "modes.direct",
        }
    }

    /// Only Direct sessions pick a server; Hard and Soft go through the local proxy
    /// (automation S6, ui-pages U-25).
    pub const fn uses_profile(self) -> bool {
        matches!(self, ScheduleMode::Direct)
    }
}

/// A local wall-clock time, minutes after midnight (0..=1439), shown and stored as `HH:MM`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HhMm(u16);

impl HhMm {
    /// `None` outside 00:00..=23:59.
    pub const fn new(hour: u16, minute: u16) -> Option<HhMm> {
        if hour < 24 && minute < 60 {
            Some(HhMm(hour * 60 + minute))
        } else {
            None
        }
    }

    /// The strict form the scheduler accepts, `^([01]?\d|2[0-3]):([0-5]\d)$` (automation S7):
    /// «9:05» and «09:05» parse, «9:5», « 9:05», «09:30abc», «24:00» do not.
    pub fn parse(text: &str) -> Option<HhMm> {
        let (h, m) = text.split_once(':')?;
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if !(1..=2).contains(&h.len()) || m.len() != 2 || !digits(h) || !digits(m) {
            return None;
        }
        HhMm::new(h.parse().ok()?, m.parse().ok()?)
    }

    pub const fn minutes(self) -> u16 {
        self.0
    }
}

impl fmt::Display for HhMm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02}:{:02}", self.0 / 60, self.0 % 60)
    }
}

/// One stored schedule. `days` uses the stored numbering 0 = Sunday … 6 = Saturday.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleEntry {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub days: Vec<u8>,
    pub start: HhMm,
    pub end: HhMm,
    /// Server of a Direct schedule; empty = keep the current server.
    pub profile_id: String,
    pub mode: ScheduleMode,
}

/// What `create` / `update` take: a validated form (name trimmed, days sorted and unique,
/// `profile_id` empty unless the mode is Direct).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleInput {
    pub name: String,
    pub enabled: bool,
    pub days: Vec<u8>,
    pub start: HhMm,
    pub end: HhMm,
    pub profile_id: String,
    pub mode: ScheduleMode,
}

/// Whether the next event connects or disconnects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextAction {
    Start,
    Stop,
}

/// The next scheduled start or stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextEvent {
    pub action: NextAction,
    pub at: UnixMs,
    /// Name of the schedule that causes it.
    pub name: String,
}

/// A server a Direct schedule can use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerChoice {
    pub id: String,
    pub name: String,
    pub protocol: String,
}
