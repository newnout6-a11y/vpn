//! Pure logic of the page: the create / edit form and its validation, day labels, the window
//! hints and the countdown text of the next event (ui-pages §3.11, §3.18, U-25).
use std::time::Duration;

use jiff::Timestamp;
use jiff::tz::TimeZone;
use vpnte_base::Msg;
use vpnte_base::types::UnixMs;

use super::model::{HhMm, ScheduleEntry, ScheduleInput, ScheduleMode, ServerChoice};

/// Stored day numbers (0 = Sunday) in display order: Monday first, everywhere (U-25).
pub const DISPLAY_ORDER: [u8; 7] = [1, 2, 3, 4, 5, 6, 0];

/// Catalog key of the short name of stored day `day` («Пн» … «Вс»).
pub const fn day_key(day: u8) -> &'static str {
    match day {
        1 => "schedule.monday",
        2 => "schedule.tuesday",
        3 => "schedule.wednesday",
        4 => "schedule.thursday",
        5 => "schedule.friday",
        6 => "schedule.saturday",
        _ => "schedule.sunday",
    }
}

/// Day-name keys of `days` in display order (unknown numbers and repeats dropped).
pub fn days_keys(days: &[u8]) -> Vec<&'static str> {
    DISPLAY_ORDER
        .iter()
        .filter(|d| days.contains(d))
        .map(|&d| day_key(d))
        .collect()
}

/// The hint under a time window: «Весь день» when start == end (a 24-hour window, automation
/// S3), «до HH:MM следующего дня» when it ends before it starts.
pub fn window_hint(start: HhMm, end: HhMm) -> Option<Msg> {
    if start == end {
        Some(Msg::new("schedule.allDay"))
    } else if end < start {
        Some(Msg::new("schedule.untilNextDay").arg("time", end))
    } else {
        None
    }
}

/// Why the form cannot be saved yet (the save button's reason).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormProblem {
    Name,
    Days,
    Start,
    End,
    /// A Direct schedule points at a server that no longer exists.
    Server,
}

impl FormProblem {
    pub const fn msg_key(self) -> &'static str {
        match self {
            FormProblem::Name => "schedule.problem.name",
            FormProblem::Days => "schedule.problem.days",
            FormProblem::Start => "schedule.problem.start",
            FormProblem::End => "schedule.problem.end",
            FormProblem::Server => "schedule.problem.server",
        }
    }
}

/// The create / edit form. Times stay raw text while typing; they are parsed on save.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleForm {
    /// `Some(id)` while editing an existing schedule.
    pub editing: Option<String>,
    pub name: String,
    pub enabled: bool,
    /// Indexed by the stored day number (0 = Sunday).
    pub days: [bool; 7],
    pub start: String,
    pub end: String,
    pub profile_id: String,
    pub mode: ScheduleMode,
}

impl Default for ScheduleForm {
    /// The empty form of the old page: no name, on, no days, 09:00–18:00, Hard.
    fn default() -> Self {
        Self {
            editing: None,
            name: String::new(),
            enabled: true,
            days: [false; 7],
            start: "09:00".into(),
            end: "18:00".into(),
            profile_id: String::new(),
            mode: ScheduleMode::Hard,
        }
    }
}

impl ScheduleForm {
    /// The form filled from a stored schedule.
    pub fn edit(entry: &ScheduleEntry) -> Self {
        let mut days = [false; 7];
        for &d in &entry.days {
            if let Some(slot) = days.get_mut(usize::from(d)) {
                *slot = true;
            }
        }
        Self {
            editing: Some(entry.id.clone()),
            name: entry.name.clone(),
            enabled: entry.enabled,
            days,
            start: entry.start.to_string(),
            end: entry.end.to_string(),
            profile_id: entry.profile_id.clone(),
            mode: entry.mode,
        }
    }

    pub fn toggle_day(&mut self, day: u8) {
        if let Some(slot) = self.days.get_mut(usize::from(day)) {
            *slot = !*slot;
        }
    }

    /// The validated input, or the first thing to fix. The server matters only for Direct:
    /// empty = keep the current server, an unknown id is refused.
    pub fn input(&self, servers: &[ServerChoice]) -> Result<ScheduleInput, FormProblem> {
        let name = self.name.trim();
        if name.is_empty() {
            return Err(FormProblem::Name);
        }
        let days: Vec<u8> = (0..7u8).filter(|&d| self.days[usize::from(d)]).collect();
        if days.is_empty() {
            return Err(FormProblem::Days);
        }
        let start = HhMm::parse(self.start.trim()).ok_or(FormProblem::Start)?;
        let end = HhMm::parse(self.end.trim()).ok_or(FormProblem::End)?;
        let profile_id = if self.mode.uses_profile() {
            self.profile_id.clone()
        } else {
            String::new()
        };
        if !profile_id.is_empty() && !servers.iter().any(|s| s.id == profile_id) {
            return Err(FormProblem::Server);
        }
        Ok(ScheduleInput {
            name: name.to_owned(),
            enabled: self.enabled,
            days,
            start,
            end,
            profile_id,
            mode: self.mode,
        })
    }

    /// The window hint for the times typed so far.
    pub fn hint(&self) -> Option<Msg> {
        window_hint(
            HhMm::parse(self.start.trim())?,
            HhMm::parse(self.end.trim())?,
        )
    }
}

/// The countdown of the next event (the old `formatTimeUntil`): more than 24 h → «1d 1h»,
/// otherwise «1h 30m», under an hour «45m»; a past moment reads «0m». Unit words come from
/// the catalog (`schedule.until.*`; the old page showed English letters in Russian too).
pub fn time_until(at: UnixMs, now: UnixMs) -> Msg {
    let ms = at.saturating_sub(now).max(0);
    let hours = ms / 3_600_000;
    let minutes = ms % 3_600_000 / 60_000;
    if hours > 24 {
        Msg::new("schedule.until.dh")
            .arg("d", hours / 24)
            .arg("h", hours % 24)
    } else if hours > 0 {
        Msg::new("schedule.until.hm")
            .arg("h", hours)
            .arg("m", minutes)
    } else {
        Msg::new("schedule.until.m").arg("m", minutes)
    }
}

/// How long until [`time_until`] shows a different text (the next whole minute of the
/// remaining time, plus a little slack); `None` once the moment has passed.
pub fn until_next_change(at: UnixMs, now: UnixMs) -> Option<Duration> {
    let left = at.checked_sub(now).filter(|&ms| ms > 0)?;
    let step = match left % 60_000 {
        0 => 60_000,
        rest => rest,
    };
    Some(Duration::from_millis(step.unsigned_abs() + 20))
}

/// `HH:MM` of `at` on the local clock of `tz`.
pub fn local_hhmm(at: UnixMs, tz: &TimeZone) -> Option<String> {
    let zoned = Timestamp::from_millisecond(at).ok()?.to_zoned(tz.clone());
    Some(format!("{:02}:{:02}", zoned.hour(), zoned.minute()))
}

/// The server part of a schedule card: the server name of a Direct schedule, «сервер не
/// найден» when it was deleted, nothing for the current server or another mode.
pub fn server_label(
    entry: &ScheduleEntry,
    servers: &[ServerChoice],
) -> Option<Result<String, Msg>> {
    if !entry.mode.uses_profile() || entry.profile_id.is_empty() {
        return None;
    }
    Some(
        servers
            .iter()
            .find(|s| s.id == entry.profile_id)
            .map(|s| s.name.clone())
            .ok_or_else(|| Msg::new("schedule.serverMissing")),
    )
}
