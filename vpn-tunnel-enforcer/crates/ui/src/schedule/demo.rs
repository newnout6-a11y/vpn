//! A fake scheduler for `demo_lists` and the tests: three schedules like the reference
//! screenshot, a next event computed from them, small delays so busy states show.
//!
//! Scenes: `full` (default), `empty`, `loading` (the first read never ends), `failed` (the first
//! read fails, «Повторить» works), `errors` (every action fails).
use std::cell::{Cell, RefCell};
use std::time::Duration;

use async_trait::async_trait;
use jiff::tz::TimeZone;
use jiff::{Timestamp, ToSpan};
use tokio::sync::watch;
use vpnte_base::types::{UnixMs, now_ms};
use vpnte_base::{AppError, AppResult, ErrorKind};

use super::model::{
    Capture, HhMm, NextAction, NextEvent, ScheduleApi, ScheduleEntry, ScheduleInput,
    ScheduleSnapshot, ServerChoice, Upstream,
};
use crate::widgets::{Load, UiError};

/// The demo backend.
pub struct DemoSchedule {
    tx: watch::Sender<ScheduleSnapshot>,
    entries: RefCell<Vec<ScheduleEntry>>,
    servers: Vec<ServerChoice>,
    fail_actions: bool,
    next_id: Cell<u32>,
    delay: Duration,
}

fn hm(h: u16, m: u16) -> HhMm {
    HhMm::new(h, m).expect("demo times are valid")
}

fn entry(
    id: &str,
    name: &str,
    enabled: bool,
    days: &[u8],
    window: (HhMm, HhMm),
    (capture, upstream): (Capture, Upstream),
    profile: &str,
) -> ScheduleEntry {
    ScheduleEntry {
        id: id.into(),
        name: name.into(),
        enabled,
        days: days.to_vec(),
        start: window.0,
        end: window.1,
        profile_id: profile.into(),
        capture,
        upstream,
    }
}

impl DemoSchedule {
    /// A demo in `scene` (unknown scenes behave like `full`).
    pub fn new(scene: &str) -> Self {
        let servers = [
            ("srv-de", "Germany · Frankfurt", "VLESS Reality"),
            ("srv-nl", "Netherlands · Amsterdam", "VLESS"),
            ("srv-fi", "Finland · Helsinki", "Trojan"),
            ("srv-lv", "Latvia · Riga", "Hysteria2"),
        ]
        .map(|(id, name, protocol)| ServerChoice {
            id: id.into(),
            name: name.into(),
            protocol: protocol.into(),
        })
        .to_vec();
        let entries = if scene == "empty" {
            Vec::new()
        } else {
            vec![
                entry(
                    "demo-1",
                    "Рабочие дни",
                    true,
                    &[1, 2, 3, 4, 5],
                    (hm(9, 0), hm(19, 0)),
                    (Capture::Proxy, Upstream::Server),
                    "",
                ),
                entry(
                    "demo-2",
                    "Вечер выходного дня",
                    false,
                    &[6, 0],
                    (hm(18, 0), hm(23, 30)),
                    (Capture::Proxy, Upstream::LocalProxy),
                    "",
                ),
                entry(
                    "demo-3",
                    "Ночные обновления",
                    true,
                    &[0, 1, 2, 3, 4, 5, 6],
                    (hm(23, 0), hm(4, 0)),
                    (Capture::Tun, Upstream::Server),
                    "srv-de",
                ),
            ]
        };
        let demo = Self {
            tx: watch::Sender::new(ScheduleSnapshot::default()),
            entries: RefCell::new(entries),
            servers,
            fail_actions: scene == "errors",
            next_id: Cell::new(4),
            delay: Duration::from_millis(450),
        };
        match scene {
            "loading" => {}
            "failed" => {
                demo.tx.send_replace(ScheduleSnapshot {
                    schedules: Load::Failed(UiError::from(AppError::new(ErrorKind::Internal))),
                    ..ScheduleSnapshot::default()
                });
            }
            _ => demo.publish(),
        }
        demo
    }

    /// No artificial delay (tests).
    pub fn instant(mut self) -> Self {
        self.delay = Duration::ZERO;
        self
    }

    fn publish(&self) {
        let entries = self.entries.borrow().clone();
        let next = next_event(&entries, &TimeZone::system(), now_ms());
        self.tx.send_replace(ScheduleSnapshot {
            schedules: Load::Ready(entries),
            next,
            servers: self.servers.clone(),
            tun_available: false,
        });
    }

    async fn pause(&self) -> AppResult<()> {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        if self.fail_actions {
            return Err(AppError::new(ErrorKind::Conflict));
        }
        Ok(())
    }

    fn with_entry(&self, id: &str, change: impl FnOnce(&mut ScheduleEntry)) -> AppResult<()> {
        let mut entries = self.entries.borrow_mut();
        let found = entries.iter_mut().find(|e| e.id == id);
        found
            .map(change)
            .ok_or_else(|| AppError::new(ErrorKind::Conflict))
    }

    fn stored(&self, id: String, input: ScheduleInput) -> ScheduleEntry {
        ScheduleEntry {
            id,
            name: input.name,
            enabled: input.enabled,
            days: input.days,
            start: input.start,
            end: input.end,
            profile_id: input.profile_id,
            capture: input.capture,
            upstream: input.upstream,
        }
    }
}

#[async_trait(?Send)]
impl ScheduleApi for DemoSchedule {
    fn state(&self) -> watch::Receiver<ScheduleSnapshot> {
        self.tx.subscribe()
    }

    async fn reload(&self) -> AppResult<()> {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        self.publish();
        Ok(())
    }

    async fn create(&self, input: ScheduleInput) -> AppResult<()> {
        self.pause().await?;
        let id = format!("demo-{}", self.next_id.replace(self.next_id.get() + 1));
        let entry = self.stored(id, input);
        self.entries.borrow_mut().push(entry);
        self.publish();
        Ok(())
    }

    async fn update(&self, id: String, input: ScheduleInput) -> AppResult<()> {
        self.pause().await?;
        let entry = self.stored(id.clone(), input);
        self.with_entry(&id, |e| *e = entry)?;
        self.publish();
        Ok(())
    }

    async fn set_enabled(&self, id: String, enabled: bool) -> AppResult<()> {
        self.pause().await?;
        self.with_entry(&id, |e| e.enabled = enabled)?;
        self.publish();
        Ok(())
    }

    async fn delete(&self, id: String) -> AppResult<()> {
        self.pause().await?;
        self.entries.borrow_mut().retain(|e| e.id != id);
        self.publish();
        Ok(())
    }
}

/// A plain version of the scheduler's next-event rule for the fake data: windows on the local
/// calendar from yesterday to a week ahead, an end at or before the start ends the next day.
pub fn next_event(entries: &[ScheduleEntry], tz: &TimeZone, now: UnixMs) -> Option<NextEvent> {
    let today = Timestamp::from_millisecond(now)
        .ok()?
        .to_zoned(tz.clone())
        .date();
    let at = |date: jiff::civil::Date, t: HhMm| -> Option<UnixMs> {
        let time = jiff::civil::time((t.minutes() / 60) as i8, (t.minutes() % 60) as i8, 0, 0);
        Some(
            date.to_datetime(time)
                .to_zoned(tz.clone())
                .ok()?
                .timestamp()
                .as_millisecond(),
        )
    };
    let mut best: Option<NextEvent> = None;
    for e in entries.iter().filter(|e| e.enabled) {
        for offset in -1..=7i32 {
            let Ok(day) = today.checked_add(offset.days()) else {
                continue;
            };
            let weekday = day.weekday().to_sunday_zero_offset() as u8;
            if !e.days.contains(&weekday) {
                continue;
            }
            let end_day = if e.end <= e.start {
                day.tomorrow().ok()
            } else {
                Some(day)
            };
            let start = at(day, e.start);
            let stop = end_day.and_then(|d| at(d, e.end));
            for (moment, action) in [(start, NextAction::Start), (stop, NextAction::Stop)] {
                let Some(moment) = moment.filter(|&m| m > now) else {
                    continue;
                };
                if best.as_ref().is_none_or(|b| moment < b.at) {
                    best = Some(NextEvent {
                        action,
                        at: moment,
                        name: e.name.clone(),
                        capture: e.capture,
                    });
                }
            }
        }
    }
    best
}
