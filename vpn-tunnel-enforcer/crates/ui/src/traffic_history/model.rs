//! View models, the [`TrafficHistoryApi`] and the pure logic of the Traffic page: search,
//! totals, day groups, sizes and times.
use std::sync::Arc;

use async_trait::async_trait;
use jiff::Timestamp;
use jiff::civil::Date;
use jiff::tz::TimeZone;
use tokio::sync::watch;
use vpnte_base::types::UnixMs;
use vpnte_base::{AppResult, Msg};

use crate::widgets::Load;

/// Rows rendered at most; the search still covers every entry (the old cap: a sing-box journal
/// can hold thousands of unique domains).
pub const MAX_RENDERED: usize = 300;

/// What the page needs from the domain history (forensics). The history takes no IP (the old
/// page stamped the current IP on every row, U-18).
#[async_trait(?Send)]
pub trait TrafficHistoryApi: 'static {
    /// The domains (newest `last_seen` first) and whether the tunnel runs, pushed on every
    /// change: new domains, counters, site names arriving, a clear.
    fn state(&self) -> watch::Receiver<TrafficSnapshot>;
    /// Reads the journal again now. A failure leaves the published list as it is (the page
    /// shows a toast); a failed first read is published as `Load::Failed`.
    async fn reload(&self) -> AppResult<()>;
    /// Deletes the whole domain history (the page asks first).
    async fn clear(&self) -> AppResult<()>;
    /// Opens `url` (always `https://<domain>`) in the default browser, never inside the app.
    async fn open_site(&self, url: String) -> AppResult<()>;
}

/// Pushed state of the page.
#[derive(Debug, Clone, PartialEq)]
pub struct TrafficSnapshot {
    pub domains: Load<Arc<[DomainRow]>>,
    pub tunnel_up: bool,
}

impl Default for TrafficSnapshot {
    fn default() -> Self {
        Self {
            domains: Load::Loading,
            tunnel_up: false,
        }
    }
}

/// Site metadata of a domain (opt-in enrichment).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SiteInfo {
    /// Not requested (enrichment off or no route to fetch it).
    #[default]
    None,
    Pending,
    Ready {
        name: Option<String>,
        title: Option<String>,
    },
    Unavailable,
}

impl SiteInfo {
    /// The page title of a ready site, if it has one.
    pub fn title(&self) -> Option<&str> {
        match self {
            SiteInfo::Ready { title, .. } => title.as_deref().filter(|t| !t.trim().is_empty()),
            _ => None,
        }
    }
}

/// One domain of the history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRow {
    pub domain: String,
    pub first_seen: UnixMs,
    pub last_seen: UnixMs,
    /// Connections seen to the domain.
    pub count: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub site: SiteInfo,
}

/// The rows whose domain contains the query (case-insensitive, query trimmed), in order.
pub fn filter<'a>(rows: &'a [DomainRow], query: &str) -> Vec<&'a DomainRow> {
    let query = query.trim().to_lowercase();
    rows.iter()
        .filter(|r| query.is_empty() || r.domain.to_lowercase().contains(&query))
        .collect()
}

/// Bytes down and up over `rows`.
pub fn totals(rows: &[&DomainRow]) -> (u64, u64) {
    rows.iter().fold((0, 0), |(down, up), r| {
        (
            down.saturating_add(r.bytes_down),
            up.saturating_add(r.bytes_up),
        )
    })
}

/// Consecutive rows grouped by the local date of `last_seen` (rows arrive newest first, so
/// this equals the old grouping by first appearance).
pub fn by_day<'a>(
    rows: &[&'a DomainRow],
    tz: &TimeZone,
) -> Vec<(Option<Date>, Vec<&'a DomainRow>)> {
    let mut groups: Vec<(Option<Date>, Vec<&DomainRow>)> = Vec::new();
    for &row in rows {
        let day = local(row.last_seen, tz).map(|z| z.date());
        match groups.last_mut() {
            Some((d, list)) if *d == day => list.push(row),
            _ => groups.push((day, vec![row])),
        }
    }
    groups
}

fn local(ms: UnixMs, tz: &TimeZone) -> Option<jiff::Zoned> {
    Some(Timestamp::from_millisecond(ms).ok()?.to_zoned(tz.clone()))
}

/// A moment on the local clock for display: day of month, month 1–12, `HH:MM:SS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moment {
    pub day: i8,
    pub month: i8,
    pub time: String,
}

impl Moment {
    /// «11 нояб., 11:53:56» / «Nov 11, 11:53:56»: the old `toLocaleString` with seconds, a
    /// 24-hour clock in both languages; `month` is the already rendered month name.
    pub fn msg(&self, month: String) -> Msg {
        Msg::new("trafficHistory.dateTime")
            .arg("day", self.day)
            .arg("month", month)
            .arg("time", &self.time)
    }
}

/// `ms` on the local clock of `tz`.
pub fn moment(ms: UnixMs, tz: &TimeZone) -> Option<Moment> {
    let z = local(ms, tz)?;
    Some(Moment {
        day: z.day(),
        month: z.month(),
        time: format!("{:02}:{:02}:{:02}", z.hour(), z.minute(), z.second()),
    })
}

/// Catalog key of the short month name («нояб.», «Nov»).
pub const fn month_key(month: i8) -> &'static str {
    match month {
        1 => "trafficHistory.month.1",
        2 => "trafficHistory.month.2",
        3 => "trafficHistory.month.3",
        4 => "trafficHistory.month.4",
        5 => "trafficHistory.month.5",
        6 => "trafficHistory.month.6",
        7 => "trafficHistory.month.7",
        8 => "trafficHistory.month.8",
        9 => "trafficHistory.month.9",
        10 => "trafficHistory.month.10",
        11 => "trafficHistory.month.11",
        _ => "trafficHistory.month.12",
    }
}

/// The heading of a day group: «11.11.2026» / «2026-11-11».
pub fn day_heading(day: Date) -> Msg {
    Msg::new("trafficHistory.day")
        .arg("day", format!("{:02}", day.day()))
        .arg("month", format!("{:02}", day.month()))
        .arg("year", day.year())
}

/// The link of the domain button: `https://<domain>` for a plain host name (letters of any
/// script, digits, `-`, `.`), nothing for anything else.
pub fn site_url(domain: &str) -> Option<String> {
    let ok = !domain.is_empty()
        && domain.len() <= 253
        && !domain.starts_with(['.', '-'])
        && domain
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '.');
    ok.then(|| format!("https://{domain}"))
}

/// The second line of a row: the site title when there is one, else when the domain was first
/// seen; then, if it was seen again later, « · » / « – » and the last time (`when` formats a
/// moment).
pub fn seen_line(row: &DomainRow, when: impl Fn(UnixMs) -> String) -> String {
    let title = row.site.title();
    let mut line = title.map_or_else(|| when(row.first_seen), str::to_owned);
    if row.first_seen != row.last_seen {
        line.push_str(if title.is_some() { " · " } else { " – " });
        line.push_str(&when(row.last_seen));
    }
    line
}
