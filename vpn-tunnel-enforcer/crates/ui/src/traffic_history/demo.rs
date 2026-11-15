//! A fake domain history for `demo_lists` and the tests: the domains of the reference screenshot
//! over today and yesterday, site names in every state (one arrives a few seconds after start).
//!
//! Scenes: `full` (default), `empty`, `loading` (the first read never ends), `failed` (the first
//! read fails, «Повторить» works), `errors` (every action fails), `many` (450 domains: the
//! 300-row cap).
use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::watch;
use vpnte_base::types::UnixMs;
use vpnte_base::{AppError, AppResult, ErrorKind};

use super::model::{DomainRow, SiteInfo, TrafficHistoryApi, TrafficSnapshot};
use crate::widgets::{Load, UiError};

/// When the pending site name of the `full` scene arrives.
const SITE_ARRIVES: Duration = Duration::from_secs(4);

/// The demo backend.
pub struct DemoTrafficHistory {
    tx: watch::Sender<TrafficSnapshot>,
    fail_actions: bool,
    delay: Duration,
    /// URLs passed to `open_site` (nothing is opened).
    pub opened: RefCell<Vec<String>>,
}

const MB: u64 = 1024 * 1024;

fn ready(name: &str, title: &str) -> SiteInfo {
    SiteInfo::Ready {
        name: Some(name.into()),
        title: Some(title.into()),
    }
}

/// The rows of the `full` scene, newest first, relative to `now`.
pub fn sample(now: UnixMs) -> Vec<DomainRow> {
    let rows: [(&str, u64, u64, u64, SiteInfo); 12] = [
        (
            "video.example.com",
            412,
            1833 * MB,
            30 * MB,
            ready("Example Video", "Example Video — смотрите что угодно"),
        ),
        ("cdn.example.net", 1207, 610 * MB, 11 * MB, SiteInfo::None),
        ("api.example.org", 960, 17 * MB, 9 * MB, SiteInfo::Pending),
        (
            "chat.example.net",
            344,
            68 * MB,
            20 * MB,
            ready("Example Chat", ""),
        ),
        (
            "mail.example.com",
            128,
            39 * MB,
            3 * MB,
            ready("Example Mail", "Входящие — Example Mail"),
        ),
        (
            "static.example.net",
            2210,
            219 * MB,
            4 * MB,
            SiteInfo::Unavailable,
        ),
        ("maps.example.com", 87, 63 * MB, MB, SiteInfo::None),
        (
            "updates.example.org",
            12,
            296 * MB,
            586 * 1024,
            SiteInfo::None,
        ),
        (
            "news.example.com",
            59,
            23 * MB,
            879 * 1024,
            ready("Example News", "Главное за сегодня"),
        ),
        ("telemetry.example.net", 640, MB, 7 * MB, SiteInfo::None),
        ("docs.example.org", 31, 5 * MB, 300 * 1024, SiteInfo::None),
        ("old.example.com", 1, 0, 0, SiteInfo::None),
    ];
    const MIN: i64 = 60_000;
    rows.into_iter()
        .enumerate()
        .map(|(i, (domain, count, down, up, site))| {
            let i = i as i64;
            // The last two were seen yesterday; the very last only once.
            let last_seen = if i < 10 {
                now - (i * 17 + 3) * MIN
            } else {
                now - (26 * 60 + i) * MIN
            };
            let first_seen = if count == 1 {
                last_seen
            } else {
                last_seen - (40 + i * 3) * MIN
            };
            DomainRow {
                domain: domain.into(),
                first_seen,
                last_seen,
                count,
                bytes_up: up,
                bytes_down: down,
                site,
            }
        })
        .collect()
}

/// `n` generated domains, newest first (the `many` scene).
pub fn generated(now: UnixMs, n: usize) -> Vec<DomainRow> {
    (0..n)
        .map(|i| {
            let last_seen = now - (i as i64) * 45_000;
            DomainRow {
                domain: format!("host-{i:03}.example.net"),
                first_seen: last_seen - 600_000,
                last_seen,
                count: (i % 37 + 1) as u64,
                bytes_up: (i as u64) * 2048,
                bytes_down: (i as u64) * 96 * 1024,
                site: SiteInfo::None,
            }
        })
        .collect()
}

impl DemoTrafficHistory {
    /// A demo in `scene` at `now` (unknown scenes behave like `full`).
    pub fn new(scene: &str, now: UnixMs) -> Self {
        let rows = match scene {
            "empty" => Vec::new(),
            "many" => generated(now, 450),
            _ => sample(now),
        };
        let domains = match scene {
            "loading" => Load::Loading,
            "failed" => Load::Failed(UiError::from(AppError::new(ErrorKind::Internal))),
            _ => Load::Ready(Arc::from(rows)),
        };
        let tx = watch::Sender::new(TrafficSnapshot {
            domains,
            tunnel_up: scene != "empty",
        });
        if scene == "full" || scene.is_empty() {
            arrive_later(tx.clone());
        }
        Self {
            tx,
            fail_actions: scene == "errors",
            delay: Duration::from_millis(500),
            opened: RefCell::new(Vec::new()),
        }
    }

    /// No artificial delay (tests).
    pub fn instant(mut self) -> Self {
        self.delay = Duration::ZERO;
        self
    }

    async fn pause(&self) -> AppResult<()> {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        if self.fail_actions {
            return Err(AppError::new(ErrorKind::Network));
        }
        Ok(())
    }
}

/// The pending site name of `api.example.org` arrives after [`SITE_ARRIVES`] (only inside a
/// tokio runtime; plain unit tests skip it).
fn arrive_later(tx: watch::Sender<TrafficSnapshot>) {
    if tokio::runtime::Handle::try_current().is_err() {
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(SITE_ARRIVES).await;
        tx.send_modify(|snapshot| {
            if let Load::Ready(rows) = &mut snapshot.domains {
                let mut next = rows.to_vec();
                for row in next.iter_mut().filter(|r| r.site == SiteInfo::Pending) {
                    row.site = ready("Example API", "Example API — документация");
                }
                *rows = Arc::from(next);
            }
        });
    });
}

#[async_trait(?Send)]
impl TrafficHistoryApi for DemoTrafficHistory {
    fn state(&self) -> watch::Receiver<TrafficSnapshot> {
        self.tx.subscribe()
    }

    async fn reload(&self) -> AppResult<()> {
        self.pause().await?;
        if self.tx.borrow().domains.error().is_some() {
            let now = vpnte_base::types::now_ms();
            self.tx
                .send_modify(|s| s.domains = Load::Ready(Arc::from(sample(now))));
        } else {
            self.tx.send_modify(|_| {});
        }
        Ok(())
    }

    async fn clear(&self) -> AppResult<()> {
        self.pause().await?;
        self.tx
            .send_modify(|s| s.domains = Load::Ready(Arc::from(Vec::new())));
        Ok(())
    }

    async fn open_site(&self, url: String) -> AppResult<()> {
        tracing::info!(%url, "demo: would open the site in the default browser");
        self.opened.borrow_mut().push(url);
        Ok(())
    }
}
