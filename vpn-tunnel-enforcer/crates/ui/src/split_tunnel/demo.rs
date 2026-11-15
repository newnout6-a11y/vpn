//! A fake split-tunnel service for `demo_lists` and the tests: the apps of the reference
//! screenshot plus a legacy row with a broken path and a CJK path, small delays so pending
//! states show.
//!
//! Scenes: `full` (default), `empty`, `loading` (the first read never ends), `failed` (the first
//! read fails, «Повторить» works), `errors` (every action fails), `only` (only the listed apps
//! use the VPN), `only-empty` (the same with nothing listed), `old-service` (`only` with a
//! helper service too old for it).
mod routing;

use std::cell::{Cell, RefCell};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::watch;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

use super::model::{AppKind, AppRule, AppScope, SplitApp, SplitSnapshot, SplitTunnelApi};
use super::routing::{RoutingImported, RoutingOffer, RoutingPreview, RoutingSource};
use crate::widgets::{Load, UiError};

/// A 16×16 PNG (dark square, signal frame) so the image path of the icon cell shows.
const DEMO_ICON: &str = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAJUlEQVR42mNgGDTgfwDDf1IwVgM0NDSIwqMGjBpAWwMoSsoDBgAxj/flpucKyAAAAABJRU5ErkJggg==";

/// The demo backend.
pub struct DemoSplitTunnel {
    tx: watch::Sender<SplitSnapshot>,
    apps: RefCell<Vec<SplitApp>>,
    found_on_rescan: RefCell<Vec<SplitApp>>,
    picks: RefCell<Vec<SplitApp>>,
    fail_actions: bool,
    next_id: Cell<u32>,
    delay: Duration,
    offers: Vec<RoutingOffer>,
    /// The latest routing preview (its token is the one `import_routing` takes).
    preview: RefCell<Option<RoutingPreview>>,
    tokens: Cell<u64>,
    smart_ru_on: Cell<bool>,
    scope: Cell<AppScope>,
    /// The running session keeps the scope it started with (scene `pending`).
    started_with: Option<AppScope>,
    proxy: bool,
    older_service: bool,
}

fn app(id: &str, name: &str, path: &str, rule: AppRule) -> SplitApp {
    SplitApp {
        id: id.into(),
        name: name.into(),
        path: path.into(),
        icon: None,
        rule,
        kind: AppKind::App,
    }
}

fn process(id: &str, name: &str) -> SplitApp {
    SplitApp {
        kind: AppKind::Process,
        ..app(id, name, name, AppRule::Direct)
    }
}

impl DemoSplitTunnel {
    /// A demo in `scene` (unknown scenes behave like `full`).
    pub fn new(scene: &str) -> Self {
        let apps = if matches!(scene, "empty" | "only-empty") {
            Vec::new()
        } else {
            vec![
                SplitApp {
                    icon: Some(DEMO_ICON.into()),
                    ..app(
                        "a1",
                        "Google Chrome",
                        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                        AppRule::Vpn,
                    )
                },
                app(
                    "a2",
                    "Mozilla Firefox",
                    r"C:\Program Files\Mozilla Firefox\firefox.exe",
                    AppRule::Vpn,
                ),
                app(
                    "a3",
                    "Telegram Desktop",
                    r"C:\Users\demo\AppData\Roaming\Telegram Desktop\Telegram.exe",
                    AppRule::Vpn,
                ),
                app(
                    "a4",
                    "Discord",
                    r"C:\Users\demo\AppData\Local\Discord\app-1.0.9200\Discord.exe",
                    AppRule::Vpn,
                ),
                app(
                    "a5",
                    "Steam",
                    r"C:\Program Files (x86)\Steam\steam.exe",
                    AppRule::Direct,
                ),
                app(
                    "a6",
                    "Demo Bank Online",
                    r"C:\Program Files\Demo Bank\bank.exe",
                    AppRule::Direct,
                ),
                app(
                    "a7",
                    "Visual Studio Code",
                    r"C:\Users\demo\AppData\Local\Programs\Microsoft VS Code\Code.exe",
                    AppRule::None,
                ),
                app(
                    "a8",
                    "Яндекс Музыка",
                    "C:\\Users\\demo\\AppData\\Local\\Programs\\\u{FFFD}\u{FFFD}\\\u{FFFD}.exe",
                    AppRule::None,
                ),
                app(
                    "a9",
                    "NetEase Cloud Music",
                    r"C:\Program Files\网易云音乐\cloudmusic.exe",
                    AppRule::None,
                ),
                process("p1", "git.exe"),
                process("p2", "curl.exe"),
            ]
        };
        let demo = Self {
            tx: watch::Sender::new(SplitSnapshot::default()),
            apps: RefCell::new(apps),
            found_on_rescan: RefCell::new(vec![app(
                "a10",
                "Notepad++",
                r"C:\Program Files\Notepad++\notepad++.exe",
                AppRule::None,
            )]),
            picks: RefCell::new(vec![app(
                "a11",
                "Spotify",
                r"C:\Users\demo\AppData\Roaming\Spotify\Spotify.exe",
                AppRule::None,
            )]),
            fail_actions: scene == "errors",
            next_id: Cell::new(1),
            delay: Duration::from_millis(500),
            offers: routing::offers(scene),
            preview: RefCell::new(None),
            tokens: Cell::new(0),
            smart_ru_on: Cell::new(false),
            scope: Cell::new(match scene {
                "only" | "only-empty" | "old-service" | "proxy" => AppScope::OnlyListed,
                _ => AppScope::All,
            }),
            started_with: (scene == "pending").then_some(AppScope::All),
            proxy: scene == "proxy",
            older_service: scene == "old-service",
        };
        match scene {
            "loading" => {}
            "failed" => {
                demo.tx.send_replace(SplitSnapshot {
                    apps: Load::Failed(UiError::from(AppError::new(ErrorKind::Internal))),
                    offers: demo.offers.clone(),
                    ..SplitSnapshot::default()
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
        self.tx.send_replace(SplitSnapshot {
            apps: Load::Ready(self.apps.borrow().clone()),
            offers: self.offers.clone(),
            scope: self.scope.get(),
            pending: self.started_with.is_some_and(|run| run != self.scope.get()),
            proxy: self.proxy,
            older_service: self.older_service,
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

    fn fresh_id(&self) -> String {
        format!("new-{}", self.next_id.replace(self.next_id.get() + 1))
    }
}

/// The service's process-name rule (routing §2.3), for the fake: quotes stripped, the leaf of
/// a pasted path, no forbidden characters or spaces, `.exe` appended, lower case.
pub fn normalize_process(raw: &str) -> Option<String> {
    let unquoted = raw.trim().trim_matches(|c| c == '"' || c == '\'');
    let leaf = unquoted.rsplit(['\\', '/']).next().unwrap_or_default();
    let bad = |c: char| "<>:\"/\\|?*".contains(c) || c.is_whitespace();
    if leaf.is_empty() || leaf.chars().any(bad) {
        return None;
    }
    let name = if leaf.contains('.') {
        leaf.to_owned()
    } else {
        format!("{leaf}.exe")
    };
    Some(name.to_lowercase())
}

#[async_trait(?Send)]
impl SplitTunnelApi for DemoSplitTunnel {
    fn state(&self) -> watch::Receiver<SplitSnapshot> {
        self.tx.subscribe()
    }

    async fn reload(&self) -> AppResult<()> {
        if !self.delay.is_zero() {
            tokio::time::sleep(self.delay).await;
        }
        self.publish();
        Ok(())
    }

    async fn refresh(&self) -> AppResult<usize> {
        self.pause().await?;
        self.pause().await?;
        let found: Vec<SplitApp> = self.found_on_rescan.borrow_mut().drain(..).collect();
        let added = found.len();
        self.apps.borrow_mut().extend(found);
        self.publish();
        Ok(added)
    }

    async fn add_app(&self) -> AppResult<Option<SplitApp>> {
        self.pause().await?;
        let Some(pick) = self.picks.borrow_mut().pop() else {
            // The next «dialog» is dismissed.
            return Ok(None);
        };
        self.apps.borrow_mut().push(pick.clone());
        self.publish();
        Ok(Some(pick))
    }

    async fn add_process(&self, name: String) -> AppResult<SplitApp> {
        self.pause().await?;
        let name = normalize_process(&name)
            .ok_or_else(|| AppError::validation(Msg::new("splitTunneling.invalidProcess")))?;
        let entry = {
            let mut apps = self.apps.borrow_mut();
            let existing = apps
                .iter_mut()
                .find(|a| a.kind == AppKind::Process && a.path.eq_ignore_ascii_case(&name));
            match existing {
                Some(found) => {
                    found.rule = AppRule::Direct;
                    found.clone()
                }
                None => {
                    let entry = process(&self.fresh_id(), &name);
                    apps.push(entry.clone());
                    entry
                }
            }
        };
        self.publish();
        Ok(entry)
    }

    async fn set_rule(&self, id: String, rule: AppRule) -> AppResult<()> {
        self.pause().await?;
        let mut apps = self.apps.borrow_mut();
        let app = apps
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or_else(|| AppError::new(ErrorKind::Conflict))?;
        app.rule = rule;
        drop(apps);
        self.publish();
        Ok(())
    }

    async fn set_scope(&self, scope: AppScope) -> AppResult<()> {
        self.pause().await?;
        self.scope.set(scope);
        self.publish();
        Ok(())
    }

    async fn remove(&self, id: String) -> AppResult<()> {
        self.pause().await?;
        self.apps.borrow_mut().retain(|a| a.id != id);
        self.publish();
        Ok(())
    }

    async fn preview_routing(&self, source: RoutingSource) -> AppResult<RoutingPreview> {
        self.pause().await?;
        let token = self.tokens.get() + 1;
        self.tokens.set(token);
        let preview = routing::preview(&source, token, self.smart_ru_on.get());
        *self.preview.borrow_mut() = Some(preview.clone());
        Ok(preview)
    }

    async fn import_routing(&self, token: u64) -> AppResult<RoutingImported> {
        self.pause().await?;
        let done = routing::import(self.preview.borrow().as_ref(), token)?;
        // The plan is spent: a second click on the same preview asks for a new one.
        *self.preview.borrow_mut() = None;
        self.smart_ru_on
            .set(self.smart_ru_on.get() || done.smart_ru_on);
        Ok(done)
    }
}
