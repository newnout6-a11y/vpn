//! A fake [`UpdatesApi`] with realistic data (tests and demos): a newer app version, a tested
//! sing-box version, one updated engine, a last check through the VPN.
use std::collections::BTreeMap;

use tokio::sync::watch;
use vpnte_base::{AppResult, Msg};

use super::UpdatesApi;
use super::model::{
    AppOffer, CheckLine, CheckResult, EngineOffer, EngineRow, Note, UpdateOutcome, UpdatesView,
};

/// The demo backend: every action changes the pushed view the way the app would.
pub struct DemoUpdates {
    state: watch::Sender<UpdatesView>,
}

impl DemoUpdates {
    /// The default scene (see the module docs).
    pub fn new() -> Self {
        Self::with_view(sample())
    }

    /// A scene of the caller's choice.
    pub fn with_view(view: UpdatesView) -> Self {
        Self {
            state: watch::Sender::new(view),
        }
    }

    fn change(&self, f: impl FnOnce(&mut UpdatesView)) -> AppResult<()> {
        self.state.send_modify(f);
        Ok(())
    }
}

impl Default for DemoUpdates {
    fn default() -> Self {
        Self::new()
    }
}

fn notes(ru: &str, en: &str) -> BTreeMap<String, String> {
    [
        ("ru".to_owned(), ru.to_owned()),
        ("en".to_owned(), en.to_owned()),
    ]
    .into()
}

/// The default scene.
pub fn sample() -> UpdatesView {
    UpdatesView {
        ready: true,
        auto_check: true,
        download_ahead: false,
        skipped: Vec::new(),
        last_check: Some(CheckLine {
            at: 1_794_480_000_000,
            host: Some("raw.githubusercontent.com".into()),
            via_vpn: true,
            result: CheckResult::Found,
        }),
        checking: false,
        app: Some(AppOffer {
            version: "2.0.1".into(),
            notes: notes(
                "Быстрее переподключение после сна.",
                "Faster reconnect after sleep.",
            ),
            security: false,
            can_skip: true,
        }),
        engines: vec![EngineOffer {
            id: "sing-box".into(),
            name: "sing-box".into(),
            from: "1.14.4".into(),
            to: "1.14.5".into(),
            tested_on: Some("2026-11-12".into()),
            notes: notes(
                "Исправлен DNS при смене сети.",
                "DNS fixed on network change.",
            ),
        }],
        installed: vec![
            EngineRow {
                id: "sing-box".into(),
                name: "sing-box".into(),
                version: "1.14.4".into(),
                updated_on: None,
                previous: None,
                can_restore_bundled: false,
            },
            EngineRow {
                id: "xray".into(),
                name: "Xray".into(),
                version: "26.11.20".into(),
                updated_on: Some("2026-11-10".into()),
                previous: Some("26.11.9".into()),
                can_restore_bundled: true,
            },
        ],
        rollback_to: None,
        outcome: None,
        progress: None,
        note: None,
    }
}

#[async_trait::async_trait(?Send)]
impl UpdatesApi for DemoUpdates {
    fn state(&self) -> watch::Receiver<UpdatesView> {
        self.state.subscribe()
    }
    async fn check_now(&self) -> AppResult<()> {
        self.change(|v| {
            if let Some(line) = v.last_check.as_mut() {
                line.at += 60_000;
            }
        })
    }
    async fn update_app(&self) -> AppResult<()> {
        self.change(|v| {
            let version = v.app.take().map(|a| a.version).unwrap_or_default();
            v.outcome = Some(UpdateOutcome::Updated { version });
        })
    }
    async fn rollback_app(&self) -> AppResult<()> {
        self.change(|v| v.rollback_to = None)
    }
    async fn later_app(&self) -> AppResult<()> {
        self.change(|v| v.app = None)
    }
    async fn skip_app(&self) -> AppResult<()> {
        self.change(|v| {
            if let Some(app) = v.app.take() {
                v.skipped.push(app.version);
            }
        })
    }
    async fn install_engine(&self, id: String) -> AppResult<()> {
        self.change(|v| {
            let Some(at) = v.engines.iter().position(|e| e.id == id) else {
                return;
            };
            let offer = v.engines.remove(at);
            if let Some(row) = v.installed.iter_mut().find(|r| r.id == id) {
                row.previous = Some(std::mem::replace(&mut row.version, offer.to.clone()));
                row.updated_on = Some("2026-11-13".into());
                row.can_restore_bundled = true;
            }
            v.note = Some(Note {
                msg: Msg::new("ui.update.demoInstalled")
                    .arg("name", offer.name)
                    .arg("version", offer.to),
                warn: false,
                switch_now: true,
            });
        })
    }
    async fn later_engine(&self, id: String) -> AppResult<()> {
        self.change(|v| v.engines.retain(|e| e.id != id))
    }
    async fn revert_previous(&self, id: String) -> AppResult<()> {
        self.change(|v| {
            if let Some(row) = v.installed.iter_mut().find(|r| r.id == id)
                && let Some(previous) = row.previous.take()
            {
                row.previous = Some(std::mem::replace(&mut row.version, previous));
            }
        })
    }
    async fn revert_bundled(&self, id: String) -> AppResult<()> {
        self.change(|v| {
            if let Some(row) = v.installed.iter_mut().find(|r| r.id == id) {
                row.can_restore_bundled = false;
                row.updated_on = None;
            }
        })
    }
    async fn set_auto_check(&self, on: bool) -> AppResult<()> {
        self.change(|v| v.auto_check = on)
    }
    async fn set_download_ahead(&self, on: bool) -> AppResult<()> {
        self.change(|v| v.download_ahead = on)
    }
    async fn reset_skipped(&self) -> AppResult<()> {
        self.change(|v| v.skipped.clear())
    }
    async fn retry_installer(&self) -> AppResult<()> {
        self.change(|v| v.outcome = None)
    }
    async fn dismiss(&self) -> AppResult<()> {
        self.change(|v| {
            v.outcome = None;
            v.note = None;
        })
    }
    async fn switch_engine_now(&self) -> AppResult<()> {
        self.change(|v| v.note = None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The demo behaves like the app: «Пропустить» moves the version to the skipped list, an
    /// engine install updates its row and leaves one calm note.
    #[tokio::test]
    async fn actions_change_the_view() {
        let demo = DemoUpdates::new();
        let rx = demo.state();
        demo.skip_app().await.unwrap();
        assert!(rx.borrow().app.is_none());
        assert_eq!(rx.borrow().skipped, ["2.0.1"]);
        demo.install_engine("sing-box".into()).await.unwrap();
        let view = rx.borrow().clone();
        assert!(view.engines.is_empty());
        assert_eq!(view.installed[0].version, "1.14.5");
        assert_eq!(view.installed[0].previous.as_deref(), Some("1.14.4"));
        assert_eq!(
            view.note.as_ref().map(|n| n.msg.key.as_ref()),
            Some("ui.update.demoInstalled")
        );
        // p-follow: a running session is offered the switch now; taking it ends the note.
        assert!(view.note.is_some_and(|n| n.switch_now));
        demo.switch_engine_now().await.unwrap();
        assert!(rx.borrow().note.is_none());
    }
}
