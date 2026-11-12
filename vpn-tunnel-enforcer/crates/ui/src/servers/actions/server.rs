//! Per-server actions: proxies, key export, select and switch, remove / restore / purge, the
//! server's own engine, bulk export, with their toast texts.
use vpnte_base::ErrorKind;
use vpnte_base::types::EnginePref;

use super::*;
use crate::lang::{tr_now, translate_now};
use crate::servers::model::{ProxySkip, ProxyStartReport, ServerView};
use crate::servers::state::{Bulk, BulkKind};
use crate::widgets::UiError;

/// The outcome line of a proxy start for one server (decision order of the old page).
pub(crate) fn proxy_outcome(
    report: &ProxyStartReport,
    id: &str,
) -> (crate::widgets::ToastKind, String) {
    use crate::widgets::ToastKind;
    if let Some(started) = report.started.first() {
        let listen = started
            .listen
            .clone()
            .unwrap_or_else(|| translate_now("ui.servers.proxy.starting", &[]));
        let body = translate_now(
            "ui.servers.proxy.started",
            &[("slot", started.slot.to_string()), ("listen", listen)],
        );
        (ToastKind::Success, body)
    } else if report.already_running.iter().any(|r| r == id) {
        (
            ToastKind::Info,
            translate_now("ui.servers.proxy.alreadyRunning", &[]),
        )
    } else if report
        .skipped
        .iter()
        .any(|(_, why)| *why == ProxySkip::ActiveVpn)
    {
        (
            ToastKind::Warning,
            translate_now("ui.servers.proxy.activeVpn", &[]),
        )
    } else if let Some((_, msg)) = report.failed.first() {
        (ToastKind::Error, tr_now(msg))
    } else {
        (
            ToastKind::Warning,
            translate_now("ui.servers.proxy.unavailable", &[]),
        )
    }
}

/// «Запущено: 2, уже работали: 1, пропущено: 1» and the toast kind of a group start.
pub(crate) fn proxies_summary(report: &ProxyStartReport) -> (crate::widgets::ToastKind, String) {
    use crate::widgets::ToastKind;
    let count = |n: usize| n.to_string();
    let mut parts = vec![translate_now(
        "ui.servers.proxy.summaryStarted",
        &[("count", count(report.started.len()))],
    )];
    if !report.already_running.is_empty() {
        parts.push(translate_now(
            "ui.servers.proxy.summaryRunning",
            &[("count", count(report.already_running.len()))],
        ));
    }
    if !report.skipped.is_empty() {
        parts.push(translate_now(
            "ui.servers.proxy.summarySkipped",
            &[("count", count(report.skipped.len()))],
        ));
    }
    if !report.failed.is_empty() {
        parts.push(translate_now(
            "ui.servers.proxy.summaryFailed",
            &[("count", count(report.failed.len()))],
        ));
    }
    let kind = if !report.failed.is_empty() {
        ToastKind::Warning
    } else if !report.started.is_empty() {
        ToastKind::Success
    } else {
        ToastKind::Info
    };
    (kind, parts.join(", "))
}

impl Actions {
    pub fn start_proxy(&self, server: &ServerView) {
        let (store, toasts, api) = (self.store, self.toasts, self.api.clone());
        let (id, name) = (server.id.clone(), server.name.clone());
        store.row(&id, |r| r.starting_proxy = true);
        self.spawn(async move {
            let result = api.start_proxies(vec![id.clone()]).await;
            store.row(&id, |r| r.starting_proxy = false);
            match result {
                Ok(report) => {
                    let (kind, body) = proxy_outcome(&report, &id);
                    toasts.push(kind, name, Some(body));
                }
                Err(err) => toast_error(toasts, name, &err),
            }
        });
    }

    /// Starts a proxy for each current (not removed) server of a group.
    pub fn start_group_proxies(&self, group_id: &str, group_name: &str, ids: Vec<String>) {
        if ids.is_empty() {
            return;
        }
        let (store, toasts, api) = (self.store, self.toasts, self.api.clone());
        let (gid, title) = (
            group_id.to_owned(),
            translate_now(
                "ui.servers.proxy.groupTitle",
                &[("name", group_name.to_owned())],
            ),
        );
        store.group_busy(&gid, |b| b.proxies = true);
        self.spawn(async move {
            let result = api.start_proxies(ids).await;
            store.group_busy(&gid, |b| b.proxies = false);
            match result {
                Ok(report) => {
                    let (kind, body) = proxies_summary(&report);
                    toasts.push(kind, title, Some(body));
                }
                Err(err) => toast_error(toasts, title, &err),
            }
        });
    }

    /// Copies or saves a share key; both outcomes are toasted (the old menu flashed labels inside
    /// a menu that had already closed, S-5), with the secret warning on success.
    pub fn export_key(&self, server: &ServerView, to_file: bool) {
        let (store, toasts, api) = (self.store, self.toasts, self.api.clone());
        let (id, name) = (server.id.clone(), server.name.clone());
        store.row(&id, |r| r.exporting = true);
        self.spawn(async move {
            let done = if to_file {
                api.save_key(&id)
                    .await
                    .map(|path| path.map(|p| translate_now("ui.servers.key.saved", &[("path", p)])))
            } else {
                api.copy_key(&id).await.map(|ttl| {
                    Some(translate_now(
                        "ui.servers.key.copied",
                        &[("seconds", ttl.as_secs().to_string())],
                    ))
                })
            };
            store.row(&id, |r| r.exporting = false);
            match done {
                Ok(Some(body)) => {
                    toasts.success(name, Some(body));
                }
                Ok(None) => {}
                Err(err) => toast_error(
                    toasts,
                    translate_now("ui.servers.key.failed", &[("name", name)]),
                    &err,
                ),
            }
        });
    }

    /// Selects a server; while connected this is a live switch the start page also shows. The
    /// marker moves only when the snapshot says so.
    pub fn select(&self, server: &ServerView) {
        let store = self.store;
        let view = store.view.peek();
        let blocked = store.selecting.peek().is_some()
            || view.switching_to.is_some()
            || view.tunnel_busy
            || view.active_id.as_deref() == Some(server.id.as_str());
        drop(view);
        if blocked {
            return;
        }
        let (toasts, api) = (self.toasts, self.api.clone());
        let (id, name) = (server.id.clone(), server.name.clone());
        let mut selecting = store.selecting;
        selecting.set(Some(id.clone()));
        self.spawn(async move {
            let result = api.select(&id).await;
            selecting.set(None);
            if let Err(err) = result {
                toast_error(
                    toasts,
                    translate_now("ui.servers.select.failed", &[("name", name)]),
                    &err,
                );
            }
        });
    }

    pub fn cancel_switch(&self) {
        let (toasts, api) = (self.toasts, self.api.clone());
        self.spawn(async move {
            if let Err(err) = api.cancel_switch().await {
                toast_error(
                    toasts,
                    translate_now("ui.servers.select.cancelFailed", &[]),
                    &err,
                );
            }
        });
    }

    /// Removes a server after its confirmation.
    pub fn remove(&self, id: String, name: String) {
        let (store, toasts, api) = (self.store, self.toasts, self.api.clone());
        let (mut busy, mut confirm) = (store.confirm_busy, store.confirm);
        busy.set(true);
        self.spawn(async move {
            let result = api.remove(&id).await;
            busy.set(false);
            confirm.set(None);
            match result {
                Ok(()) => {
                    let mut detail = store.detail;
                    if detail.peek().as_deref() == Some(id.as_str()) {
                        detail.set(None);
                    }
                }
                Err(err) => toast_error(
                    toasts,
                    translate_now("ui.servers.remove.failed", &[("name", name)]),
                    &err,
                ),
            }
        });
    }

    /// Brings a removed server back (no confirmation: nothing is lost).
    pub fn restore(&self, server: &ServerView) {
        let (store, toasts, api) = (self.store, self.toasts, self.api.clone());
        let (id, name) = (server.id.clone(), server.name.clone());
        store.row(&id, |r| r.restoring = true);
        self.spawn(async move {
            let result = api.restore(&id).await;
            store.row(&id, |r| r.restoring = false);
            if let Err(err) = result {
                toast_error(
                    toasts,
                    translate_now("ui.servers.restore.failed", &[("name", name)]),
                    &err,
                );
            }
        });
    }

    /// Sets the server's own engine (the connected server reconnects); a refusal comes back as
    /// a toast with the backend's reason.
    pub fn set_engine(&self, server: &ServerView, engine: EnginePref) {
        let (toasts, api) = (self.toasts, self.api.clone());
        let (id, name) = (server.id.clone(), server.name.clone());
        self.spawn(async move {
            if let Err(err) = api.set_engine(&id, engine).await {
                let title = translate_now("ui.servers.engine.failed", &[("name", name)]);
                toast_error(toasts, title, &err);
            }
        });
    }

    /// Deletes a removed server for good after its confirmation.
    pub fn purge(&self, id: String, name: String) {
        let (store, toasts, api) = (self.store, self.toasts, self.api.clone());
        let (mut busy, mut confirm) = (store.confirm_busy, store.confirm);
        busy.set(true);
        self.spawn(async move {
            let result = api.purge(&id).await;
            busy.set(false);
            confirm.set(None);
            if let Err(err) = result {
                toast_error(
                    toasts,
                    translate_now("ui.servers.remove.failed", &[("name", name)]),
                    &err,
                );
            }
        });
    }

    /// Bulk export of every key or of the proxy list, reported in the notice above the list.
    pub fn export_bulk(&self, kind: BulkKind) {
        let store = self.store;
        let mut bulk = store.bulk;
        if matches!(*bulk.peek(), Some(Bulk::Working(_))) {
            return;
        }
        bulk.set(Some(Bulk::Working(kind)));
        let api = self.api.clone();
        self.spawn(async move {
            let result = match kind {
                BulkKind::Keys => api.export_all_keys().await,
                BulkKind::Proxies => api.export_proxy_list().await,
            };
            bulk.set(match result {
                Ok(Some(report)) => Some(Bulk::Done(kind, report)),
                Ok(None) => None,
                Err(err) if err.kind == ErrorKind::Cancelled => None,
                Err(err) => Some(Bulk::Failed(kind, UiError::from(err))),
            });
        });
    }
}
