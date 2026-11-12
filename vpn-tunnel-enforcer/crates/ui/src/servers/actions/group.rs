//! Group and import actions: host resolution, expanded groups, refresh, interval, health check,
//! rename, delete and add (import), with their toast texts.
use std::num::NonZeroU32;

use vpnte_base::ErrorKind;

use super::*;
use crate::lang::translate_now;
use crate::servers::model::{FetchError, ImportReport, RefreshOutcome};
use crate::servers::present::GROUP_NAME_MAX;
use crate::widgets::UiError;

impl Actions {
    /// Re-resolves hosts for the IP column (after imports, refreshes and deletes; never polled).
    pub fn resolve_ips(&self) {
        let api = self.api.clone();
        self.spawn(async move {
            if let Err(err) = api.resolve_ips().await {
                tracing::debug!(error = %err, "resolving server hosts failed");
            }
        });
    }

    pub fn toggle_expanded(&self, id: &str) {
        let mut expanded = self.store.expanded;
        {
            let mut ids = expanded.write();
            match ids.iter().position(|e| e == id) {
                Some(at) => {
                    ids.remove(at);
                }
                None => ids.push(id.to_owned()),
            }
        }
        self.save_expanded();
    }

    pub fn save_expanded(&self) {
        let (api, ids) = (self.api.clone(), self.store.expanded.peek().clone());
        self.spawn(async move {
            if let Err(err) = api.save_expanded_groups(ids).await {
                tracing::debug!(error = %err, "saving expanded groups failed");
            }
        });
    }

    pub fn refresh_group(&self, id: &str, name: &str) {
        let (store, toasts, api, actions) =
            (self.store, self.toasts, self.api.clone(), self.clone());
        if store.busy.peek().get(id).is_some_and(|b| b.refresh) {
            return;
        }
        let (id, name) = (id.to_owned(), name.to_owned());
        store.group_busy(&id, |b| b.refresh = true);
        self.spawn(async move {
            let result = api.refresh_group(&id).await;
            store.group_busy(&id, |b| b.refresh = false);
            let failed = translate_now("servers.groups.refreshFailed", &[]);
            match result {
                Ok(RefreshOutcome::Refreshed {
                    added,
                    updated,
                    removed,
                    expired,
                }) => {
                    let body = translate_now(
                        "servers.groups.refreshOk",
                        &[
                            ("added", added.to_string()),
                            ("updated", updated.to_string()),
                            ("removed", removed.to_string()),
                        ],
                    );
                    toasts.success(name.clone(), Some(body));
                    if expired {
                        toasts.warning(
                            name,
                            Some(translate_now("servers.groups.expiredBannerToast", &[])),
                        );
                    }
                    actions.resolve_ips();
                }
                Ok(RefreshOutcome::Failed(why)) => {
                    toasts.error(failed, Some(fetch_error_text(why)));
                }
                Err(err) => toast_error(toasts, failed, &err),
            }
        });
    }

    /// Ignores re-picking the current value and a change while one is saved (S-18).
    pub fn set_interval(&self, id: &str, current: Option<NonZeroU32>, next: Option<NonZeroU32>) {
        let (store, toasts, api) = (self.store, self.toasts, self.api.clone());
        if next == current || store.busy.peek().get(id).is_some_and(|b| b.policy) {
            return;
        }
        let id = id.to_owned();
        store.group_busy(&id, |b| b.policy = true);
        self.spawn(async move {
            let result = api.set_refresh_interval(&id, next).await;
            store.group_busy(&id, |b| b.policy = false);
            if let Err(err) = result {
                toast_error(
                    toasts,
                    translate_now("ui.servers.group.intervalFailed", &[]),
                    &err,
                );
            }
        });
    }

    pub fn check_health(&self, id: &str, name: &str) {
        let (store, toasts, api) = (self.store, self.toasts, self.api.clone());
        if store.busy.peek().get(id).is_some_and(|b| b.health) {
            return;
        }
        let (id, name) = (id.to_owned(), name.to_owned());
        store.group_busy(&id, |b| b.health = true);
        self.spawn(async move {
            let result = api.check_group_health(&id).await;
            store.group_busy(&id, |b| b.health = false);
            match result {
                Ok(report) => {
                    let alive = report.results.iter().filter(|(_, h)| h.online).count();
                    let total = report.results.len();
                    for (sid, health) in report.results {
                        store.row(&sid, |r| r.health = Some(health));
                    }
                    let mut body = translate_now(
                        "servers.health.aliveCount",
                        &[("count", alive.to_string()), ("total", total.to_string())],
                    );
                    // Keys left unchecked are named, never folded into the total as if checked.
                    if report.not_checked > 0 {
                        let count = report.not_checked.to_string();
                        body.push_str(". ");
                        body.push_str(&translate_now(
                            "ui.servers.verdict.notChecked",
                            &[("count", count)],
                        ));
                    }
                    toasts.info(name, Some(body));
                }
                Err(err) => toast_error(toasts, name, &err),
            }
        });
    }

    /// Saves the rename draft (Enter / blur): trimmed, capped at 60; empty or unchanged = no call.
    pub fn commit_rename(&self) {
        let mut rename = self.store.rename;
        let Some((id, draft)) = rename.take() else {
            return;
        };
        let next: String = draft.trim().chars().take(GROUP_NAME_MAX as usize).collect();
        let current = self
            .store
            .view
            .peek()
            .groups
            .iter()
            .find(|g| g.id == id)
            .map(|g| g.name.clone());
        if next.is_empty() || current.is_none() || current.as_deref() == Some(next.as_str()) {
            return;
        }
        let (toasts, api) = (self.toasts, self.api.clone());
        self.spawn(async move {
            if let Err(err) = api.rename_group(&id, next).await {
                toast_error(
                    toasts,
                    translate_now("ui.servers.group.renameFailed", &[]),
                    &err,
                );
            }
        });
    }

    /// Deletes a group (also a recovered one) after its confirmation.
    pub fn delete_group(&self, id: String, name: String, delete_servers: bool) {
        let (store, toasts, api, actions) =
            (self.store, self.toasts, self.api.clone(), self.clone());
        let (mut busy, mut confirm) = (store.confirm_busy, store.confirm);
        busy.set(true);
        self.spawn(async move {
            let result = api.delete_group(&id, delete_servers).await;
            busy.set(false);
            confirm.set(None);
            match result {
                Ok(()) => {
                    let mut expanded = store.expanded;
                    expanded.write().retain(|e| e != &id);
                    actions.save_expanded();
                    actions.resolve_ips();
                }
                Err(err) => {
                    let title = translate_now("ui.servers.group.deleteFailed", &[("name", name)]);
                    toast_error(toasts, title, &err);
                }
            }
        });
    }

    /// Imports the add form's input. The run belongs to the page: closing the dialog does not
    /// stop it; its outcome then arrives as a toast.
    pub fn add(&self) {
        let (store, toasts, api, actions) =
            (self.store, self.toasts, self.api.clone(), self.clone());
        let mut form = store.add;
        let (input, target, device, request) = {
            let f = form.peek();
            if f.busy || f.input.trim().is_empty() {
                return;
            }
            let draft = (f.input.trim().to_owned(), f.target.clone());
            (draft.0, draft.1, f.device, f.request.clone())
        };
        {
            let mut f = form.write();
            f.busy = true;
            f.error = None;
            f.report = None;
        }
        self.spawn(async move {
            let result = api.add(input, target, device, request).await;
            let open = *store.add_open.peek();
            let mut f = form.write();
            f.busy = false;
            match result {
                Ok(report) => {
                    f.imported();
                    // A closed dialog got its toast; reopening it starts with an empty form.
                    if open {
                        f.report = Some(report);
                    } else {
                        let title = translate_now("ui.servers.add.doneTitle", &[]);
                        toasts.success(title, Some(import_summary(&report)));
                    }
                    actions.resolve_ips();
                }
                Err(err) if err.kind == ErrorKind::Cancelled => {}
                Err(err) => {
                    if !open {
                        toast_error(
                            toasts,
                            translate_now("ui.servers.add.failedTitle", &[]),
                            &err,
                        );
                    }
                    f.error = Some(UiError::from(err));
                }
            }
        });
    }

    /// Copies a short ready-made request for the plain subscription link (the answer to an
    /// encrypted app link) in the page's language.
    pub fn copy_provider_request(&self) {
        let (toasts, api) = (self.toasts, self.api.clone());
        let text = translate_now("ui.servers.add.requestText", &[]);
        self.spawn(async move {
            match api.copy_text(text).await {
                Ok(()) => {
                    toasts.success(translate_now("ui.servers.add.requestCopied", &[]), None);
                }
                Err(err) => {
                    toast_error(
                        toasts,
                        translate_now("ui.servers.add.copyFailed", &[]),
                        &err,
                    );
                }
            }
        });
    }
}

/// The people's wording of a failed subscription refresh (typed, S-4).
pub(crate) fn fetch_error_text(why: FetchError) -> String {
    match why {
        FetchError::Empty => translate_now("servers.groups.emptySubscription", &[]),
        FetchError::Invalid => translate_now("servers.groups.invalidSubscription", &[]),
        FetchError::Http(code) => {
            translate_now("ui.servers.fetch.http", &[("code", code.to_string())])
        }
        FetchError::Network => translate_now("ui.servers.fetch.network", &[]),
        FetchError::Tls => translate_now("ui.servers.fetch.tls", &[]),
        FetchError::Timeout => translate_now("ui.servers.fetch.timeout", &[]),
        FetchError::Refused => translate_now("ui.servers.fetch.refused", &[]),
        FetchError::HwidRequired => translate_now("ui.servers.fetch.hwidRequired", &[]),
        FetchError::DeviceLimit => translate_now("ui.servers.fetch.deviceLimit", &[]),
    }
}

/// «Добавлено: 3 · обновлено: 1 · пропущено: 2 → Ручные ключи».
pub(crate) fn import_summary(report: &ImportReport) -> String {
    translate_now(
        "ui.servers.add.summary",
        &[
            ("added", report.added.to_string()),
            ("updated", report.updated.to_string()),
            ("skipped", report.skipped.len().to_string()),
            ("group", report.group_name.clone()),
        ],
    )
}
