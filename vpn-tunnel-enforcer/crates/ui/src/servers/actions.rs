//! What the page's buttons do. Every task is spawned in the page root's scope (the shell keeps the
//! page mounted), so collapsing a group or leaving the page never drops a running ping, import,
//! refresh, health check or export; texts for toasts are rendered when the result lands.
use std::future::Future;
use std::rc::Rc;

use dioxus::core::{Runtime, Task};
use dioxus::prelude::*;
use tokio::sync::mpsc;
use vpnte_base::{AppError, ErrorKind};

use super::api::ServersApi;
use super::model::{CountryCheck, ServerView};
use super::state::Store;
use crate::lang::{tr_now, translate_now};
use crate::widgets::Toasts;

mod group;
mod request;
mod server;

pub(crate) use group::fetch_error_text;

/// Shows an action's error unless it was a cancellation (silent everywhere).
pub(crate) fn toast_error(toasts: Toasts, title: String, err: &AppError) {
    if err.kind != ErrorKind::Cancelled {
        toasts.error(title, Some(tr_now(&err.user_msg())));
    }
}

/// Handles the page parts share: the store, the backend and the toast queue.
#[derive(Clone)]
pub(crate) struct Actions {
    pub store: Store,
    pub api: Rc<dyn ServersApi>,
    pub toasts: Toasts,
}

impl Actions {
    /// Spawns `fut` in the page root's scope.
    pub fn spawn(&self, fut: impl Future<Output = ()> + 'static) -> Task {
        Runtime::current().in_scope(self.store.scope, || spawn(fut))
    }

    pub fn ping_one(&self, id: &str) {
        let store = self.store;
        let measuring = store
            .rows
            .peek()
            .get(id)
            .is_some_and(|r| r.ping.is_measuring());
        if measuring {
            return;
        }
        store.row(id, |r| r.ping = r.ping.measuring());
        let (api, id) = (self.api.clone(), id.to_owned());
        self.spawn(async move {
            let ms = api.ping_one(&id).await.unwrap_or(None);
            store.row(&id, |r| r.ping_done(ms));
        });
    }

    /// Pings every server five at a time; a second call cancels the run and puts the rows back.
    pub fn ping_all(&self) {
        let store = self.store;
        let mut running = store.ping_task;
        if let Some(task) = running.take() {
            task.cancel();
            self.restore_pings();
            return;
        }
        let ids: Vec<String> = store
            .view
            .peek()
            .servers
            .iter()
            .filter(|s| !s.host.is_empty() && s.port != 0)
            .map(|s| s.id.clone())
            .collect();
        if ids.is_empty() {
            return;
        }
        let mut before = store.ping_before;
        before.set(
            ids.iter()
                .map(|id| {
                    (
                        id.clone(),
                        store
                            .rows
                            .peek()
                            .get(id)
                            .map(|r| r.ping)
                            .unwrap_or_default(),
                    )
                })
                .collect(),
        );
        for id in &ids {
            store.row(id, |r| r.ping = r.ping.measuring());
        }
        let (api, actions) = (self.api.clone(), self.clone());
        let task = self.spawn(async move {
            let (tx, mut rx) = mpsc::unbounded_channel();
            let run = api.ping_many(ids, tx);
            futures_util::pin_mut!(run);
            loop {
                tokio::select! {
                    _ = &mut run => break,
                    Some((id, ms)) = rx.recv() => store.row(&id, |r| r.ping_done(ms)),
                }
            }
            while let Ok((id, ms)) = rx.try_recv() {
                store.row(&id, |r| r.ping_done(ms));
            }
            let mut running = store.ping_task;
            running.set(None);
            actions.restore_pings();
        });
        running.set(Some(task));
    }

    /// Rows a ping-all left measuring (cancelled, failed) get their previous state back.
    fn restore_pings(&self) {
        let store = self.store;
        let mut before = store.ping_before;
        for (id, prev) in before.take() {
            store.row(&id, |r| {
                if r.ping.is_measuring() {
                    r.ping = prev;
                }
            });
        }
    }

    pub fn verify_country(&self, server: &ServerView) {
        let (store, toasts, api) = (self.store, self.toasts, self.api.clone());
        let (id, name) = (server.id.clone(), server.name.clone());
        store.row(&id, |r| r.verifying = true);
        self.spawn(async move {
            let result = api.verify_country(&id).await;
            store.row(&id, |r| r.verifying = false);
            match result {
                Ok(CountryCheck::Verified(code)) => {
                    toasts.success(
                        name,
                        Some(translate_now(
                            "ui.servers.country.verified",
                            &[("country", code)],
                        )),
                    );
                }
                Ok(CountryCheck::GeoDisabled) => {
                    toasts.warning(
                        name,
                        Some(translate_now("ui.servers.country.geoDisabled", &[])),
                    );
                }
                Ok(CountryCheck::Failed) => {
                    toasts.warning(name, Some(translate_now("ui.servers.country.failed", &[])));
                }
                Err(err) => toast_error(toasts, name, &err),
            }
        });
    }
}
