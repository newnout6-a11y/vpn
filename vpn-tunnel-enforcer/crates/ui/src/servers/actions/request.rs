//! The subscription request settings (ru-2026 item 1): the HWID switch and the extra headers.
use dioxus::prelude::*;

use crate::lang::translate_now;
use crate::servers::state::RequestForm;
use crate::widgets::UiError;

use super::{Actions, toast_error};

impl Actions {
    /// Opens the request dialog of subscription `id`.
    pub fn open_request(&self, id: &str, name: &str) {
        let mut request = self.store.request;
        request.set(Some(RequestForm {
            group: id.to_owned(),
            name: name.to_owned(),
            ..RequestForm::default()
        }));
    }

    /// Turns the subscription's HWID on or off; `refresh` fetches it right after (the empty-list
    /// hint's button: the user wants to see whether the panel answers now).
    pub fn set_send_hwid(&self, id: &str, on: bool, refresh: bool) {
        let (store, toasts, api) = (self.store, self.toasts, self.api.clone());
        if store.busy.peek().get(id).is_some_and(|b| b.policy) {
            return;
        }
        let id = id.to_owned();
        let actions = self.clone();
        store.group_busy(&id, |b| b.policy = true);
        self.spawn(async move {
            let result = api.set_send_hwid(&id, on).await;
            store.group_busy(&id, |b| b.policy = false);
            match result {
                Ok(()) if refresh => {
                    let name = store
                        .view
                        .peek()
                        .groups
                        .iter()
                        .find(|g| g.id == id)
                        .map(|g| g.name.clone());
                    actions.refresh_group(&id, &name.unwrap_or_default());
                }
                Ok(()) => {}
                Err(err) => {
                    let title = translate_now("ui.servers.request.failed", &[]);
                    toast_error(toasts, title, &err);
                }
            }
        });
    }

    /// Saves the dialog's header draft (`clear`: removes every header instead); the dialog stays
    /// open with the names now set, or shows the field error.
    pub fn save_headers(&self, clear: bool) {
        let (api, mut request) = (self.api.clone(), self.store.request);
        let Some((id, lines)) = request.peek().as_ref().filter(|f| !f.busy).map(|f| {
            let lines = if clear {
                String::new()
            } else {
                f.headers.clone()
            };
            (f.group.clone(), lines)
        }) else {
            return;
        };
        if let Some(f) = request.write().as_mut() {
            f.busy = true;
            f.error = None;
        }
        self.spawn(async move {
            let result = api.set_request_headers(&id, lines).await;
            if let Some(f) = request.write().as_mut().filter(|f| f.group == id) {
                f.busy = false;
                match result {
                    Ok(_) => f.headers.clear(),
                    Err(err) => f.error = Some(UiError::from(err)),
                }
            }
        });
    }
}
