//! What the root component takes over from [`super::run`] and keeps when a WebView2 crash
//! rebuilds the window (a new window with a new VirtualDom, `vpnte_ui::launch`): the receiver of
//! in-app notices is lent to the mounted root's pump. It sits behind an async mutex: a rebuilt
//! root's pump waits until the dropped one let go, and whatever arrives while no window is mounted
//! waits in its channel for the next one. The page shown is remembered, so a rebuilt window opens
//! on it. Commands of later launches and toast clicks do not come here: they never wait for a
//! VirtualDom (`super::commands`, the window bell).
use std::cell::Cell;
use std::rc::Rc;

use dioxus::prelude::*;
use tokio::sync::Mutex;
use tokio::sync::broadcast::{self, error::RecvError};
use vpnte_ui::pages::Page;

use crate::svc_core::notify::InAppNotice;

pub(crate) struct Inbox {
    /// The notifier's in-app list, subscribed before the first window exists.
    notices: Mutex<broadcast::Receiver<InAppNotice>>,
    /// The page shown last.
    page: Cell<Page>,
}

impl Inbox {
    pub(crate) fn new(notices: broadcast::Receiver<InAppNotice>) -> Inbox {
        Inbox {
            notices: Mutex::new(notices),
            page: Cell::new(Page::Dashboard),
        }
    }

    /// The page a (rebuilt) window opens on.
    pub(crate) fn page(&self) -> Page {
        self.page.get()
    }

    pub(crate) fn keep_page(&self, page: Page) {
        self.page.set(page);
    }
}

/// Runs `on` for each in-app notice while the caller is mounted.
pub(crate) fn use_notices(inbox: &Rc<Inbox>, on: impl FnMut(InAppNotice) + Clone + 'static) {
    let inbox = inbox.clone();
    use_future(move || {
        let (inbox, mut on) = (inbox.clone(), on.clone());
        async move {
            let mut list = inbox.notices.lock().await;
            loop {
                match list.recv().await {
                    Ok(item) => on(item),
                    Err(RecvError::Lagged(missed)) => {
                        tracing::warn!(missed, "in-app notices dropped (window busy)");
                    }
                    Err(RecvError::Closed) => return,
                }
            }
        }
    });
}

#[cfg(test)]
mod tests;
