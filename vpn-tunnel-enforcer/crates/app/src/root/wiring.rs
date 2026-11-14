//! What the root component takes over from [`super::run`] and keeps when a WebView2 crash
//! rebuilds the window (a new window with a new VirtualDom, `vpnte_ui::launch`): the receivers of
//! later launches' commands, toast clicks and in-app notices are lent to the mounted root's pumps.
//! Each sits behind an async mutex: a rebuilt root's pump waits until the dropped one let go, and
//! whatever arrives while no window is mounted waits in its channel for the next one. The page
//! shown is remembered, so a rebuilt window opens on it.
use std::cell::{Cell, RefCell};
use std::rc::Rc;

use dioxus::prelude::*;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{Mutex, broadcast, mpsc};
use vpnte_ui::pages::Page;
use vpnte_winnet::single_instance::Command;

use crate::svc_core::notify::InAppNotice;

pub(crate) struct Inbox {
    /// Commands of later launches (`activate`, a link, `shutdown-for-update`); `None` without
    /// the single-instance pipe.
    commands: Mutex<Option<mpsc::UnboundedReceiver<Command>>>,
    /// Clicks on a Windows toast while it is on screen.
    clicks: Mutex<mpsc::UnboundedReceiver<()>>,
    /// The notifier's in-app list, subscribed before the first window exists.
    notices: Mutex<broadcast::Receiver<InAppNotice>>,
    /// The link this process was started with (RU-2026 item 4), until a root hands it over.
    first_link: RefCell<Option<String>>,
    /// The page shown last.
    page: Cell<Page>,
}

impl Inbox {
    pub(crate) fn new(
        commands: Option<mpsc::UnboundedReceiver<Command>>,
        clicks: mpsc::UnboundedReceiver<()>,
        notices: broadcast::Receiver<InAppNotice>,
    ) -> Inbox {
        Inbox {
            commands: Mutex::new(commands),
            clicks: Mutex::new(clicks),
            notices: Mutex::new(notices),
            first_link: RefCell::new(None),
            page: Cell::new(Page::Dashboard),
        }
    }

    pub(crate) fn set_first_link(&self, link: Option<String>) {
        self.first_link.replace(link);
    }

    /// The start link, once per process.
    pub(crate) fn take_first_link(&self) -> Option<String> {
        self.first_link.borrow_mut().take()
    }

    /// The page a (rebuilt) window opens on.
    pub(crate) fn page(&self) -> Page {
        self.page.get()
    }

    pub(crate) fn keep_page(&self, page: Page) {
        self.page.set(page);
    }
}

/// Runs `on` for each command of a later launch while the caller is mounted.
pub(crate) fn use_commands(inbox: &Rc<Inbox>, on: impl FnMut(Command) + Clone + 'static) {
    let inbox = inbox.clone();
    use_future(move || {
        let (inbox, mut on) = (inbox.clone(), on.clone());
        async move {
            let mut commands = inbox.commands.lock().await;
            let Some(commands) = commands.as_mut() else {
                return;
            };
            while let Some(command) = commands.recv().await {
                on(command);
            }
        }
    });
}

/// Runs `on` for each click on a Windows toast while the caller is mounted.
pub(crate) fn use_clicks(inbox: &Rc<Inbox>, on: impl FnMut() + Clone + 'static) {
    let inbox = inbox.clone();
    use_future(move || {
        let (inbox, mut on) = (inbox.clone(), on.clone());
        async move {
            let mut clicks = inbox.clicks.lock().await;
            while clicks.recv().await.is_some() {
                on();
            }
        }
    });
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
