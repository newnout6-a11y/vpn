//! The update channel in the app (p-updates; research/updates.md §4): the feed check on its
//! schedule, the offers on the start page and in Settings, downloads through the running session,
//! engine installs into the engine store (they reach the tunnel without an app restart:
//! `switch`), the app's own update through the per-user installer.
//! Nothing runs while the owner's keys are not compiled in (`vpnte_update::policy::keys_ready`).
mod actions;
mod api;
mod checks;
mod doc;
mod flow;
mod launch;
mod service;
mod switch;
mod trial;
mod view;
mod ways;

use std::any::Any;
use std::fs::File;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::{Notify, watch};
use vpnte_core::store::Store;
use vpnte_ui::updates::{Note, Progress, UpdatesApi, UpdatesView};
use vpnte_update::dirs;
use vpnte_update::feed::{FEED_FILE, Feed, SIG_FILE, verify_trusted};
use vpnte_update::pending::{self, Outcome};
use vpnte_update::policy;
use vpnte_update::store::EngineStore;

use crate::services::Backend;
use doc::UpdatesDoc;

/// The root contexts of the update channel: `Rc<dyn UpdatesApi>`. Starts the checker and the
/// trial watch under `backend.shutdown` (inside the UI's tokio runtime).
pub fn contexts(backend: &Arc<Backend>) -> Vec<Box<dyn Any>> {
    let updates = Updates::start(backend.clone());
    let api: Rc<dyn UpdatesApi> = Rc::new(api::Handle(updates));
    vec![Box::new(api)]
}

/// The engine store of this user (`<local>\engines`, the bundled engines in `resources`).
pub(crate) fn engine_store(data_root: &std::path::Path, resources: PathBuf) -> EngineStore {
    EngineStore::new(dirs::engines_dir(&local_root(data_root)), resources)
}

/// `%LOCALAPPDATA%\VPN Tunnel Enforcer` (or `<data>\local` on an overridden data dir).
fn local_root(data_root: &std::path::Path) -> PathBuf {
    dirs::local_root(data_root).unwrap_or_else(|err| {
        tracing::warn!(%err, "local app data folder unknown, using the data dir");
        data_root.join("local")
    })
}

/// A verified feed with the exact signed bytes (stored next to what it installs).
#[derive(Clone)]
pub(crate) struct Signed {
    pub feed: Feed,
    pub bytes: Vec<u8>,
    pub sig: String,
}

/// What lives only for this app run.
#[derive(Default)]
struct Inner {
    feed: Option<Signed>,
    /// «Позже» on the app banner.
    hidden_app: bool,
    /// «Позже» on engine offers.
    hidden_engines: Vec<String>,
    outcome: Option<Outcome>,
    note: Option<Note>,
    progress: Option<Progress>,
    checking: bool,
    /// A download, install or installer start runs.
    busy: bool,
    /// The installer handed to Windows, held without write / delete sharing until exit.
    held: Option<File>,
    /// The helper service's last answer about its own update (p-svc-update).
    service: Option<vpnte_service::proto::ServiceUpdateWire>,
}

/// The update channel of this app run.
pub(crate) struct Updates {
    backend: Arc<Backend>,
    updates_dir: PathBuf,
    store: EngineStore,
    doc: Store<UpdatesDoc>,
    inner: Mutex<Inner>,
    view: watch::Sender<UpdatesView>,
    now: Arc<Notify>,
}

impl Updates {
    fn start(backend: Arc<Backend>) -> Arc<Self> {
        let local = local_root(&backend.dirs.root);
        let updates_dir = dirs::updates_dir(&local);
        let store = EngineStore::new(dirs::engines_dir(&local), backend.dirs.resources.clone());
        let doc = Store::<UpdatesDoc>::open(&backend.dirs.root);
        let outcome = pending::take(&updates_dir, policy::app_version());
        let feed = policy::keys_ready()
            .then(|| cached_feed(&updates_dir))
            .flatten();
        let this = Arc::new(Self {
            backend,
            updates_dir,
            store,
            doc,
            inner: Mutex::new(Inner {
                feed,
                outcome,
                ..Inner::default()
            }),
            view: watch::Sender::new(UpdatesView::default()),
            now: Arc::new(Notify::new()),
        });
        this.after_update();
        this.refresh();
        if policy::keys_ready() {
            flow::spawn_checker(&this);
        }
        trial::spawn(&this);
        let reader = this.clone();
        tokio::spawn(async move { reader.refresh_service().await });
        this
    }

    /// The start after an update says how it went: success once as a notice, a failure stays
    /// as the banner with the kept installer.
    fn after_update(&self) {
        if let Some(Outcome::Updated { to }) = &self.inner.lock().outcome {
            use vpnte_base::Msg;
            use vpnte_base::types::{Level, Notice};
            let notice = Notice::new(
                Level::Success,
                Msg::new("app.update.updated").arg("version", to),
            );
            self.backend.notifier.notify(notice, None);
        }
    }

    /// Recomputes the pushed view.
    fn refresh(&self) {
        let next = view::compute(self);
        self.view.send_if_modified(|current| {
            let changed = *current != next;
            if changed {
                *current = next;
            }
            changed
        });
    }

    /// One calm line after an action (`warn` = a refusal or failure).
    fn note(&self, msg: vpnte_base::Msg, warn: bool) {
        self.inner.lock().note = Some(Note {
            msg,
            warn,
            switch_now: false,
        });
        self.refresh();
    }
}

/// The last accepted feed, when its signature still verifies (`updates\update.json`).
fn cached_feed(updates_dir: &std::path::Path) -> Option<Signed> {
    let bytes = std::fs::read(updates_dir.join(FEED_FILE)).ok()?;
    let sig = std::fs::read_to_string(updates_dir.join(SIG_FILE)).ok()?;
    let feed = verify_trusted(&bytes, &sig).ok()?;
    Some(Signed { feed, bytes, sig })
}

#[cfg(test)]
mod tests;
