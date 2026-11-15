//! Location privacy follows the session and the Settings toggle one change at a time, over an
//! in-memory registry (nothing of the real one is touched).
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Condvar, Mutex};
use tokio::sync::watch;
use vpnte_automation::hardening::{self, Location, System};
use vpnte_automation::tweaks::journal::{Backend, Journal, Target, TweakError, Val};
use vpnte_base::types::Owner;
use vpnte_tunnel::history::SessionMode;
use vpnte_tunnel::lifecycle::SessionView;

use super::coord::rig;
use super::pure::view;
use crate::svc_auto::{Followed, Privacy};

/// The registry in memory; `hold` makes the next write wait until released.
#[derive(Default)]
struct Registry {
    values: Mutex<HashMap<Target, Val>>,
    hold: Mutex<bool>,
    released: Condvar,
}

impl Registry {
    fn release(&self) {
        *self.hold.lock() = false;
        self.released.notify_all();
    }

    fn consent(&self) -> Option<Val> {
        let values = self.values.lock();
        values.values().next().cloned()
    }
}

impl Backend for Registry {
    fn read(&self, target: &Target) -> io::Result<Val> {
        Ok(self
            .values
            .lock()
            .get(target)
            .cloned()
            .unwrap_or(Val::Absent))
    }

    fn write(&self, target: &Target, value: &Val) -> io::Result<bool> {
        let mut hold = self.hold.lock();
        while *hold {
            self.released.wait(&mut hold);
        }
        drop(hold);
        let mut values = self.values.lock();
        match value {
            Val::Absent => values.remove(target),
            v => values.insert(target.clone(), v.clone()),
        };
        Ok(false)
    }

    fn prune(&self, _: &Target) -> io::Result<()> {
        Ok(())
    }
}

impl System for Registry {
    fn dir_exists(&self, _: &Path) -> bool {
        false
    }

    fn elevated(&self) -> bool {
        false
    }

    fn check_user(&self) -> Result<(), TweakError> {
        Ok(())
    }
}

struct Setup {
    privacy: Arc<Privacy>,
    registry: Arc<Registry>,
    session: watch::Sender<Option<SessionView>>,
    rig: super::coord::Rig,
}

fn setup(name: &str) -> Setup {
    let rig = rig(name);
    let registry = Arc::new(Registry::default());
    let journal = Arc::new(Journal::open(&rig.dir(), hardening::admit));
    let location = Location::new(journal, registry.clone());
    let session = watch::Sender::new(None);
    let privacy = Arc::new(Privacy::new(
        location,
        rig.settings.clone(),
        rig.notifier.clone(),
        session.subscribe(),
    ));
    Setup {
        privacy,
        registry,
        session,
        rig,
    }
}

fn setting(s: &Setup, on: bool) {
    s.rig
        .settings
        .update(|v| v.location_privacy = on)
        .expect("settings");
}

/// a9: turned on just after a session ended (the page may still show it connected): nothing is
/// denied without a session, the choice waits for the next connect.
#[tokio::test]
async fn a_toggle_without_a_session_denies_nothing() {
    let s = setup("privacy-ended");
    setting(&s, true);
    assert_eq!(s.privacy.follow_setting().await, Followed::Stored);
    assert_eq!(s.registry.consent(), None);
    assert!(!s.privacy.location.is_applied());
}

/// b9: the toggle turned off while the session's apply is still writing waits for it and then
/// gives the consent back: never denied with the setting off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_toggle_during_the_sessions_apply_is_not_lost() {
    let s = setup("privacy-race");
    setting(&s, true);
    s.session
        .send_replace(Some(view(SessionMode::Soft, "a", Owner::Manual, 1)));
    *s.registry.hold.lock() = true;
    let up = tokio::spawn({
        let privacy = s.privacy.clone();
        async move { privacy.session_up().await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    setting(&s, false);
    let toggle = tokio::spawn({
        let privacy = s.privacy.clone();
        async move { privacy.follow_setting().await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !toggle.is_finished(),
        "the toggle waits for the apply in flight"
    );
    s.registry.release();
    up.await.unwrap();
    assert_eq!(toggle.await.unwrap(), Followed::Applied);
    assert_eq!(
        s.registry.consent(),
        None,
        "the consent is the user's again"
    );
    assert!(!s.privacy.location.is_applied());
}
