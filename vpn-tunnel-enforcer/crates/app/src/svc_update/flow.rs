//! The feed check (research §4.4): on the schedule of `vpnte_update::check`, through the session
//! first; an accepted feed is stored with its signature, remembered by `seq`, and its offers go
//! to the view. A security release is said once in a notice (tray), never forced; any other
//! offered app version once in the event journal.
use std::sync::Arc;

use vpnte_base::Msg;
use vpnte_base::types::{Level, Notice, now_ms};
use vpnte_update::check::{self, Trigger};
use vpnte_update::feed::{FEED_FILE, SIG_FILE};
use vpnte_update::fetch::{FetchError, Fetched, Freshness, fetch_feed, freshness};
use vpnte_update::net::Way;
use vpnte_update::policy;

use super::doc::{Found, LastCheck};
use super::view::{engine_offers, newer_release};
use super::{Signed, Updates, ways};
use crate::svc_journal::Tone;

/// Starts the checker under the app's shutdown token.
pub(super) fn spawn_checker(u: &Arc<Updates>) {
    let this = u.clone();
    let (now, cancel) = (u.now.clone(), u.backend.shutdown.child_token());
    tokio::spawn(check::run(
        move |trigger| this.clone().check(trigger),
        now,
        cancel,
    ));
}

impl Updates {
    /// One check; `false` = it failed (the schedule retries sooner).
    pub(super) async fn check(self: Arc<Self>, trigger: Trigger) -> bool {
        if trigger == Trigger::Timer && !self.doc.read(|d| d.auto_check) {
            return true;
        }
        self.inner.lock().checking = true;
        self.refresh();
        let max_seq = self.doc.read(|d| d.max_seq);
        let ways = self.ways();
        let result = fetch_feed(&policy::FEED_BASES, &ways, policy::trusted_keys(), max_seq).await;
        let ok = match result {
            Ok(fetched) => {
                self.accept(fetched);
                true
            }
            // Every mirror is behind the feed we already hold: nothing new, the held one stands.
            Err(FetchError::Older) => {
                self.record(None, self.found_in_held());
                true
            }
            Err(err) => {
                tracing::warn!(%err, "update check failed");
                self.record(None, Found::Failed);
                false
            }
        };
        self.inner.lock().checking = false;
        self.refresh();
        if ok {
            self.clone().download_ahead();
        }
        self.refresh_service().await;
        ok
    }

    /// The ways out right now (session first, then direct).
    pub(super) fn ways(&self) -> Vec<Way> {
        self.backend
            .tunnel()
            .map(|t| ways::ways(&t.runtime_status().borrow()))
            .unwrap_or_else(|_| vec![Way::direct()])
    }

    fn accept(&self, fetched: Fetched) {
        let Fetched {
            feed,
            bytes,
            sig,
            source,
            stale,
        } = fetched;
        // The pair is written feed first: a crash between the two leaves a pair that does not
        // verify, which simply reads as "no feed held" at the next start.
        let saved = std::fs::create_dir_all(&self.updates_dir)
            .and_then(|()| {
                vpnte_core::store::write_atomic(&self.updates_dir.join(FEED_FILE), &bytes)
            })
            .and_then(|()| {
                vpnte_core::store::write_atomic(&self.updates_dir.join(SIG_FILE), sig.as_bytes())
            });
        if let Err(err) = saved {
            tracing::warn!(%err, "update feed not stored");
        }
        let seq = feed.seq;
        self.inner.lock().feed = Some(Signed { feed, bytes, sig });
        let found = if stale {
            Found::Stale
        } else {
            self.found_in_held()
        };
        if let Err(err) = self.doc.update(|d| d.max_seq = d.max_seq.max(seq)) {
            tracing::warn!(%err, "update seq not stored");
        }
        tracing::info!(seq, host = %source.host, via = ?source.via, ?found, "update feed accepted");
        self.record(Some(source), found);
        self.tell_security();
        self.tell_offer();
    }

    /// Newer versions in the held feed? A stale held feed never reads as "up to date".
    fn found_in_held(&self) -> Found {
        let inner = self.inner.lock();
        let Some(signed) = inner.feed.as_ref() else {
            return Found::UpToDate;
        };
        let running = policy::app_version();
        if freshness(&signed.feed, 0, jiff::Timestamp::now()) == Freshness::Stale {
            Found::Stale
        } else if newer_release(&signed.feed, running).is_some()
            || !engine_offers(&signed.feed, &self.store, running).is_empty()
        {
            Found::Newer
        } else {
            Found::UpToDate
        }
    }

    fn record(&self, source: Option<vpnte_update::fetch::Source>, result: Found) {
        let line = LastCheck {
            at: now_ms(),
            host: source.as_ref().map(|s| s.host.clone()),
            via: source.map(|s| s.via),
            result,
            app: Some(policy::app_version()),
        };
        if let Err(err) = self.doc.update(|d| d.last_check = Some(line)) {
            tracing::warn!(%err, "update check result not stored");
        }
    }

    /// One journal line per offered app version; a security release has its notice instead
    /// (which the journal records too). A version that could not be remembered is not written
    /// either: no repeat at every check.
    pub(super) fn tell_offer(&self) {
        let offer = {
            let inner = self.inner.lock();
            let feed = inner.feed.as_ref().map(|s| &s.feed);
            feed.and_then(|f| newer_release(f, policy::app_version()))
                .map(|r| (r.version.to_string(), r.severity.is_security()))
        };
        let Some((version, security)) = offer else {
            return;
        };
        if self
            .doc
            .read(|d| d.offered.as_deref() == Some(version.as_str()))
        {
            return;
        }
        if let Err(err) = self.doc.update(|d| d.offered = Some(version.clone())) {
            tracing::warn!(%err, "offered version not stored");
            return;
        }
        if !security {
            let title = Msg::new("app.journal.update.offered").arg("version", &version);
            self.journal(Tone::Info, title, None);
        }
    }

    /// One notice per security release (the banner stays; nothing is forced).
    fn tell_security(&self) {
        let version = {
            let inner = self.inner.lock();
            let running = policy::app_version();
            let release = inner
                .feed
                .as_ref()
                .and_then(|s| newer_release(&s.feed, running));
            match release {
                Some(r) if r.severity.is_security() => r.version.to_string(),
                _ => return,
            }
        };
        if self
            .doc
            .read(|d| d.announced.as_deref() == Some(version.as_str()))
        {
            return;
        }
        if let Err(err) = self.doc.update(|d| d.announced = Some(version.clone())) {
            tracing::warn!(%err, "announced version not stored");
        }
        let notice = Notice::new(
            Level::Warn,
            Msg::new("app.update.securityTitle").arg("version", &version),
        )
        .body(Msg::new("app.update.securityBody"));
        self.backend.notifier.notify(notice, None);
    }
}
