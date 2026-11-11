//! Browser hardening (spec §2.12, §3.7, §6.8 `BrowserWebRtc`; owner decision 10.2-B): machine
//! policies for the verified Chromium browsers only, written to `HKLM` (the process is elevated
//! and `HKLM` is the authoritative machine policy). Unverified browsers are detected and reported
//! as not checked, with nothing written; `Preferences` and Firefox `user.js` are never edited
//! (the running browser rewrites `Preferences`, and Firefox copies `user.js` into `prefs.js`).
use std::path::PathBuf;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use vpnte_base::{AppResult, Msg};

use super::system::System;
use super::{admissible, needs_admin, short_text};
use crate::tweaks::journal::{Feature, Journal, RegHive, RollbackReport, Target, TweakError, Val};
use crate::tweaks::run_blocking;

/// `WebRtcIPHandlingPolicy`: WebRTC may send UDP only through a proxy (the tunnel), so a page
/// cannot learn the real address through STUN.
pub const WEBRTC_POLICY: (&str, &str) = ("WebRtcIPHandlingPolicy", "disable_non_proxied_udp");

/// `DnsOverHttpsMode`: the browser's own DNS-over-HTTPS resolver is off, so its lookups go to the
/// system resolver, which the tunnel captures. A browser resolver that the routing sends direct
/// (Yandex's own resolver under a Russian split) would see every visited name outside the tunnel.
pub const DOH_POLICY: (&str, &str) = ("DnsOverHttpsMode", "off");

/// Every policy key the old app wrote a WebRTC value to, under `HKLM` and `HKCU` each (16 values,
/// BH:95-141). Allow-listed so that its leftovers can be rolled back; legacy records are renamed
/// to this spelling so a leftover and a new write of the same value are one journal record.
pub(crate) const OLD_POLICY_KEYS: [&str; 8] = [
    r"SOFTWARE\Policies\Google\Chrome",
    r"SOFTWARE\Policies\Microsoft\Edge",
    r"SOFTWARE\Policies\BraveSoftware\Brave",
    r"SOFTWARE\Policies\YandexBrowser",
    r"SOFTWARE\Policies\Yandex\YandexBrowser",
    r"SOFTWARE\Policies\Chromium",
    r"SOFTWARE\Policies\Vivaldi",
    r"SOFTWARE\Policies\Opera Software\Opera",
];

/// Where installed applications register their executable (64-bit, 32-bit, per user).
const APP_PATHS: [(RegHive, &str); 3] = [
    (
        RegHive::Hklm,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
    ),
    (
        RegHive::Hklm,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths",
    ),
    (
        RegHive::Hkcu,
        r"Software\Microsoft\Windows\CurrentVersion\App Paths",
    ),
];

/// A browser the hardening knows about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Browser {
    Chrome,
    Edge,
    Brave,
    Yandex,
    Chromium,
    Vivaldi,
    Opera,
    Firefox,
}

struct Spec {
    name: &'static str,
    /// `App Paths` entry and a fragment its (lower-cased) path must contain: `chrome.exe` is
    /// shared by Chrome and Chromium, and Yandex registers the generic `browser.exe`.
    exe: (&'static str, &'static str),
    /// User-data directory: below `%APPDATA%` when `true`, else below `%LOCALAPPDATA%`.
    data: (bool, &'static str),
    /// `HKLM` policy keys we write; empty = not a verified browser.
    keys: &'static [&'static str],
}

impl Browser {
    /// Every known browser, verified ones first (the order of the card).
    pub const ALL: [Browser; 8] = [
        Browser::Chrome,
        Browser::Edge,
        Browser::Brave,
        Browser::Yandex,
        Browser::Chromium,
        Browser::Vivaldi,
        Browser::Opera,
        Browser::Firefox,
    ];

    /// Product name (the same in every language).
    pub fn name(self) -> &'static str {
        self.spec().name
    }

    /// Whether policies are applied to it (Chrome, Edge, Brave, Yandex); the others are shown
    /// as not checked (owner decision 10.2-B).
    pub fn verified(self) -> bool {
        !self.spec().keys.is_empty()
    }

    fn spec(self) -> Spec {
        type Row = (
            &'static str,
            (&'static str, &'static str),
            (bool, &'static str),
            &'static [&'static str],
        );
        let (name, exe, data, keys): Row = match self {
            Browser::Chrome => (
                "Google Chrome",
                ("chrome.exe", r"google\chrome"),
                (false, r"Google\Chrome\User Data"),
                &[r"SOFTWARE\Policies\Google\Chrome"],
            ),
            Browser::Edge => (
                "Microsoft Edge",
                ("msedge.exe", r"microsoft\edge"),
                (false, r"Microsoft\Edge\User Data"),
                &[r"SOFTWARE\Policies\Microsoft\Edge"],
            ),
            Browser::Brave => (
                "Brave",
                ("brave.exe", "bravesoftware"),
                (false, r"BraveSoftware\Brave-Browser\User Data"),
                &[r"SOFTWARE\Policies\BraveSoftware\Brave"],
            ),
            // Yandex reads both policy roots (BH:102-107).
            Browser::Yandex => (
                "Yandex Browser",
                ("browser.exe", "yandex"),
                (false, r"Yandex\YandexBrowser\User Data"),
                &[
                    r"SOFTWARE\Policies\YandexBrowser",
                    r"SOFTWARE\Policies\Yandex\YandexBrowser",
                ],
            ),
            Browser::Chromium => (
                "Chromium",
                ("chrome.exe", "chromium"),
                (false, r"Chromium\User Data"),
                &[],
            ),
            Browser::Vivaldi => (
                "Vivaldi",
                ("vivaldi.exe", "vivaldi"),
                (false, r"Vivaldi\User Data"),
                &[],
            ),
            Browser::Opera => (
                "Opera",
                ("opera.exe", "opera"),
                (true, r"Opera Software\Opera Stable"),
                &[],
            ),
            Browser::Firefox => (
                "Mozilla Firefox",
                ("firefox.exe", "firefox"),
                (true, r"Mozilla\Firefox\Profiles"),
                &[],
            ),
        };
        Spec {
            name,
            exe,
            data,
            keys,
        }
    }

    /// Whether `target` is one of this browser's policy values.
    fn owns(self, target: &Target) -> bool {
        matches!(target, Target::Reg { hive: RegHive::Hklm, key, .. }
            if self.spec().keys.iter().any(|k| k.eq_ignore_ascii_case(key)))
    }
}

/// The per-user folders browser detection looks in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BrowserDirs {
    /// `%LOCALAPPDATA%`.
    pub local: Option<PathBuf>,
    /// `%APPDATA%`.
    pub roaming: Option<PathBuf>,
}

impl BrowserDirs {
    /// The folders of the account the process runs as.
    pub fn current_user() -> Self {
        let var = |name: &str| {
            std::env::var_os(name)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        let profile = var("USERPROFILE");
        let below = |rel: &str| Some(profile.as_ref()?.join(rel));
        Self {
            local: var("LOCALAPPDATA").or_else(|| below(r"AppData\Local")),
            roaming: var("APPDATA").or_else(|| below(r"AppData\Roaming")),
        }
    }

    fn user_data(&self, browser: Browser) -> Option<PathBuf> {
        let (roaming, rel) = browser.spec().data;
        let base = if roaming { &self.roaming } else { &self.local };
        Some(base.as_ref()?.join(rel))
    }
}

/// Whether `browser` is installed: its `App Paths` entry points into its own folder, or its
/// user-data directory exists. A key that cannot be read counts as "not there".
fn installed(sys: &dyn System, dirs: &BrowserDirs, browser: Browser) -> bool {
    let (exe, hint) = browser.spec().exe;
    let registered = APP_PATHS.iter().any(|(hive, root)| {
        let entry = Target::Reg {
            hive: *hive,
            key: format!(r"{root}\{exe}"),
            name: String::new(),
        };
        match sys.read(&entry) {
            Ok(Val::Sz(path) | Val::ExpandSz(path)) => path.to_ascii_lowercase().contains(hint),
            Ok(_) => false,
            Err(e) => {
                tracing::debug!(target = %entry.label(), error = %e, "App Paths entry unreadable");
                false
            }
        }
    });
    registered
        || dirs
            .user_data(browser)
            .is_some_and(|dir| sys.dir_exists(&dir))
}

/// The policy values of `browser` (none for an unverified one).
pub fn plan(browser: Browser) -> Vec<(Feature, Target, Val)> {
    browser
        .spec()
        .keys
        .iter()
        .flat_map(|key| {
            [WEBRTC_POLICY, DOH_POLICY].map(|(name, value)| {
                (
                    Feature::BrowserWebRtc,
                    Target::Reg {
                        hive: RegHive::Hklm,
                        key: (*key).to_owned(),
                        name: name.to_owned(),
                    },
                    Val::Sz(value.to_owned()),
                )
            })
        })
        .collect()
}

/// The canonical spelling of an old policy key (legacy import), `None` for any other key.
pub(crate) fn canonical_key(key: &str) -> Option<&'static str> {
    OLD_POLICY_KEYS
        .into_iter()
        .find(|k| k.eq_ignore_ascii_case(key))
}

/// Allow-list part of [`super::admit`]: the WebRTC value on every key the old app used (both
/// hives, so its leftovers can be rolled back) and the DoH value on the verified `HKLM` keys;
/// strings only.
pub(crate) fn admits(hive: RegHive, key: &str, name: &str, value: &Val) -> bool {
    let verified = || {
        Browser::ALL
            .into_iter()
            .any(|b| b.spec().keys.iter().any(|k| k.eq_ignore_ascii_case(key)))
    };
    short_text(value)
        && if name.eq_ignore_ascii_case(WEBRTC_POLICY.0) {
            canonical_key(key).is_some()
        } else if name.eq_ignore_ascii_case(DOH_POLICY.0) {
            hive == RegHive::Hklm && verified()
        } else {
            false
        }
}

/// What a browser looks like to the hardening.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum BrowserState {
    /// Not found on this computer.
    NotInstalled,
    /// Installed but not a verified browser: left untouched, shown as not checked.
    NotVerified,
    /// Installed and verified; none of our policies is set.
    Off,
    /// Our policies are in place (read back).
    Protected,
    /// Some of our policies were changed by someone else since.
    Drifted,
    /// A value could not be read: not checked.
    Unknown,
    /// This apply failed and left nothing behind; `reason` is for the user.
    Failed { reason: Msg },
}

/// One row of the browser card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserEntry {
    pub browser: Browser,
    pub state: BrowserState,
}

/// Outcome of an apply, rollback or status read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserReport {
    /// Every known browser, verified ones first.
    pub browsers: Vec<BrowserEntry>,
    /// A policy changed now: browsers pick it up only after a full restart, background
    /// processes included (BH:472).
    pub restart_required: bool,
    /// Apply: no browser failed and every old value outside the plan was put back. Rollback: no
    /// value is left for a retry.
    pub success: bool,
    /// Summary line for the card (`None` for a plain status read).
    pub message: Option<Msg>,
    /// Further lines: the "managed by your organization" hint, values changed by someone else.
    pub notes: Vec<Msg>,
}

/// Browser hardening over the shared journal. Cheap to clone. Apply and rollback are serialised:
/// the old app let two clicks race on the same keys (F-036).
#[derive(Clone)]
pub struct Browsers {
    journal: Arc<Journal>,
    sys: Arc<dyn System>,
    dirs: Arc<BrowserDirs>,
    serial: Arc<Mutex<()>>,
}

impl Browsers {
    /// Browser hardening with the machine `sys` and the user folders `dirs`.
    pub fn new(journal: Arc<Journal>, sys: Arc<dyn System>, dirs: BrowserDirs) -> Self {
        Self {
            journal,
            sys,
            dirs: Arc::new(dirs),
            serial: Arc::new(Mutex::new(())),
        }
    }

    /// Writes the policies of every installed verified browser (needs elevation).
    pub async fn apply(&self) -> AppResult<BrowserReport> {
        let this = self.clone();
        run_blocking(move || this.apply_blocking()).await?
    }

    /// Puts every journalled browser value back (needs elevation when there is one).
    pub async fn rollback(&self) -> AppResult<BrowserReport> {
        let this = self.clone();
        run_blocking(move || this.rollback_blocking()).await?
    }

    /// Reads detection and our values back.
    pub async fn status(&self) -> AppResult<BrowserReport> {
        let this = self.clone();
        run_blocking(move || this.status_blocking()).await
    }

    /// Whether browser values are journalled (ours to roll back).
    pub fn is_applied(&self) -> bool {
        self.journal.is_applied(Feature::BrowserWebRtc)
    }

    fn detect(&self) -> Vec<Browser> {
        Browser::ALL
            .into_iter()
            .filter(|b| installed(&*self.sys, &self.dirs, *b))
            .collect()
    }
}

const APPLIED: &str = "automation.hardening.browser.applied";
const ALREADY: &str = "automation.hardening.browser.alreadyApplied";
const NONE_FOUND: &str = "automation.hardening.browser.noneFound";
const FAILED: &str = "automation.hardening.browser.failed";
const NOT_CONFIRMED: &str = "automation.hardening.browser.notConfirmed";
const FOREIGN: &str = "automation.hardening.browser.foreignValue";
const MANAGED: &str = "automation.hardening.browser.managedNote";
const CLEANUP_PARTIAL: &str = "automation.hardening.browser.cleanupPartial";
const ROLLED_BACK: &str = "automation.hardening.browser.rolledBack";
const ROLLBACK_PARTIAL: &str = "automation.hardening.browser.rollbackPartial";
const NOT_APPLIED: &str = "automation.hardening.browser.notApplied";

impl Browsers {
    /// Blocking form of [`Browsers::apply`]. Each verified browser is one unit: a failure undoes
    /// that browser's writes and leaves the others protected.
    pub fn apply_blocking(&self) -> AppResult<BrowserReport> {
        let _serial = self.serial.lock();
        if !self.sys.elevated() {
            return Err(needs_admin());
        }
        let installed = self.detect();
        let wanted: Vec<Target> = installed
            .iter()
            .flat_map(|b| plan(*b))
            .map(|(_, target, _)| target)
            .collect();
        // Values outside today's plan (the old app's HKCU keys and unverified browsers, a browser
        // uninstalled since) go back first (spec §8.11). The journal rolls back per feature; a
        // full rollback followed by the apply keeps every original baseline.
        let mut cleanup = RollbackReport::default();
        let records = self.journal.records(Feature::BrowserWebRtc);
        if records.iter().any(|r| !wanted.contains(&r.target)) {
            cleanup = self.journal.rollback(&*self.sys, &[Feature::BrowserWebRtc]);
        }
        let mut changed = !cleanup.restored.is_empty();
        let mut failures: Vec<Msg> = Vec::new();
        let mut browsers = Vec::new();
        for browser in Browser::ALL {
            let state = if !installed.contains(&browser) {
                BrowserState::NotInstalled
            } else if !browser.verified() {
                BrowserState::NotVerified
            } else {
                match self.apply_one(browser) {
                    Ok(wrote) => {
                        changed |= wrote;
                        BrowserState::Protected
                    }
                    Err(reason) => {
                        failures.push(reason.clone());
                        BrowserState::Failed { reason }
                    }
                }
            };
            browsers.push(BrowserEntry { browser, state });
        }
        let message = if !failures.is_empty() {
            if failures.iter().any(|m| m.key == NOT_CONFIRMED) {
                NOT_CONFIRMED
            } else {
                FAILED
            }
        } else if !installed.iter().any(|b| b.verified()) {
            NONE_FOUND
        } else if changed {
            APPLIED
        } else {
            ALREADY
        };
        let mut notes = Vec::new();
        if browsers.iter().any(|e| e.state == BrowserState::Protected) {
            notes.push(Msg::new(MANAGED));
        }
        if !cleanup.is_complete() {
            notes.push(Msg::new(CLEANUP_PARTIAL));
        }
        notes.extend(cleanup.kept_msg());
        Ok(BrowserReport {
            browsers,
            restart_required: changed,
            success: failures.is_empty() && cleanup.is_complete(),
            message: Some(Msg::new(message)),
            notes,
        })
    }

    /// Applies the policies of one browser as a unit; `Ok(true)` when a value changed.
    fn apply_one(&self, browser: Browser) -> Result<bool, Msg> {
        let plan = plan(browser);
        let mut changed = false;
        for (_, target, value) in &plan {
            let current = self
                .sys
                .read(target)
                .map_err(|e| failure(browser, &TweakError::Unreadable(target.label(), e)))?;
            // A baseline outside the allow-list would be dropped from the journal at the next
            // start and our value would stay for good: such a key is not touched.
            if !admissible(target, &current) {
                tracing::warn!(browser = browser.name(), target = %target.label(),
                    "policy value of an unexpected type present; browser left alone");
                return Err(Msg::new(FOREIGN));
            }
            changed |= current != *value;
        }
        self.journal
            .apply(&*self.sys, &plan)
            .map_err(|e| failure(browser, &e))?;
        Ok(changed)
    }

    /// Blocking form of [`Browsers::rollback`]: own values only (a value changed by someone else
    /// since is kept); what fails stays journalled for the next attempt.
    pub fn rollback_blocking(&self) -> AppResult<BrowserReport> {
        let _serial = self.serial.lock();
        if !self.is_applied() {
            return Ok(BrowserReport {
                message: Some(Msg::new(NOT_APPLIED)),
                ..self.status_blocking()
            });
        }
        if !self.sys.elevated() {
            return Err(needs_admin());
        }
        let report = self.journal.rollback(&*self.sys, &[Feature::BrowserWebRtc]);
        let mut out = self.status_blocking();
        out.restart_required = !report.restored.is_empty();
        out.success = report.is_complete();
        out.message = Some(Msg::new(if report.is_complete() {
            ROLLED_BACK
        } else {
            ROLLBACK_PARTIAL
        }));
        out.notes.extend(report.kept_msg());
        Ok(out)
    }

    /// Blocking form of [`Browsers::status`].
    pub fn status_blocking(&self) -> BrowserReport {
        let installed = self.detect();
        let records = self.journal.records(Feature::BrowserWebRtc);
        let browsers = Browser::ALL
            .into_iter()
            .map(|browser| {
                let journalled = records.iter().any(|r| browser.owns(&r.target));
                let state = if !journalled && !installed.contains(&browser) {
                    BrowserState::NotInstalled
                } else if !browser.verified() {
                    BrowserState::NotVerified
                } else {
                    self.read_back(browser, journalled)
                };
                BrowserEntry { browser, state }
            })
            .collect();
        BrowserReport {
            browsers,
            restart_required: false,
            success: true,
            message: None,
            notes: Vec::new(),
        }
    }

    /// A verified browser: protected when every policy holds our value, whoever wrote it.
    fn read_back(&self, browser: Browser, journalled: bool) -> BrowserState {
        let mut ours = true;
        for (_, target, value) in plan(browser) {
            match self.sys.read(&target) {
                Ok(current) => ours &= current == value,
                Err(_) => return BrowserState::Unknown,
            }
        }
        match (ours, journalled) {
            (true, _) => BrowserState::Protected,
            (false, true) => BrowserState::Drifted,
            (false, false) => BrowserState::Off,
        }
    }
}

fn failure(browser: Browser, e: &TweakError) -> Msg {
    tracing::warn!(browser = browser.name(), error = %e, "browser policy not applied");
    Msg::new(match e {
        TweakError::NotVerified(_) => NOT_CONFIRMED,
        _ => FAILED,
    })
}

#[cfg(test)]
mod tests;
