//! The engine store (research §4.7): downloaded engine versions next to the bundled ones, which
//! are never touched and stay the last fallback.
//!
//! ```text
//! <local>\engines\
//!   sing-box\1.14.5\  sing-box.exe libcronet.dll wintun.dll update.json update.json.minisig
//!   xray\26.11.20\    xray.exe update.json update.json.minisig
//!   state.json        which version is active / previous per engine, the trial
//! ```
//! Each version keeps the signed feed it was installed from (the elevated pin check re-verifies
//! it at every start), so «Вернуть предыдущую» works after a newer feed dropped the old entry.
mod install;
mod state;
mod switch;

use std::path::PathBuf;

use minisign_verify::PublicKey;

use crate::feed::{FEED_FILE, SIG_FILE, verify};
use crate::policy::{self, bundled_version, engine_allowed};
use crate::version::Version;

pub use install::{EngineCheck, InstallError, Installed};
pub use state::{Choice, EngineState, StoreState};

/// The executable of engine `id` in its folder.
pub fn exe_name(id: &str) -> Option<&'static str> {
    match id {
        policy::SINGBOX => Some("sing-box.exe"),
        policy::XRAY => Some("xray.exe"),
        _ => None,
    }
}

/// Where an engine of this run comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// The files shipped with the app.
    Bundled,
    /// A version this store installed (`on` = when, for «обновлён 12.11»).
    Downloaded {
        version: Version,
        on: vpnte_base::types::UnixMs,
    },
}

/// The engine to run: its exe and where it comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub exe: PathBuf,
    pub origin: Origin,
}

/// A trial that failed: the store went back by itself (say it in one line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolledBack {
    pub id: String,
    pub from: Version,
    pub to: Choice,
}

/// The store over `root` (`<local>\engines`), with the bundled engines in `resources`.
#[derive(Debug, Clone)]
pub struct EngineStore {
    root: PathBuf,
    resources: PathBuf,
    keys: &'static [PublicKey],
    /// A downloaded version equal to the bundled one counts too ([`EngineStore::not_below_bundled`]).
    equal_ok: bool,
}

impl EngineStore {
    /// A store that trusts the compiled feed keys.
    pub fn new(root: PathBuf, resources: PathBuf) -> Self {
        Self::with_keys(root, resources, policy::trusted_keys())
    }

    /// A store that trusts `keys` (tests).
    pub fn with_keys(root: PathBuf, resources: PathBuf, keys: &'static [PublicKey]) -> Self {
        Self {
            root,
            resources,
            keys,
            equal_ok: false,
        }
    }

    /// The helper service's store: a downloaded version equal to the bundled one is used and
    /// installed as well. After the service took a newer release's exe from the feed, its folder
    /// still holds the older release's engine files, which the new exe's release pins refuse;
    /// the same version from the signed feed (the same member hashes) takes their place.
    #[must_use]
    pub fn not_below_bundled(mut self) -> Self {
        self.equal_ok = true;
        self
    }

    /// `version` of `id` is past the bundled engine (or equal to it, see `not_below_bundled`).
    fn above_bundled(&self, id: &str, version: Version) -> bool {
        bundled_version(id).is_none_or(|b| version > b || (self.equal_ok && version == b))
    }

    /// The folder of version `version` of engine `id`.
    pub fn version_dir(&self, id: &str, version: Version) -> PathBuf {
        self.root.join(id).join(version.to_string())
    }

    /// What `state.json` says (empty when missing or unreadable: everything bundled).
    pub fn state(&self) -> StoreState {
        state::read(&self.root)
    }

    /// The engine to run for `id`: the active downloaded version when it is still usable (its
    /// files are there, the feed stored with it verifies and lists it, it fits this build's
    /// range and is newer than the bundled one), else the bundled engine. Cheap: no hashing
    /// (unelevated an engine runs with the user's own rights; elevated, the pin check hashes).
    pub fn resolve(&self, id: &str) -> Resolved {
        let bundled = || Resolved {
            exe: self.resources.join(exe_name(id).unwrap_or_default()),
            origin: Origin::Bundled,
        };
        let state = self.state();
        let Some(Choice::Downloaded(version)) = state.engine(id).map(|e| e.active) else {
            return bundled();
        };
        match self.usable(id, version) {
            Some(exe) => Resolved {
                exe,
                origin: Origin::Downloaded {
                    version,
                    on: state.engine(id).map_or(0, |e| e.installed_on(version)),
                },
            },
            None => bundled(),
        }
    }

    /// What a switch back of `id` would run now (the trial's [`EngineStore::record_start`]): the
    /// previous version while it may run, else the bundled engine.
    pub fn fallback(&self, id: &str) -> Resolved {
        let state = self.state();
        let record = state.engine(id);
        if let Some(Choice::Downloaded(version)) = record.and_then(|e| e.previous)
            && let Some(exe) = self.usable(id, version)
        {
            let on = record.map_or(0, |e| e.installed_on(version));
            return Resolved {
                exe,
                origin: Origin::Downloaded { version, on },
            };
        }
        Resolved {
            exe: self.resources.join(exe_name(id).unwrap_or_default()),
            origin: Origin::Bundled,
        }
    }

    /// The exe of a downloaded `version` when it may run (see [`EngineStore::resolve`]).
    fn usable(&self, id: &str, version: Version) -> Option<PathBuf> {
        let dir = self.version_dir(id, version);
        let exe = dir.join(exe_name(id)?);
        if !exe.is_file() || !engine_allowed(id, version) || !self.above_bundled(id, version) {
            return None;
        }
        let bytes = std::fs::read(dir.join(FEED_FILE)).ok()?;
        let sig = std::fs::read_to_string(dir.join(SIG_FILE)).ok()?;
        let feed = verify(&bytes, &sig, self.keys).ok()?;
        let entry = feed.engine(id)?;
        let app_ok = entry.app.contains(policy::app_version());
        (entry.version == version && app_ok).then_some(exe)
    }
}

#[cfg(test)]
mod tests;
