//! Soft mode as a session: the per-user system proxy and proxy variables plus the dev-tool targets
//! the user opted into, applied and rolled back together (spec G6: the old app left Git / Gradle pointing at a
//! dead proxy after Soft stopped). The lifecycle calls [`Soft::apply`] on a Soft start or refresh
//! and [`Soft::rollback`] on stop, before a Hard / Direct start, at shutdown and in startup
//! recovery when the settings no longer say Soft.
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use vpnte_base::types::ProxyKind;
use vpnte_base::{AppResult, Msg};
use vpnte_core::net::HostPort;
use vpnte_winnet::env::{BROADCAST_TIMEOUT, UserEnv, broadcast_change};

use super::git::{self, GitCli};
use super::journal::{
    Backend, BlockKind, Feature, Journal, RollbackReport, Target, TweakError, TweakState, Val,
    Writer,
};
use super::sysproxy::{self, SystemProxy, WinInet};
use super::{block, env, env_dir, run_blocking, studio, user};

/// Every feature a Soft session owns, in apply order.
pub const SOFT_FEATURES: [Feature; 5] = [
    Feature::SoftProxy,
    Feature::SoftEnv,
    Feature::DevGit,
    Feature::DevGradle,
    Feature::DevStudio,
];

/// Where the Soft-mode targets live. Production: [`SoftSystem::current_user`]; tests point every
/// field at throw-away places (a fake system proxy, a test registry key, a temp Git config file,
/// temp directories).
#[derive(Debug, Clone)]
pub struct SoftSystem {
    /// The per-user system proxy ([`WinInet`]).
    pub proxy: Arc<dyn SystemProxy>,
    /// The per-user environment (`HKCU\Environment`).
    pub env: UserEnv,
    /// Git, `None` when not installed.
    pub git: Option<GitCli>,
    /// The directory of `gradle.properties` (`%GRADLE_USER_HOME%`, else `%USERPROFILE%\.gradle`);
    /// Gradle counts as not installed while it does not exist.
    pub gradle_home: Option<PathBuf>,
    /// Android Studio's settings root (`%APPDATA%\Google`).
    pub studio_root: Option<PathBuf>,
    /// Broadcast `WM_SETTINGCHANGE` after the variables changed.
    pub broadcast: bool,
    /// Refuse when the process runs as another account than the session user (spec E3).
    pub check_user: bool,
}

impl SoftSystem {
    /// The real targets of the account this process runs as.
    pub fn current_user() -> Self {
        let profile = env_dir("USERPROFILE");
        let appdata =
            env_dir("APPDATA").or_else(|| Some(profile.as_ref()?.join(r"AppData\Roaming")));
        Self {
            proxy: Arc::new(WinInet),
            env: UserEnv::current_user(),
            git: GitCli::find(),
            gradle_home: env_dir("GRADLE_USER_HOME").or_else(|| Some(profile?.join(".gradle"))),
            studio_root: appdata.map(|dir| dir.join("Google")),
            broadcast: true,
            check_user: true,
        }
    }

    fn git(&self) -> io::Result<&GitCli> {
        self.git
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "git not found"))
    }
}

fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "not a soft-mode target")
}

impl Backend for SoftSystem {
    fn read(&self, target: &Target) -> io::Result<Val> {
        match target {
            Target::Env { var } => env::read(&self.env, *var),
            Target::Git { key } => self.git()?.read(*key),
            Target::Block { kind, path } => block::read(*kind, path),
            Target::StudioOpt { path, option } => studio::read_option(path, *option),
            Target::Lines { path, lines } => block::read_lines(path, lines),
            Target::SystemProxy => sysproxy::read(&*self.proxy),
            Target::Reg { .. } => Err(unsupported()),
        }
    }

    fn write(&self, target: &Target, value: &Val) -> io::Result<bool> {
        match target {
            Target::Env { var } => env::write(&self.env, *var, value),
            Target::Git { key } => self.git()?.write(*key, value),
            Target::Block { kind, path } => {
                block::write(*kind, path, value, *kind == BlockKind::Gradle)
            }
            Target::StudioOpt { path, option } => studio::write_option(path, *option, value),
            Target::Lines { path, lines } if *value == Val::Absent => {
                block::remove_lines(path, lines).map(|()| false)
            }
            Target::SystemProxy => sysproxy::write(&*self.proxy, value),
            Target::Lines { .. } | Target::Reg { .. } => Err(unsupported()),
        }
    }

    fn prune(&self, target: &Target) -> io::Result<()> {
        match target {
            Target::Block { path, .. } | Target::Lines { path, .. } => block::prune(path),
            Target::StudioOpt { path, .. } => studio::prune(path),
            _ => Ok(()),
        }
    }

    fn changed(&self, targets: &[Target]) {
        if self.broadcast
            && targets.iter().any(|t| matches!(t, Target::Env { .. }))
            && let Err(e) = broadcast_change(BROADCAST_TIMEOUT)
        {
            tracing::warn!(error = %e, "environment change broadcast failed");
        }
    }
}

/// The opt-in dev-tool targets of a Soft session (all off by default). Serialized camelCase like
/// the app's other documents (`{"git", "gradle", "androidStudio"}`), missing fields off.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DevTargets {
    pub git: bool,
    pub gradle: bool,
    pub android_studio: bool,
}

impl DevTargets {
    fn features(self) -> impl Iterator<Item = Feature> {
        [
            (self.git, Feature::DevGit),
            (self.gradle, Feature::DevGradle),
            (self.android_studio, Feature::DevStudio),
        ]
        .into_iter()
        .filter_map(|(on, f)| on.then_some(f))
    }
}

/// Outcome of a Soft apply.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SoftReport {
    /// Configured now (`SoftProxy`, then `SoftEnv`, then the dev targets).
    pub applied: Vec<Feature>,
    /// Selected but not installed: skipped, nothing created.
    pub not_detected: Vec<Feature>,
    /// Dev targets of the previous apply that are no longer selected, rolled back now.
    pub dropped: RollbackReport,
}

/// Who the per-user system proxy belongs to right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProxyOwner {
    /// It holds the value Soft mode wrote (journalled and read back).
    Ours,
    /// It holds the user's own settings: Soft never set it, or someone changed it since (kept on
    /// rollback).
    User,
    /// It could not be read: not checked.
    Unreadable,
}

/// Read-back of every Soft feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftStatus {
    /// The second proof of a Soft connection (NOADMIN §2): `Ours` while it is up.
    pub system_proxy: ProxyOwner,
    pub env: TweakState,
    pub git: TweakState,
    pub gradle: TweakState,
    pub android_studio: TweakState,
}

/// The Soft-mode session over the shared journal. Cheap to clone.
#[derive(Clone)]
pub struct Soft {
    journal: Arc<Journal>,
    sys: Arc<SoftSystem>,
}

impl Soft {
    /// Soft mode over `journal` with the targets of `sys`.
    pub fn new(journal: Arc<Journal>, sys: SoftSystem) -> Self {
        Self {
            journal,
            sys: Arc::new(sys),
        }
    }

    /// Points the system proxy, the variables and the selected dev targets at `addr` (the engine's
    /// mixed inbound; `kind` picks the scheme of the variables and dev targets). A refresh while
    /// Soft is on keeps the original baselines; any failure puts back what was there before this
    /// call. No credentials are ever written: they would sit in plain text in the registry and files.
    pub async fn apply(
        &self,
        addr: HostPort,
        kind: ProxyKind,
        dev: DevTargets,
    ) -> AppResult<SoftReport> {
        let this = self.clone();
        run_blocking(move || this.apply_blocking(&addr, kind, dev)).await?
    }

    /// Blocking form of [`Soft::apply`].
    pub fn apply_blocking(
        &self,
        addr: &HostPort,
        kind: ProxyKind,
        dev: DevTargets,
    ) -> AppResult<SoftReport> {
        if self.sys.check_user {
            user::ensure_session_user()?;
        }
        let mut plan = sysproxy::plan(addr);
        plan.extend(env::plan(addr, kind));
        let mut report = SoftReport {
            applied: vec![Feature::SoftProxy, Feature::SoftEnv],
            ..SoftReport::default()
        };
        for feature in dev.features() {
            match self.plan_dev(feature, addr, kind) {
                Ok(steps) => {
                    plan.extend(steps);
                    report.applied.push(feature);
                }
                Err(TweakError::NotDetected(f)) => report.not_detected.push(f),
                Err(e) => return Err(e.into()),
            }
        }
        self.journal.apply(&*self.sys, &plan)?;
        let stale: Vec<Feature> = SOFT_FEATURES
            .into_iter()
            .filter(|f| !report.applied.contains(f) && self.journal.is_applied(*f))
            .collect();
        if !stale.is_empty() {
            report.dropped = self.journal.rollback(&*self.sys, &stale);
        }
        Ok(report)
    }

    fn plan_dev(
        &self,
        feature: Feature,
        addr: &HostPort,
        kind: ProxyKind,
    ) -> Result<Vec<(Feature, Target, Val)>, TweakError> {
        let missing = || TweakError::NotDetected(feature);
        match feature {
            Feature::DevGit => self
                .sys
                .git
                .as_ref()
                .map(|_| git::plan(addr, kind))
                .ok_or_else(missing),
            Feature::DevGradle => {
                let dir = self
                    .sys
                    .gradle_home
                    .as_ref()
                    .filter(|d| d.is_dir())
                    .ok_or_else(missing)?;
                let target = Target::Block {
                    kind: BlockKind::Gradle,
                    path: dir.join(BlockKind::Gradle.file_name()),
                };
                let text = block::render(BlockKind::Gradle, addr, kind);
                Ok(vec![(feature, target, Val::Text(text))])
            }
            Feature::DevStudio => {
                let root = self.sys.studio_root.as_ref().ok_or_else(missing)?;
                let install = studio::newest_install(root)
                    .map_err(|e| TweakError::Unreadable(r"Google\AndroidStudio*".into(), e))?
                    .ok_or_else(missing)?;
                Ok(studio::plan(&install, addr, kind))
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Restores every Soft feature (own values only; failures stay journalled for a retry).
    pub async fn rollback(&self) -> AppResult<RollbackReport> {
        let this = self.clone();
        run_blocking(move || this.rollback_blocking()).await
    }

    /// Blocking form of [`Soft::rollback`].
    pub fn rollback_blocking(&self) -> RollbackReport {
        self.journal.rollback(&*self.sys, &SOFT_FEATURES)
    }

    /// Whether Soft mode holds values (the obligation the startup recovery looks at).
    pub fn is_applied(&self) -> bool {
        SOFT_FEATURES
            .into_iter()
            .any(|f| self.journal.is_applied(f))
    }

    /// Reads every Soft feature back.
    pub async fn status(&self) -> AppResult<SoftStatus> {
        let this = self.clone();
        run_blocking(move || this.status_blocking()).await
    }

    /// Blocking form of [`Soft::status`].
    pub fn status_blocking(&self) -> SoftStatus {
        let state = |f| self.journal.status(&*self.sys, f);
        SoftStatus {
            system_proxy: self.proxy_owner_blocking(),
            env: state(Feature::SoftEnv),
            git: state(Feature::DevGit),
            gradle: state(Feature::DevGradle),
            android_studio: state(Feature::DevStudio),
        }
    }

    /// Reads only the system proxy back (no Git or file reads): the session's read-back.
    pub async fn proxy_owner(&self) -> AppResult<ProxyOwner> {
        let this = self.clone();
        run_blocking(move || this.proxy_owner_blocking()).await
    }

    /// Blocking form of [`Soft::proxy_owner`].
    pub fn proxy_owner_blocking(&self) -> ProxyOwner {
        match self.journal.status(&*self.sys, Feature::SoftProxy) {
            TweakState::On => ProxyOwner::Ours,
            TweakState::Drifted => ProxyOwner::User,
            TweakState::Unknown => ProxyOwner::Unreadable,
            TweakState::Off => match self.sys.read(&Target::SystemProxy) {
                Ok(_) => ProxyOwner::User,
                Err(_) => ProxyOwner::Unreadable,
            },
        }
    }

    /// Points the system proxy at the journalled value again after someone else changed it
    /// (the user's «Вернуть»); the original baseline stays. `false`: nothing journalled.
    pub async fn reclaim_proxy(&self) -> AppResult<bool> {
        let this = self.clone();
        run_blocking(move || this.reclaim_proxy_blocking()).await?
    }

    /// Blocking form of [`Soft::reclaim_proxy`].
    pub fn reclaim_proxy_blocking(&self) -> AppResult<bool> {
        if self.sys.check_user {
            user::ensure_session_user()?;
        }
        let Some(ours) = self.journal.records(Feature::SoftProxy).pop() else {
            return Ok(false);
        };
        self.journal.apply(
            &*self.sys,
            &[(Feature::SoftProxy, ours.target, ours.applied)],
        )?;
        Ok(true)
    }

    /// The crash watcher's rollback of the dead app `writer`'s session: only while that app is
    /// the last process that changed the journal (`None`: someone else did and handles it).
    /// `after` runs under the journal lock ([`Journal::rollback_left`]).
    pub fn rollback_left_by(
        &self,
        writer: Writer,
        after: impl FnOnce(&RollbackReport),
    ) -> Option<RollbackReport> {
        self.journal
            .rollback_left(&*self.sys, &SOFT_FEATURES, |w| w == writer, after)
    }

    /// The logon restore's rollback (RU-2026 14c): the session the journal's last writer left,
    /// once that process is gone (a logoff or a power loss ended it). `None`: it still runs, so
    /// what is journalled is a live session's (the app started at this sign-in) and stays.
    pub fn rollback_orphaned(&self) -> Option<RollbackReport> {
        self.journal
            .rollback_left(&*self.sys, &SOFT_FEATURES, |w| !w.is_running(), |_| {})
    }
}

/// Display name of a Soft feature (for the opt-in list).
pub fn feature_name(feature: Feature) -> Msg {
    Msg::new(match feature {
        Feature::SoftProxy => "automation.tweaks.target.systemProxy.name",
        Feature::DevGit => "automation.tweaks.target.git.name",
        Feature::DevGradle => "automation.tweaks.target.gradle.name",
        Feature::DevStudio => "automation.tweaks.target.studio.name",
        _ => "automation.tweaks.target.env.name",
    })
}

/// What a Soft feature changes while applied (shown next to its switch).
pub fn feature_warning(feature: Feature) -> Msg {
    Msg::new(match feature {
        Feature::SoftProxy => "automation.tweaks.target.systemProxy.warning",
        Feature::DevGit => "automation.tweaks.target.git.warning",
        Feature::DevGradle => "automation.tweaks.target.gradle.warning",
        Feature::DevStudio => "automation.tweaks.target.studio.warning",
        _ => "automation.tweaks.target.env.warning",
    })
}

#[cfg(test)]
mod tests;
