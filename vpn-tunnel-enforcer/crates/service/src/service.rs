//! The service body: everything between the SCM's START and STOP. One current-thread tokio
//! runtime (a pipe server needs no worker per core); while idle nothing ticks: the listener waits
//! in an overlapped `ConnectNamedPipe`, the runtime actor on its inbox, and the WFP watchdog with
//! the re-checks on wake / network change and the leak self-test (`recheck`) runs only while a
//! session's filters are held ([`crate::watchdog`]).
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::KillSwitchLevel;
use vpnte_probes::leak::{SelfTester, SystemEnv, WatchConfig};
use vpnte_tunnel::api::{CaptureKind, Runtime, StopOptions};
use vpnte_tunnel::runtime::{
    Capture, ProxyCapture, RealEngines, RuntimeDeps, Timings, TunCapture, TunnelHandle,
};
use vpnte_update::download::sha256_of;
use vpnte_update::policy;
use vpnte_update::version::Version;
use vpnte_winnet::adapters;
use vpnte_winnet::wfp::{EnginePaths, Protection};

use crate::host::{self, Host, HostDeps, SharedInputs, WfpKillSwitch};
use crate::install::pins;
use crate::paths::{self, DataFiles};
use crate::pipe::{Listener, PipeConfig, admit_all};
use crate::sandbox::{self, Sandbox};
use crate::scm::dispatch::Control;
use crate::update::engines::ServiceEngines;
use crate::update::in_flight::{Counted, InFlight};
use crate::update::source::Mirrors;
use crate::update::swap::{self, AtStart, SwapFiles};
use crate::update::trial::Judged;
use crate::update::{self, RESTART_EXIT, Updates, UpdatesDeps};
use crate::users::Users;
use crate::watchdog::{self, Engaged};
use crate::{install, sddl};

mod recheck;

use recheck::Recheck;

/// Debounce of the network-change watch behind the re-checks (a Wi-Fi join flaps several times).
const NET_SETTLE: Duration = Duration::from_millis(1500);

/// Runs the service until STOP; the exit code goes to the SCM (non-zero = recovery restarts it).
pub fn run(control: Control) -> u32 {
    let Ok(exe) = std::env::current_exe() else {
        return 1;
    };
    // First, before anything that could fail (the runtime's build included: svcupd-a9): a fresh
    // exe counts its trial, a failed one puts the previous exe back (p-svc-update).
    let swap_files = SwapFiles::new(&exe);
    let own = policy::app_version();
    let at_start = staging_trusted(&swap_files).then(|| swap::at_start(&swap_files, own));
    if let Some(Ok(AtStart::RolledBack(_))) = at_start {
        return RESTART_EXIT;
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return 1,
    };
    runtime.block_on(serve(control, exe, swap_files, at_start))
}

/// Why the service does not run engines from its folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FolderFault {
    /// A file is gone (an antivirus quarantined an engine, say): not a tampering alarm.
    Missing(String),
    /// The folder or a file admits writes by non-admins: the reason names which and why.
    Untrusted(String),
}

impl FolderFault {
    /// What a refused start says (review service-b6).
    pub fn msg(&self) -> Msg {
        match self {
            Self::Missing(file) => Msg::new("service.folder.fileMissing").arg("file", file.clone()),
            Self::Untrusted(_) => host::untrusted_folder(),
        }
    }
}

impl std::fmt::Display for FolderFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(file) => write!(f, "{file} is missing"),
            Self::Untrusted(reason) => f.write_str(reason),
        }
    }
}

/// The service's folder admits writes by administrators only, and so does every file it runs:
/// `Err` names the first one missing or not admin-only.
pub fn trusted_install(dir: &Path, exe: &Path) -> Result<(), FolderFault> {
    let files = pins::FILES.iter().map(|f| dir.join(f));
    for path in [dir.to_owned(), exe.to_owned()].into_iter().chain(files) {
        if std::fs::symlink_metadata(&path).is_err() {
            let name = path.file_name().unwrap_or(path.as_os_str());
            return Err(FolderFault::Missing(name.to_string_lossy().into_owned()));
        }
        if let Some(reason) = sddl::untrusted_reason(&path) {
            return Err(FolderFault::Untrusted(reason));
        }
    }
    Ok(())
}

async fn serve(
    control: Control,
    exe: PathBuf,
    swap_files: SwapFiles,
    at_start: Option<io::Result<AtStart>>,
) -> u32 {
    let Some(dir) = exe.parent().map(Path::to_path_buf) else {
        return 1;
    };
    let own = policy::app_version();
    let Ok(data) = paths::data_dir() else {
        return 1;
    };
    let files = DataFiles::new(&data);
    if files.secure().is_err() {
        return 1;
    }
    let _ = std::fs::create_dir_all(&files.logs);
    // Without its log the service still runs (a full or broken disk must not stop the tunnel).
    let _ = crate::logs::init(&files.private);
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "service starting");
    if let Some(Ok(AtStart::Trial(_))) = at_start
        && wintun_refused(&dir)
    {
        // The feed never brings Wintun: a release that changed it needs its installer (a8).
        match swap::give_up(&swap_files) {
            Ok(back) => {
                tracing::warn!(%back, "wintun.dll is not this release's: back to the previous service");
                return RESTART_EXIT;
            }
            Err(err) => tracing::error!(%err, "service update not rolled back"),
        }
    }
    // The engines of the next session start: a version the updater installed, else the bundled.
    let engines = Arc::new(ServiceEngines::open(&dir));
    let record = files.private.join("update.json");
    if update_at_start(&swap_files, own, at_start.as_ref(), &record, &engines) {
        return RESTART_EXIT;
    }
    let fault = trusted_install(&dir, &exe).err();
    if let Some(fault) = &fault {
        tracing::error!(%fault, "tunnel disabled");
    }
    let trusted = fault.is_none();
    let exes = engines.exes();
    let (singbox, xray) = {
        let current = exes.borrow();
        (current.singbox.clone(), current.xray.clone())
    };
    // This service owns our filters (owner decision 12.11.2026): "Always" is kept here, under a
    // provider registered with the service's name, and "If the VPN drops" is static, so its block
    // outlives a crash of the service until Windows restarts it (research killswitch §5.4).
    let protection = Arc::new(Protection::in_service(
        EnginePaths {
            singbox: singbox.clone(),
            xray: Some(xray.clone()),
            external_proxy: None,
        },
        exe.clone(),
        host::load_settings(&files.protection),
        paths::SERVICE_NAME,
    ));
    // "Always" filters are re-applied; a crashed run's held block is taken over, the rest of it
    // and persistent leftovers of a level no longer in force are removed.
    if let Err(err) = protection.startup() {
        tracing::error!(error = %err, "kill switch start-up failed");
    }
    let inputs = Arc::new(SharedInputs::new(Some(dir.clone())));
    let permitted = vec![singbox.clone(), xray.clone()];
    let tun = trusted.then(|| {
        let capture = Engaged::new(TunCapture::new(protection.clone()));
        Arc::new(capture.with_engines(exes.clone(), permitted))
    });
    let holds = tun.as_ref().map(|t| t.holds());
    let held = holds.clone().unwrap_or_else(|| watch::channel(false).1);
    let real = RealEngines::following(exes, Some(files.logs.clone()));
    let starts = real.starts();
    let runtime = TunnelHandle::spawn(RuntimeDeps {
        engines: Arc::new(real),
        tun: tun.map(|t| t as Arc<dyn Capture>),
        proxy: Arc::new(ProxyCapture::new()),
        inputs: inputs.clone(),
        failover: None,
        confirmations: None,
        timings: Timings::default(),
    });
    // While a session's filters are held (crash pause and preserved block included): the WFP
    // watchdog, and the re-checks on wake and network change with the leak self-test (RU audit
    // item 11). An idle service has no timer.
    let recheck = holds.map(|holds| {
        let recheck = recheck_for(&protection, &runtime);
        let (protection, held, stop) = (protection.clone(), recheck.clone(), control.clone());
        let start = move |token: CancellationToken| {
            tokio::spawn(protection.clone().run_watchdog(token.clone()));
            let changes = adapters::watch_network(NET_SETTLE, token.clone())
                .inspect_err(|err| tracing::warn!(%err, "no network-change watch"))
                .ok();
            tokio::spawn(held.clone().run(stop.resumes(), changes, token));
        };
        tokio::spawn(watchdog::run(holds, start, control.stop.clone()));
        recheck
    });
    // Engines may not start programs: each one is confined as soon as it shows up.
    tokio::spawn(sandbox::run(
        Sandbox::new(dir.clone()),
        runtime.status(),
        runtime.subscribe(),
        control.stop.clone(),
    ));
    let removing = Arc::new(AtomicBool::new(false));
    // The engines' trial hears how each start the host asked for ended (svcupd-a5), and the
    // updater sees every start and filter change of the host from its first step (svcfix-a4).
    let in_flight = InFlight::default();
    let judged = Judged::new(
        Arc::new(runtime.clone()),
        engines.clone(),
        starts,
        in_flight.clone(),
    );
    let wfp = WfpKillSwitch::new(protection.clone(), files.protection.clone());
    let deps = HostDeps {
        runtime: Arc::new(judged),
        kill_switch: Arc::new(Counted::new(wfp, in_flight.clone())),
        inputs,
        users: Arc::new(Users::open(&files.users)),
        check: admit_all(),
        on_last_user: last_user(removing.clone(), control.stop.clone()),
        service_version: env!("CARGO_PKG_VERSION").to_owned(),
        refuse_tunnel: fault.as_ref().map(FolderFault::msg),
    };
    let listener = match Listener::bind(&PipeConfig::production()) {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(error = %err, "pipe not created (another instance or a squatter?)");
            protection.shutdown();
            return 2;
        }
    };
    let host = Host::new(deps);
    crate::logs::attribute({
        let host = Arc::downgrade(&host);
        move || {
            host.upgrade()
                .map_or(crate::logs::Owner::Service, |h| h.log_owner())
        }
    });
    host.keep_sessions_in(files.session.clone());
    if let Some(recheck) = &recheck {
        host.report_self_tests(recheck.results.subscribe());
    }
    let restart = Arc::new(AtomicBool::new(false));
    let level = protection.clone();
    let updates = Updates::new(UpdatesDeps {
        own,
        keys: policy::trusted_keys(),
        source: Arc::new(Mirrors),
        engines,
        files: swap_files.clone(),
        record,
        status: runtime.status(),
        events: runtime.subscribe(),
        holds: held,
        always: Arc::new(move || level.level_in_force() == KillSwitchLevel::Strict),
        in_flight,
        probe: swap::probe,
        restart: restarter(restart.clone(), control.stop.clone()),
        stop: control.stop.clone(),
    });
    host.serve_updates(Arc::new(updates.clone()));
    tokio::spawn(updates.run());
    if let Some(Ok(AtStart::Trial(_))) = at_start {
        tokio::spawn(settle_trial(swap_files, control.stop.clone()));
    }
    control.running();
    tracing::info!("service running");
    let resume = protection.paused() || protection.level_in_force() == KillSwitchLevel::Strict;
    if resume {
        let cancel = control.stop.child_token();
        tokio::spawn(resume_session(host.clone(), protection.clone(), cancel));
    }
    host.serve(listener, control.stop.clone()).await;
    control.stopping(Duration::from_secs(15));
    finish(&runtime, &protection, &exe, removing.load(Ordering::SeqCst)).await;
    if restart.load(Ordering::SeqCst) {
        RESTART_EXIT
    } else {
        0
    }
}

/// The staging folder is ours: absent, or admin-only (it holds the exe the service may run next).
fn staging_trusted(files: &SwapFiles) -> bool {
    !files.staging.exists() || sddl::path_admin_only(&files.staging)
}

/// A fresh exe on trial needs the Wintun its pins accept, and the feed never brings it: a
/// wintun.dll in the install folder that is not this release's (one that changed it) means the
/// release's installer has to run. A missing file is the folder check's to report.
fn wintun_refused(dir: &Path) -> bool {
    let sha = std::fs::File::open(dir.join("wintun.dll")).and_then(|mut f| sha256_of(&mut f));
    sha.is_ok_and(|sha| pins::pin("wintun.dll") != Some(sha))
}

/// Logs what the start found; `true` = a verified release waits staged for this start and is
/// now in place (the service exits for the SCM to start it, before anything runs). `record`:
/// the updater's record (a staged release from a feed older than the accepted one stays out);
/// `engines`: what Tunnel mode runs (the release must fit them: svcfix-a1).
fn update_at_start(
    files: &SwapFiles,
    own: Version,
    found: Option<&io::Result<AtStart>>,
    record: &Path,
    engines: &ServiceEngines,
) -> bool {
    match found {
        None => {
            tracing::warn!(dir = %files.staging.display(), "update folder writable by users: ignored")
        }
        Some(Err(err)) => tracing::warn!(%err, "update trial not read"),
        Some(Ok(AtStart::Trial(n))) => tracing::info!(start = n, "fresh service version on trial"),
        // Once, by the first start after the rollback (svcfix-b4).
        Some(Ok(AtStart::After(version))) => {
            tracing::warn!(%version, "a service update failed its trial and was rolled back")
        }
        Some(Ok(_)) => {}
    }
    if found.is_none() || !policy::keys_ready() {
        return false;
    }
    let max_seq = update::accepted_seq(record);
    let keys = policy::trusted_keys();
    let Some(staged) = update::staged_release(files, keys, own, max_seq, engines) else {
        return false;
    };
    let (staged, version) = (staged.exe, staged.version);
    match swap::swap_in(files, &staged, own, version) {
        Ok(()) => {
            tracing::info!(%version, "staged service update swapped in at start: restarting");
            true
        }
        Err(err) => {
            tracing::error!(%version, %err, "staged service update not swapped in");
            false
        }
    }
}

/// A start that ran [`swap::TRIAL_RUN`] ends the trial of a fresh exe.
async fn settle_trial(files: SwapFiles, stop: CancellationToken) {
    tokio::select! {
        () = stop.cancelled() => {}
        () = tokio::time::sleep(swap::TRIAL_RUN) => {
            swap::settled(&files);
            tracing::info!("fresh service version passed its trial");
        }
    }
}

/// An update asks to restart: remember it and stop (the exit code makes the SCM start the exe
/// now in place).
fn restarter(restart: Arc<AtomicBool>, stop: CancellationToken) -> Arc<dyn Fn() + Send + Sync> {
    Arc::new(move || {
        restart.store(true, Ordering::SeqCst);
        stop.cancel();
    })
}

/// The re-checks over the real filters, runtime and curl: self-tests while a TUN session runs
/// with the kill switch on, judged against the level in force.
fn recheck_for(protection: &Arc<Protection>, runtime: &TunnelHandle) -> Arc<Recheck> {
    let (tick, gate, level) = (protection.clone(), protection.clone(), protection.clone());
    let status = runtime.status();
    Arc::new(Recheck {
        tick: Arc::new(move || tick.watchdog_tick()),
        tester: Arc::new(SelfTester::new(Arc::new(SystemEnv))),
        config: WatchConfig::default(),
        gate: Arc::new(move || {
            let s = status.borrow();
            s.running
                && s.capture == Some(CaptureKind::Tun)
                && gate.level_in_force() != KillSwitchLevel::Off
        }),
        level: Arc::new(move || level.level_in_force()),
        results: watch::channel(None).0,
        settle: recheck::SETTLE,
    })
}

/// After a crash that left a held drop, or with "Always" (connect at Windows start), the last
/// session starts again for its user's app to take over; a held drop with nothing to resume is
/// let go (never a block nobody can see or end).
async fn resume_session(host: Arc<Host>, protection: Arc<Protection>, cancel: CancellationToken) {
    if host.resume(cancel).await || !protection.paused() {
        return;
    }
    tracing::info!("no session to resume: the held block is lifted");
    let released = tokio::task::spawn_blocking(move || protection.disconnected()).await;
    if !matches!(released, Ok(Ok(()))) {
        tracing::warn!("the held block was not lifted; a reboot clears it");
    }
}

/// The last user left: remember it and stop; `finish` removes the service after the stop.
fn last_user(removing: Arc<AtomicBool>, stop: CancellationToken) -> Arc<dyn Fn() + Send + Sync> {
    Arc::new(move || {
        tracing::info!("the last user left: removing the service");
        removing.store(true, Ordering::SeqCst);
        stop.cancel();
    })
}

/// Stops the tunnel ("Always" in force keeps blocking: its filters are persistent by design),
/// closes the dynamic WFP session and, after the last user left, removes the service.
async fn finish(runtime: &TunnelHandle, protection: &Arc<Protection>, exe: &Path, remove: bool) {
    let keep_block = protection.level_in_force() == KillSwitchLevel::Strict && !remove;
    let receipt = runtime
        .stop(StopOptions {
            preserve_protection: keep_block,
            preserve_last: false,
        })
        .await;
    tracing::info!(ok = receipt.ok, forced = receipt.forced, "tunnel stopped");
    let protection = protection.clone();
    let exe = exe.to_path_buf();
    let _ = tokio::task::spawn_blocking(move || {
        protection.shutdown();
        if remove {
            install::remove_self(&exe);
        }
    })
    .await;
    tracing::info!("service stopped");
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// Review service-b6: a missing engine is reported as missing, not as tampering.
    #[test]
    fn a_missing_file_is_not_a_tampering_alarm() {
        let root = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"));
        let system = root.join("System32");
        let fault = trusted_install(&system, &system.join("notepad.exe")).expect_err("no engines");
        assert_eq!(fault, FolderFault::Missing("sing-box.exe".into()));
        assert_eq!(fault.msg().key, "service.folder.fileMissing");
        let temp = std::env::temp_dir();
        let fault = trusted_install(&temp, &temp.join("x.exe")).expect_err("user-writable");
        assert!(matches!(fault, FolderFault::Untrusted(_)), "{fault:?}");
        assert_eq!(fault.msg().key, "service.folder.untrusted");
    }

    /// p-svc-update: what the update folder holds is used at start only from a folder users
    /// cannot change (none yet is fine: nothing is staged).
    #[test]
    fn the_update_folder_counts_only_when_admin_only() {
        let temp = std::env::temp_dir().join(format!("vpnte-svc-staging-{}", std::process::id()));
        let files = SwapFiles::new(&temp.join("vpnte-service.exe"));
        assert!(staging_trusted(&files), "absent");
        std::fs::create_dir_all(&files.staging).expect("user-writable folder");
        assert!(!staging_trusted(&files));
        let _ = std::fs::remove_dir_all(&temp);
    }

    /// svcupd-a8: a fresh exe gives its trial up only for a wintun.dll that is there and not
    /// this release's (the feed never brings Wintun); a missing one is the folder check's.
    #[test]
    fn only_another_releases_wintun_ends_a_trial() {
        let temp = std::env::temp_dir().join(format!("vpnte-svc-wintun-{}", std::process::id()));
        std::fs::create_dir_all(&temp).expect("temp");
        assert!(!wintun_refused(&temp), "missing");
        std::fs::write(temp.join("wintun.dll"), b"another release").expect("wintun");
        assert!(wintun_refused(&temp));
        let _ = std::fs::remove_dir_all(&temp);
        let resources = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources"));
        if resources.join("wintun.dll").is_file() {
            assert!(!wintun_refused(resources), "the release's own");
        }
    }
}
