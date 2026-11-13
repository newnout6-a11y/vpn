//! The service body: everything between the SCM's START and STOP. One current-thread tokio
//! runtime (a pipe server needs no worker per core); while idle nothing ticks: the listener waits
//! in an overlapped `ConnectNamedPipe`, the runtime actor on its inbox, and the WFP watchdog runs
//! only while a session's filters are held ([`crate::watchdog`]).
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_base::Msg;
use vpnte_base::types::KillSwitchLevel;
use vpnte_tunnel::api::{Runtime, StopOptions};
use vpnte_tunnel::runtime::{
    Capture, ProxyCapture, RealEngines, RuntimeDeps, Timings, TunCapture, TunnelHandle,
};
use vpnte_winnet::wfp::{EnginePaths, Protection};

use crate::host::{self, Host, HostDeps, SharedInputs, WfpKillSwitch};
use crate::install::pins;
use crate::paths::{self, DataFiles};
use crate::pipe::{Listener, PipeConfig, admit_all};
use crate::sandbox::{self, Sandbox};
use crate::scm::dispatch::Control;
use crate::users::Users;
use crate::watchdog::{self, Engaged};
use crate::{install, sddl};

/// Service log size at which it is rotated (one `.old` generation).
const LOG_LIMIT: u64 = 1 << 20;

/// Runs the service until STOP; the exit code goes to the SCM (non-zero = recovery restarts it).
pub fn run(control: Control) -> u32 {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return 1,
    };
    runtime.block_on(serve(control))
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

fn init_logging(log: &Path) {
    if std::fs::metadata(log).is_ok_and(|m| m.len() > LOG_LIMIT) {
        let _ = std::fs::rename(log, log.with_extension("log.old"));
    }
    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
    else {
        return;
    };
    let _ = tracing_subscriber::fmt()
        .with_writer(std::sync::Mutex::new(file))
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .try_init();
}

async fn serve(control: Control) -> u32 {
    let Ok(exe) = std::env::current_exe() else {
        return 1;
    };
    let Some(dir) = exe.parent().map(Path::to_path_buf) else {
        return 1;
    };
    let Ok(data) = paths::data_dir() else {
        return 1;
    };
    let files = DataFiles::new(&data);
    if files.secure().is_err() {
        return 1;
    }
    let _ = std::fs::create_dir_all(&files.logs);
    init_logging(&files.service_log);
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "service starting");
    let fault = trusted_install(&dir, &exe).err();
    if let Some(fault) = &fault {
        tracing::error!(%fault, "tunnel disabled");
    }
    let trusted = fault.is_none();
    let (singbox, xray) = (dir.join("sing-box.exe"), dir.join("xray.exe"));
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
    let tun = trusted.then(|| Arc::new(Engaged::new(TunCapture::new(protection.clone()))));
    // The WFP watchdog runs while a session's filters are held (crash pause and preserved block
    // included); an idle service has no timer.
    if let Some(tun) = &tun {
        let protection = protection.clone();
        let start = move |token| {
            tokio::spawn(protection.clone().run_watchdog(token));
        };
        tokio::spawn(watchdog::run(tun.holds(), start, control.stop.clone()));
    }
    let runtime = TunnelHandle::spawn(RuntimeDeps {
        engines: Arc::new(RealEngines::new(singbox, xray, Some(files.logs.clone()))),
        tun: tun.map(|t| t as Arc<dyn Capture>),
        proxy: Arc::new(ProxyCapture::new()),
        inputs: inputs.clone(),
        failover: None,
        confirmations: None,
        timings: Timings::default(),
    });
    // Engines may not start programs: each one is confined as soon as it shows up.
    tokio::spawn(sandbox::run(
        Sandbox::new(dir.clone()),
        runtime.status(),
        runtime.subscribe(),
        control.stop.clone(),
    ));
    let removing = Arc::new(AtomicBool::new(false));
    let deps = HostDeps {
        runtime: Arc::new(runtime.clone()),
        kill_switch: Arc::new(WfpKillSwitch::new(
            protection.clone(),
            files.protection.clone(),
        )),
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
    host.keep_sessions_in(files.session.clone());
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
    0
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
}
