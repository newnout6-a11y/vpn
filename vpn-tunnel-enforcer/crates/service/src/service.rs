//! The service body: everything between the SCM's START and STOP. One current-thread tokio
//! runtime (a pipe server needs no worker per core); while idle nothing ticks: the listener waits
//! in an overlapped `ConnectNamedPipe`, the runtime actor on its inbox, and the WFP watchdog runs
//! only while a session does.
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use vpnte_base::types::KillSwitchLevel;
use vpnte_tunnel::api::{Runtime, StopOptions, TunStatus};
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

/// The service's folder admits writes by administrators only, and so does every file it runs:
/// `Err` names the first file that does not.
pub fn trusted_install(dir: &Path, exe: &Path) -> Result<(), String> {
    let files = pins::FILES.iter().map(|f| dir.join(f));
    [dir.to_owned(), exe.to_owned()]
        .into_iter()
        .chain(files)
        .find_map(|path| sddl::untrusted_reason(&path))
        .map_or(Ok(()), Err)
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
    if paths::secure_dir(&files.root).is_err() {
        return 1;
    }
    let _ = std::fs::create_dir_all(&files.logs);
    init_logging(&files.service_log);
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "service starting");
    let trusted = match trusted_install(&dir, &exe) {
        Ok(()) => true,
        Err(reason) => {
            tracing::error!(%reason, "install folder writable by users: tunnel disabled");
            false
        }
    };
    let (singbox, xray) = (dir.join("sing-box.exe"), dir.join("xray.exe"));
    let protection = Arc::new(Protection::new(
        EnginePaths {
            singbox: singbox.clone(),
            xray: Some(xray.clone()),
            external_proxy: None,
        },
        exe.clone(),
        host::load_settings(&files.protection),
    ));
    // Strict filters from the last run are re-applied, leftovers of a crashed session removed.
    if let Err(err) = protection.startup() {
        tracing::error!(error = %err, "kill switch start-up failed");
    }
    let inputs = Arc::new(SharedInputs::new(Some(dir.clone())));
    let tun = trusted.then(|| Arc::new(TunCapture::new(protection.clone())) as Arc<dyn Capture>);
    let runtime = TunnelHandle::spawn(RuntimeDeps {
        engines: Arc::new(RealEngines::new(singbox, xray, Some(files.logs.clone()))),
        tun,
        proxy: Arc::new(ProxyCapture::new()),
        inputs: inputs.clone(),
        failover: None,
        confirmations: None,
        timings: Timings::default(),
    });
    tokio::spawn(watchdog(
        runtime.status(),
        protection.clone(),
        control.stop.clone(),
    ));
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
        refuse_tunnel: (!trusted).then(host::untrusted_folder),
    };
    let listener = match Listener::bind(&PipeConfig::production()) {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(error = %err, "pipe not created (another instance or a squatter?)");
            protection.shutdown();
            return 2;
        }
    };
    control.running();
    tracing::info!("service running");
    Host::new(deps).serve(listener, control.stop.clone()).await;
    control.stopping(Duration::from_secs(15));
    finish(&runtime, &protection, &exe, removing.load(Ordering::SeqCst)).await;
    0
}

/// The last user left: remember it and stop; `finish` removes the service after the stop.
fn last_user(removing: Arc<AtomicBool>, stop: CancellationToken) -> Arc<dyn Fn() + Send + Sync> {
    Arc::new(move || {
        tracing::info!("the last user left: removing the service");
        removing.store(true, Ordering::SeqCst);
        stop.cancel();
    })
}

/// Stops the tunnel (a strict kill switch keeps blocking: its filters are persistent by
/// design), closes the dynamic WFP session and, after the last user left, removes the service.
async fn finish(runtime: &TunnelHandle, protection: &Arc<Protection>, exe: &Path, remove: bool) {
    let keep_block = protection.settings().level == KillSwitchLevel::Strict && !remove;
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

/// Runs winnet's WFP watchdog only while a session runs: an idle service has no timer.
async fn watchdog(
    mut status: watch::Receiver<TunStatus>,
    protection: Arc<Protection>,
    stop: CancellationToken,
) {
    let mut ticking: Option<CancellationToken> = None;
    loop {
        let session = status.borrow_and_update().capture.is_some();
        match (session, ticking.as_ref()) {
            (true, None) => {
                let token = stop.child_token();
                tokio::spawn(protection.clone().run_watchdog(token.clone()));
                ticking = Some(token);
            }
            (false, Some(token)) => {
                token.cancel();
                ticking = None;
            }
            _ => {}
        }
        tokio::select! {
            () = stop.cancelled() => break,
            changed = status.changed() => if changed.is_err() { break },
        }
    }
}
