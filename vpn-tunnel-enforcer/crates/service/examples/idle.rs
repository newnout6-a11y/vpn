//! Idle footprint of the service's serving stack, measured unelevated: the same current-thread
//! runtime, the real tunnel runtime (`RealEngines`, no TUN) and the real host behind a private
//! pipe, waiting for clients. Prints the working set, private bytes and the CPU time spent while
//! idle (no timer should wake the process: expect 0 ms).
//!
//! `cargo run -p vpnte-service --example idle [--release] -- [seconds]` (default 20).
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use vpnte_service::host::{Host, HostDeps, SharedInputs, WfpKillSwitch};
use vpnte_service::pipe::{Listener, PipeConfig, admit_all};
use vpnte_service::users::Users;
use vpnte_tunnel::runtime::{ProxyCapture, RealEngines, RuntimeDeps, Timings, TunnelHandle};
use vpnte_winnet::wfp::{EnginePaths, Protection, ProtectionSettings};
use windows::Win32::Foundation::FILETIME;
use windows::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX,
};
use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");

fn memory() -> (f64, f64) {
    let mut c = PROCESS_MEMORY_COUNTERS_EX {
        cb: size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        ..Default::default()
    };
    // SAFETY: the struct is sized and passed with its size.
    let _ = unsafe {
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            (&raw mut c).cast::<PROCESS_MEMORY_COUNTERS>(),
            c.cb,
        )
    };
    let mb = |b: usize| b as f64 / (1024.0 * 1024.0);
    (mb(c.WorkingSetSize), mb(c.PrivateUsage))
}

fn cpu_ms() -> u64 {
    let (mut created, mut exited, mut kernel, mut user) = Default::default();
    // SAFETY: out pointers are locals.
    let _ = unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    };
    let ticks = |t: FILETIME| (u64::from(t.dwHighDateTime) << 32) | u64::from(t.dwLowDateTime);
    (ticks(kernel) + ticks(user)) / 10_000
}

fn main() {
    let seconds: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let dir = std::env::temp_dir().join(format!("vpnte-idle-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let resources = std::path::Path::new(RESOURCES);
        let (singbox, xray) = (resources.join("sing-box.exe"), resources.join("xray.exe"));
        let protection = Arc::new(Protection::new(
            EnginePaths {
                singbox: singbox.clone(),
                xray: Some(xray.clone()),
                external_proxy: None,
            },
            std::env::current_exe().expect("exe"),
            ProtectionSettings::default(),
        ));
        let inputs = Arc::new(SharedInputs::new(None));
        let tunnel = TunnelHandle::spawn(RuntimeDeps {
            engines: Arc::new(RealEngines::new(singbox, xray, Some(dir.clone()))),
            tun: None,
            proxy: Arc::new(ProxyCapture::new()),
            inputs: inputs.clone(),
            failover: None,
            confirmations: None,
            timings: Timings::default(),
        });
        let host = Host::new(HostDeps {
            runtime: Arc::new(tunnel),
            kill_switch: Arc::new(WfpKillSwitch::new(protection, dir.join("protection.json"))),
            inputs,
            users: Arc::new(Users::open(&dir.join("users.json"))),
            check: admit_all(),
            on_last_user: Arc::new(|| {}),
            service_version: "idle".into(),
            refuse_tunnel: None,
        });
        let config = PipeConfig {
            name: format!(r"\\.\pipe\vpnte-idle-{}", std::process::id()),
            sddl: "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)".into(),
        };
        let cancel = CancellationToken::new();
        let serving =
            tokio::spawn(host.serve(Listener::bind(&config).expect("pipe"), cancel.clone()));
        // Let start-up settle (and the blocking pool's idle threads exit) before measuring.
        tokio::time::sleep(Duration::from_secs(12)).await;
        let (cpu_before, (ws_before, _)) = (cpu_ms(), memory());
        tokio::time::sleep(Duration::from_secs(seconds)).await;
        let (cpu_after, (ws, private)) = (cpu_ms(), memory());
        println!(
            "idle {seconds} s: working set {ws_before:.1} -> {ws:.1} MB, private {private:.1} MB, \
             CPU {} ms",
            cpu_after.saturating_sub(cpu_before)
        );
        cancel.cancel();
        let _ = serving.await;
        let _ = std::fs::remove_dir_all(&dir);
    });
}
