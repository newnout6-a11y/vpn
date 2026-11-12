//! The proxy column: projection of the manager's snapshot and the server list, and the actions
//! over a real manager whose list holds no runnable server (nothing starts an engine here).
use std::path::{Path, PathBuf};
use std::sync::Arc;

use vpnte_base::AppError;
use vpnte_base::types::{ClientDevice, EnginePref, now_ms};
use vpnte_core::ops::OperationRegistry;
use vpnte_core::settings::Settings;
use vpnte_core::store::Store;
use vpnte_probes::key_health::ProbeCtx;
use vpnte_probes::ping::NetPath;
use vpnte_proxies::manager::{ProxyManager, ProxySnapshot};
use vpnte_proxies::model::{Degradation, Health, InstanceStatus, Lifecycle, ProxyError};
use vpnte_proxies::slot::Slot;
use vpnte_servers::model::ProfileId;
use vpnte_servers::store::{AddTarget, Servers};
use vpnte_ui::panels::ProxyHealth;

use super::*;
use crate::svc_proxies::ServerProfiles;

const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");
const KEY_A: &str = "vless://00000000-0000-4000-8000-00000000000a@203.0.113.20:443?security=tls&sni=example.com&type=tcp#Fake%20A";
const KEY_B: &str = "vless://00000000-0000-4000-8000-00000000000b@203.0.113.21:443?security=tls&sni=example.com&type=tcp#Fake%20B";

/// A throw-away data dir under %TEMP%, removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("vpnte-wire-column-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn add(servers: &Servers, uri: &str) -> String {
    let profile = vpnte_profiles::uri::parse_uri(uri).unwrap();
    let target = AddTarget::Keys {
        group: None,
        device: ClientDevice::default(),
    };
    servers.add(vec![profile], target).unwrap().added[0]
        .0
        .clone()
}

/// Every listed slot by number (a failed one with the reason in the user's language); the
/// picker offers the list's servers (removed ones left out) and marks the one a running slot
/// uses and the VPN's own.
#[test]
fn the_column_projects_slots_and_choices() {
    let dir = TempDir::new("view");
    let servers = Servers::open(&dir.0);
    let a = add(&servers, KEY_A);
    let b = add(&servers, KEY_B);
    servers.remove(&ProfileId::from(b.as_str())).unwrap();
    let now = now_ms();
    let running = InstanceStatus {
        process_running: true,
        health: Health::Healthy,
        state: Lifecycle::Ready,
        egress_ip: Some("198.51.100.9".parse().unwrap()),
        latency_ms: Some(120),
        last_checked_at: Some(now),
        last_success_at: Some(now),
        port: Some(17991),
        proxy_url: Some("http://127.0.0.1:17991".into()),
        profile_id: Some(a.clone()),
        profile_name: Some("Fake A".into()),
        engine: Some(vpnte_base::types::Engine::Xray),
        ..InstanceStatus::stopped(Slot::new(2).unwrap())
    };
    let failed = InstanceStatus {
        health: Health::Failed,
        state: Lifecycle::Failed,
        last_error: Some("engine exited (code 1)".into()),
        degradation_reason: Some(Degradation::ProcessFailed),
        ..InstanceStatus::stopped(Slot::DEFAULT)
    };
    let snap = ProxySnapshot {
        instances: vec![running, failed],
        at: now,
        ..ProxySnapshot::default()
    };
    let column = view(&snap, &servers.view(), now);
    let slots: Vec<u16> = column.rows.iter().map(|r| r.slot).collect();
    assert_eq!(slots, [1, 2]);
    assert_eq!(column.rows[0].health, ProxyHealth::Failed);
    let reason = column.rows[0].last_error.clone().expect("why it failed");
    assert_eq!(reason, degradation_msg(Degradation::ProcessFailed));
    let row = &column.rows[1];
    assert!(row.process_running && row.ready, "{row:?}");
    assert_eq!((row.port, row.latency_ms), (Some(17991), Some(120)));
    assert_eq!(
        row.engine,
        Some(vpnte_base::types::Engine::Xray),
        "the slot names its engine"
    );
    assert_eq!(column.rows[0].engine, None, "a failed slot runs no engine");
    assert_eq!(column.choices.len(), 1, "the removed server is not offered");
    let choice = &column.choices[0];
    assert_eq!(choice.id, a);
    assert!(choice.in_proxy && choice.vpn_server && !choice.usable());
}

/// The actions reach the manager with the slot the page chose; its refusals become the UI's
/// messages (`proxies.error.*`).
#[tokio::test]
async fn actions_reach_the_manager_and_report_its_refusals() {
    let dir = TempDir::new("actions");
    let probe_ctx: crate::svc_proxies::ProbeCtxFn = Arc::new(|device| ProbeCtx {
        singbox_exe: Path::new(RESOURCES).join("sing-box.exe"),
        xray_exe: Path::new(RESOURCES).join("xray.exe"),
        engine_pref: EnginePref::Auto,
        device,
        net: NetPath { tun_direct: None },
        dns_bootstrap_in: None,
    });
    let source = ServerProfiles {
        servers: Arc::new(Servers::open(&dir.0)),
        settings: Arc::new(Store::<Settings>::open(&dir.0)),
        ops: OperationRegistry::new(),
        probe_ctx,
    };
    let manager = ProxyManager::new(Arc::new(source), Path::new(RESOURCES));
    let start = |slot: u16, id: &str| ProxyAction::Start {
        slot,
        profile_id: id.into(),
    };
    let zero = apply(&manager, start(0, "p")).await.unwrap_err();
    assert!(matches!(zero, ProxyError::BadRequest(_)), "{zero:?}");
    assert_eq!(
        AppError::from(zero).user_msg().key,
        "proxies.error.badRequest"
    );
    let missing = apply(&manager, start(1, "no-such-server"))
        .await
        .unwrap_err();
    assert!(missing.detail().contains("no-such-server"), "{missing:?}");
    assert!(
        apply(&manager, ProxyAction::Rotate(1)).await.is_err(),
        "nothing to rotate to"
    );
    apply(&manager, ProxyAction::StopAll).await.unwrap();
    let snap = manager.snapshot().borrow().clone();
    assert!(snap.instances.iter().all(|i| !i.process_running));
    manager.shutdown().await;
}
