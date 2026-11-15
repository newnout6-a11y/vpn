//! Lab F-7 (p-live2): the AutoPilot launch run never probes this app's own listeners and says
//! nothing when no local proxy runs.
use std::net::SocketAddr;

use vpnte_automation::autopilot::{AutoPilotMode, AutoPilotResult, StepStatus};
use vpnte_base::Msg;
use vpnte_base::types::Level;
use vpnte_winnet::process::{SocketRow, TcpState, Transport};

use crate::svc_auto::pilot::local_listeners;
use crate::svc_auto::pilot_notice;

fn listen(addr: &str, pid: u32) -> SocketRow {
    SocketRow {
        transport: Transport::Tcp,
        local: addr.parse::<SocketAddr>().unwrap(),
        remote: None,
        state: Some(TcpState::Listen),
        pid,
    }
}

#[test]
fn own_listeners_are_never_probed() {
    const OWN: u32 = 4242;
    let rows = [
        listen("127.0.0.1:61234", OWN), // the window's edits websocket
        listen("127.0.0.1:17873", OWN), // the control API
        listen("127.0.0.1:10808", 77),  // a VPN client's proxy
        listen("0.0.0.0:7890", 78),
        listen("192.0.2.10:8080", 79), // not reachable through loopback
    ];
    let found = local_listeners(&rows, OWN, |pid| format!("p{pid}"));
    let ports: Vec<u16> = found.iter().map(|l| l.port).collect();
    assert_eq!(ports, [10808, 7890]);
    assert_eq!(found[0].process, "p77");
}

fn result(summary: StepStatus, name: &str) -> AutoPilotResult {
    AutoPilotResult {
        ran_at: 0,
        summary,
        mode: AutoPilotMode::Off,
        title: Msg::new(format!("automation.autopilot.{name}Title")),
        message: Msg::new(format!("automation.autopilot.{name}")),
        changed: false,
        steps: Vec::new(),
    }
}

#[test]
fn nothing_found_raises_no_notice() {
    assert!(pilot_notice(&result(StepStatus::Info, "noProxy")).is_none());
    let failed = pilot_notice(&result(StepStatus::Fail, "failed")).unwrap();
    assert_eq!(failed.level, Level::Error);
    let started = pilot_notice(&result(StepStatus::Ok, "success")).unwrap();
    assert_eq!(started.level, Level::Success);
}
