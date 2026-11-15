//! Lab live-12 L12-4: a fresh connect and a switch judge the same evidence alike; the leak fact,
//! the mascot and the tray's route check say what the start page's same-exit line says.
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use vpnte_base::Msg;
use vpnte_base::i18n::Lang;
use vpnte_base::types::Verdict;
use vpnte_probes::ip_monitor::{IpEvidence, IpVerdict};
use vpnte_probes::leak::{CheckItem, CheckReport, CheckStatus};
use vpnte_probes::public_ip::IpSample;
use vpnte_tunnel::api::TunStatus;
use vpnte_tunnel::fsm::{Transition, TunnelMode, TunnelSnapshot, TunnelState};
use vpnte_ui::dashboard::SameExit;
use vpnte_view::swiss::{ConnView, Mode};

use super::project;

const HOME: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
const EXIT: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));

fn read(ip: IpAddr, verdict: IpVerdict) -> IpEvidence {
    IpEvidence {
        baseline: None,
        real_ip: Some(HOME),
        last: Some(IpSample {
            ip,
            provider: 0,
            at: 1_700_000_000_000,
        }),
        fresh: true,
        verdict,
    }
}

fn proven(exit: Option<IpAddr>) -> TunStatus {
    TunStatus {
        running: true,
        proven_exit: exit,
        ..TunStatus::default()
    }
}

fn connected() -> TunnelSnapshot {
    TunnelSnapshot {
        state: TunnelState::Connected,
        ..TunnelSnapshot::default()
    }
}

fn item(id: &'static str, status: CheckStatus) -> CheckItem {
    CheckItem {
        id,
        label: Msg::new(format!("probes.leak.check.label.{id}")),
        status,
        value: Msg::new("v"),
        details: Vec::new(),
    }
}

fn report(items: Vec<CheckItem>) -> CheckReport {
    CheckReport::new(items)
}

/// The calm line's exit reads «не проверен»: not a leak, and not «VPN-IP изменился», which
/// the old `Warn` said beside it.
#[test]
fn the_calm_exit_is_not_checked_and_no_leak() {
    let (exit, _) = project::exit_ip(&connected(), &read(HOME, IpVerdict::Failed), None, Lang::Ru);
    let calm = project::calm_exit(exit);
    assert!(!calm.leak);
    assert_eq!(calm.verdict, Verdict::NotChecked);
}

/// The log's facts name the proof against the address without our VPN, never the address;
/// nothing is judged before the session settled.
#[test]
fn the_exit_facts_say_where_the_proof_saw_the_exit() {
    let home_read = read(HOME, IpVerdict::Failed);
    let facts = |exit| project::exit_facts(&connected(), &proven(exit), &home_read, false);
    let f = facts(Some(HOME)).expect("judged");
    assert_eq!(
        (f.verdict, f.read_is_home, f.proven),
        (SameExit::Server, true, "home")
    );
    let f = facts(Some(EXIT)).expect("judged");
    assert_eq!((f.verdict, f.proven), (SameExit::No, "elsewhere"));
    assert_eq!(facts(None).expect("judged").proven, "none");
    let busy = TunnelSnapshot {
        transition: Some(Transition::Reconnecting),
        ..connected()
    };
    assert_eq!(
        project::exit_facts(&busy, &proven(Some(HOME)), &home_read, false),
        None
    );
    let other_read = read(EXIT, IpVerdict::Indeterminate);
    let f = project::exit_facts(&connected(), &proven(Some(HOME)), &other_read, false);
    assert_eq!(
        f.map(|f| (f.verdict, f.read_is_home)),
        Some((SameExit::No, false))
    );
}

/// The same evidence, the same verdict: whichever of the read and the proof landed first (a
/// fresh connect publishes the proof before the monitor starts, a switch after its select),
/// the page judges what it holds now.
#[test]
fn the_order_of_the_read_and_the_proof_does_not_matter() {
    let snap = connected();
    let failed = read(HOME, IpVerdict::Failed);
    let before = project::same_exit(&snap, &proven(None), &failed, false);
    let after = project::same_exit(&snap, &proven(Some(HOME)), &failed, false);
    assert_eq!((before, after), (SameExit::No, SameExit::Server));
    let not_yet = IpEvidence {
        last: None,
        verdict: IpVerdict::NotChecked,
        ..failed
    };
    let proof_first = project::same_exit(&snap, &proven(Some(HOME)), &not_yet, false);
    assert_eq!(
        proof_first,
        SameExit::No,
        "nothing read yet: nothing to explain"
    );
}

/// The check's public IPv4 on the address without our VPN is explained by the same exit; a
/// failure of any other item stays a leak.
#[test]
fn the_same_exit_explains_only_the_public_ipv4() {
    let ok = |id| item(id, CheckStatus::Ok);
    let alone = report(vec![item("ipv4", CheckStatus::Fail), ok("ipv6"), ok("dns")]);
    assert_eq!(alone.summary, CheckStatus::Fail);
    assert_eq!(project::explained_leak_status(&alone), CheckStatus::Warn);
    let (status, headline) = project::shown_check(&alone, true);
    assert_eq!(status, CheckStatus::Warn);
    assert_eq!(headline.key, "probes.leak.check.summary.warn");
    assert_eq!(project::shown_check(&alone, false).0, CheckStatus::Fail);
    let real = report(vec![
        item("ipv4", CheckStatus::Fail),
        item("ipv6", CheckStatus::Fail),
    ]);
    assert_eq!(project::explained_leak_status(&real), CheckStatus::Fail);
    let dns = report(vec![ok("ipv4"), item("dns", CheckStatus::Fail)]);
    assert_eq!(project::shown_check(&dns, true).0, CheckStatus::Fail);
}

/// Tunnel mode: the page's explanation covers the check; Proxy mode keeps «Вне прокси» (the
/// check reads the programs outside the proxy there); no explanation, no change.
#[test]
fn only_a_tunnel_sessions_explained_exit_covers_the_check() {
    let conn = |mode| ConnView {
        mode,
        ..ConnView::default()
    };
    for same in [SameExit::Server, SameExit::OtherVpn] {
        assert!(project::ipv4_explained(&conn(Some(Mode::Tun)), same));
        assert!(!project::ipv4_explained(&conn(Some(Mode::Soft)), same));
    }
    assert!(!project::ipv4_explained(
        &conn(Some(Mode::Tun)),
        SameExit::No
    ));
}

/// The hub: a Tunnel session whose read and proof are the address without our VPN shows the
/// check's real-address IPv4 as a warning, and the mascot hears the same; a Proxy session
/// keeps the failure for its own fact. (Another VPN that owns this PC's default route explains
/// it the same way.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_leak_fact_follows_the_same_exit_line() {
    use vpnte_ui::dashboard::DashboardApi;

    use super::flows::setup;
    use super::traits::Dashboard;

    let (hub, fake, _dir) = setup("l12-leak");
    let dash = Dashboard(hub.clone());
    fake.evidence.send_replace(read(HOME, IpVerdict::Failed));
    fake.status.send_replace(proven(Some(HOME)));
    *fake.leak.lock() = Some(report(vec![item("ipv4", CheckStatus::Fail)]));
    for (mode, seen, shown) in [
        (TunnelMode::Tun, Mode::Tun, Verdict::Warn),
        (TunnelMode::Soft, Mode::Soft, Verdict::Fail),
    ] {
        fake.snapshot.send_modify(|s| {
            s.revision += 1;
            s.state = TunnelState::Connected;
            s.mode = Some(mode);
        });
        let mut view = dash.state();
        let calm = view.wait_for(|v| v.same_exit != SameExit::No && v.conn.mode == Some(seen));
        let calm = tokio::time::timeout(Duration::from_secs(5), calm).await;
        assert!(
            calm.is_ok_and(|seen| seen.is_ok()),
            "{mode:?}: no calm line"
        );
        let check = tokio::time::timeout(Duration::from_secs(10), dash.run_leak_check());
        let verdict = check.await.expect("in time").expect("ran");
        assert_eq!(verdict, shown, "{mode:?}: the mascot's verdict");
        assert_eq!(
            dash.state().borrow().leak,
            shown,
            "{mode:?}: the page's fact"
        );
    }
}
