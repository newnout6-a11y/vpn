//! Lifecycle tests with fakes: the lane vectors (lifecycle-app §7.1, §7.2), session tracking and
//! history rows (§7.11), orchestration (§6.4) and the bug fixes of §4.
use vpnte_base::types::{Owner, ProxyKind};
use vpnte_core::ops::Source;

use super::{ConnectReq, ConnectTarget, DisconnectReq, StopCause};

mod automation;
mod fakes;
mod joint;
mod killswitch;
mod lane;
mod live_guard;
mod orchestration;
mod outage;
mod sessions;

const PROXY: &str = "127.0.0.1:10808";

/// Hard TUN through the local proxy.
fn local(owner: Owner) -> ConnectReq {
    let target = ConnectTarget::LocalProxy {
        addr: PROXY.into(),
        kind: ProxyKind::Socks5,
    };
    ConnectReq::new(target, owner, Source::Ui)
}

/// Soft mode on `127.0.0.1:<port>`.
fn soft(port: u16, kind: ProxyKind, owner: Owner) -> ConnectReq {
    let target = ConnectTarget::Soft {
        addr: format!("127.0.0.1:{port}"),
        kind,
    };
    ConnectReq::new(target, owner, Source::Ui)
}

/// Direct VPN on `id` (`None` = the active server).
fn direct(id: Option<&str>, owner: Owner) -> ConnectReq {
    let target = ConnectTarget::DirectVpn {
        profile_id: id.map(str::to_owned),
    };
    ConnectReq::new(target, owner, Source::Ui)
}

/// Soft mode through the server `id` (`None` = the active server).
fn soft_vpn(id: Option<&str>, owner: Owner) -> ConnectReq {
    let target = ConnectTarget::SoftVpn {
        profile_id: id.map(str::to_owned),
    };
    ConnectReq::new(target, owner, Source::Ui)
}

fn user_stop() -> DisconnectReq {
    DisconnectReq::new(StopCause::User, Owner::Manual, Source::Ui)
}

/// Every notice has a title in both languages; a body key exists exactly for the notices that
/// do not pass their own body (an outcome headline, a runtime warning).
#[test]
fn notices_are_localized() {
    for (name, with_body) in [
        ("connected", true),
        ("restored", true),
        ("disconnected", true),
        ("stopFailed", false),
        ("stopped", false),
        ("keptBlocked", true),
        ("keptSoftBlocked", true),
        ("paused", true),
        ("keyRejected", true),
        ("reconnecting", true),
        ("failover", true),
        ("restartFailed", false),
        ("internalError", true),
        ("softRestored", true),
        ("softConnected", true),
        ("softResumeFailed", true),
    ] {
        let title = format!("tunnel.lifecycle.notice.{name}.title");
        let body = format!("tunnel.lifecycle.notice.{name}.body");
        assert!(crate::test_locales::has_key(&title), "{title}");
        assert_eq!(crate::test_locales::has_key(&body), with_body, "{body}");
    }
    // The outage notice's other bodies (fix-ks a3, b4).
    for key in ["paused.manual", "reconnecting.direct", "reconnecting.other"] {
        let key = format!("tunnel.lifecycle.notice.{key}");
        assert!(crate::test_locales::has_key(&key), "{key}");
    }
}
