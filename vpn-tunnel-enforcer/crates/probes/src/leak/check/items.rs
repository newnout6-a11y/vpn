//! The card's measured items: proxy, public IPv4 / IPv6, self-test, foreign adapters, DNS.
use std::net::{IpAddr, Ipv6Addr};

use vpnte_base::Msg;

use super::{CheckItem, CheckStatus, Mode, ip_value};
use crate::ip_monitor::IpEvidence;
use crate::leak::self_test::{self, SelfTestResult, SelfTestVerdict};

/// `proxy`: the configured upstream only (never a free-form target, B-LC-5). `reachable` is
/// the TCP probe result (`None` = not probed); `foreign` names another VPN's tunnel.
pub fn proxy_item(
    mode: &Mode,
    tunnel_up: bool,
    reachable: Option<bool>,
    foreign: Option<&str>,
) -> CheckItem {
    let key = |k: &str| Msg::new(format!("probes.leak.check.proxy.{k}"));
    match mode {
        Mode::DirectVpn => {
            CheckItem::new("proxy", CheckStatus::Info, key("directVpn")).detail(key(if tunnel_up {
                "directVpnOn"
            } else {
                "directVpnOff"
            }))
        }
        Mode::LocalProxy {
            upstream: Some(addr),
        } => {
            let value = Msg::new("probes.leak.check.value.text").arg("text", addr);
            match reachable {
                Some(true) => CheckItem::new("proxy", CheckStatus::Ok, value).detail(key("open")),
                Some(false) => {
                    CheckItem::new("proxy", CheckStatus::Fail, value).detail(key("closed"))
                }
                None => CheckItem::new("proxy", CheckStatus::NotChecked, value),
            }
        }
        Mode::LocalProxy { upstream: None } => match foreign {
            Some(name) if !tunnel_up => {
                CheckItem::new("proxy", CheckStatus::Info, key("notNeeded"))
                    .detail(key("externalOnly").arg("name", name))
            }
            _ => CheckItem::new("proxy", CheckStatus::Warn, key("missing"))
                .detail(key("missingDetail")),
        },
    }
}

/// `ipv4`: the address ordinary apps show, against the IP monitor's evidence (B-LC-3): the
/// real IP → `Fail`; the adopted exit → `Ok`; another exit → `Warn`; no answer → `NotChecked`
/// (an unreachable service is not a leak).
pub fn ipv4_item(sample: Option<IpAddr>, evidence: &IpEvidence, tunnel_up: bool) -> CheckItem {
    let key = |k: &str| Msg::new(format!("probes.leak.check.ipv4.{k}"));
    let Some(ip) = sample else {
        return CheckItem::new("ipv4", CheckStatus::NotChecked, key("noAnswer"));
    };
    let (status, detail) = if !tunnel_up {
        (CheckStatus::Info, "tunnelOff")
    } else if evidence.real_ip == Some(ip) {
        (CheckStatus::Fail, "realIp")
    } else if evidence.baseline == Some(ip) {
        (CheckStatus::Ok, "vpnExit")
    } else if evidence.baseline.is_none() {
        (CheckStatus::NotChecked, "noBaseline")
    } else {
        (CheckStatus::Warn, "otherExit")
    };
    CheckItem::new("ipv4", status, ip_value(ip)).detail(key(detail))
}

/// `ipv6` (B-LC-2): no global IPv6 on the physical adapters → `Ok`; an answer inside one of
/// their /64 prefixes → `Fail` (the provider's IPv6 is visible); another answer → `Ok`
/// (through the VPN); no answer although IPv6 exists → `NotChecked`. `physical_v6` is `None`
/// when the adapters could not be enumerated.
pub fn ipv6_item(
    sample: Option<IpAddr>,
    physical_v6: Option<&[Ipv6Addr]>,
    tunnel_up: bool,
) -> CheckItem {
    let key = |k: &str| Msg::new(format!("probes.leak.check.ipv6.{k}"));
    let value = sample.map_or_else(|| key("none"), ip_value);
    let Some(physical) = physical_v6 else {
        return CheckItem::new("ipv6", CheckStatus::NotChecked, value)
            .detail(key("adaptersUnknown"));
    };
    if !tunnel_up {
        return CheckItem::new("ipv6", CheckStatus::Info, value).detail(key("tunnelOff"));
    }
    if physical.is_empty() {
        return CheckItem::new("ipv6", CheckStatus::Ok, key("absent"));
    }
    match sample {
        None => CheckItem::new("ipv6", CheckStatus::NotChecked, value).detail(key("noAnswer")),
        Some(IpAddr::V6(seen)) if physical.iter().any(|p| same_64(*p, seen)) => {
            CheckItem::new("ipv6", CheckStatus::Fail, value).detail(key("realIpv6"))
        }
        Some(_) => CheckItem::new("ipv6", CheckStatus::Ok, value).detail(key("viaVpn")),
    }
}

fn same_64(a: Ipv6Addr, b: Ipv6Addr) -> bool {
    a.segments()[..4] == b.segments()[..4]
}

/// `self-test`: the latest physical-adapter self-test (`None` = not run).
pub fn self_test_item(result: Option<&SelfTestResult>) -> CheckItem {
    let Some(result) = result else {
        return CheckItem::new(
            "self-test",
            CheckStatus::NotChecked,
            Msg::new("probes.leak.check.selfTest.notRun"),
        );
    };
    let report = self_test::report(result);
    let status = match report.verdict {
        SelfTestVerdict::Leak => CheckStatus::Fail,
        SelfTestVerdict::PossibleLeak => CheckStatus::Warn,
        SelfTestVerdict::Ok => CheckStatus::Ok,
        SelfTestVerdict::Inconclusive => CheckStatus::NotChecked,
    };
    let mut item = CheckItem::new("self-test", status, report.headline);
    item.details = report.details;
    item
}

/// `adapters`: other VPNs' tunnels (labels from winnet `foreign_tun::detect`; `None` = the
/// detection failed). With our tunnel off a foreign one is simply the current route.
pub fn adapters_item(foreign: Option<&[String]>, tunnel_up: bool) -> CheckItem {
    let key = |k: &str| Msg::new(format!("probes.leak.check.adapters.{k}"));
    match foreign {
        None => CheckItem::new("adapters", CheckStatus::NotChecked, key("unknown")),
        Some([]) => CheckItem::new("adapters", CheckStatus::Ok, key("none")),
        Some(found) => {
            let names = found.join("; ");
            let value = Msg::new("probes.leak.check.value.text").arg("text", &names);
            if tunnel_up {
                CheckItem::new("adapters", CheckStatus::Warn, value)
                    .detail(key("conflict").arg("name", &names))
            } else {
                CheckItem::new("adapters", CheckStatus::Ok, value)
                    .detail(key("externalRoute").arg("name", &names))
            }
        }
    }
}

/// `dns`: the OS resolver answering for `example.com` (`None` = not probed). Not a leak test:
/// a silent resolver while connected is a warning (B-LC-7), otherwise informational.
pub fn dns_item(resolved: Option<bool>, tunnel_up: bool) -> CheckItem {
    let key = |k: &str| Msg::new(format!("probes.leak.check.dns.{k}"));
    match resolved {
        None => CheckItem::new("dns", CheckStatus::NotChecked, key("notProbed")),
        Some(true) => CheckItem::new("dns", CheckStatus::Info, key("answers")),
        Some(false) if tunnel_up => CheckItem::new("dns", CheckStatus::Warn, key("silent")),
        Some(false) => CheckItem::new("dns", CheckStatus::Info, key("silent")),
    }
}
