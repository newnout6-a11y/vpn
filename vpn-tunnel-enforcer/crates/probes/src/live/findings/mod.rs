//! Typed findings (live-probe §3.10 with B-03, B-06, B-08, B-09, B-14, B-15, B-19): a pure rule
//! table over the check and the previous good check. Texts are message keys
//! (`probes.live.finding.<rule>.{title,detail}`); the Russian wording of the old app is in the
//! locale fragment. Order = table order (the UI shows them as listed).
mod network;
mod tunnel;

use std::collections::BTreeMap;
use std::net::IpAddr;

use vpnte_base::Msg;

use super::diff::{HistoryDiff, diff};
use super::model::{Evidence, Finding, FindingCode as C, LiveCheck, Severity};
use crate::live_stages::target::{TargetClass, classify_target};
use crate::live_stages::{Text, TimedStatus};
use network::network_rules;
use tunnel::tunnel_rules;

const HIGH_LATENCY_WARNING_MS: u64 = 250;
const HIGH_LATENCY_ERROR_MS: u64 = 500;
const HIGH_JITTER_WARNING_MS: u64 = 40;
const LOSS_WARNING: f64 = 0.1;
const LOSS_ERROR: f64 = 0.5;
const TLS_EXPIRING_WARNING_DAYS: i64 = 30;
const TLS_EXPIRING_ERROR_DAYS: i64 = 7;
const LOW_PMTU: u32 = 1300;

fn title(rule: &str) -> Text {
    Msg::new(format!("probes.live.finding.{rule}.title")).into()
}

fn detail(rule: &str) -> Msg {
    Msg::new(format!("probes.live.finding.{rule}.detail"))
}

/// The detail with the stage's own error text, or the rule's generic sentence.
fn detail_or_error(rule: &str, error: Option<&str>) -> Msg {
    match error.map(str::trim).filter(|e| !e.is_empty()) {
        Some(e) => Msg::new(format!("probes.live.finding.{rule}.detailError")).arg("error", e),
        None => detail(rule),
    }
}

struct Out(Vec<Finding>);

impl Out {
    fn push<const N: usize>(
        &mut self,
        code: C,
        severity: Severity,
        rule: &str,
        detail: impl Into<Text>,
        evidence: [(&str, Evidence); N],
    ) {
        self.0.push(Finding {
            code,
            severity,
            title: title(rule),
            detail: detail.into(),
            evidence: evidence
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v))
                .collect::<BTreeMap<_, _>>(),
        });
    }
}

/// The address the check measured: first A, else first AAAA, else the host literal.
fn checked_ip(check: &LiveCheck) -> Option<IpAddr> {
    check
        .dns
        .primary_ip()
        .or_else(|| check.host.trim_matches(['[', ']']).parse().ok())
}

/// All findings of `cur` (`prev` = the previous good check of the same target, if any).
pub fn evaluate_findings(cur: &LiveCheck, prev: Option<&LiveCheck>) -> Vec<Finding> {
    let d = prev.map(|p| diff(cur, p));
    let mut out = Out(Vec::new());
    target_rules(cur, d.as_ref(), &mut out);
    tls_http_rules(cur, prev, d.as_ref(), &mut out);
    network_rules(cur, d.as_ref(), &mut out);
    tunnel_rules(cur, d.as_ref(), &mut out);
    out.0
}

fn target_rules(cur: &LiveCheck, d: Option<&HistoryDiff>, out: &mut Out) {
    if let Some(ip) = checked_ip(cur).filter(|ip| classify_target(*ip) == TargetClass::Private) {
        let ip = ip.to_string();
        out.push(
            C::PrivateTarget,
            Severity::Info,
            "privateTarget",
            detail("privateTarget").arg("ip", &ip),
            [("ip", ip.into())],
        );
    }
    let (a, aaaa) = (&cur.dns.a, &cur.dns.aaaa);
    // A dual-stack host with one address per family is normal (B-14).
    if a.len() > 1 || aaaa.len() > 1 {
        let all: Vec<&str> = a.iter().chain(aaaa).map(String::as_str).collect();
        out.push(
            C::DnsMultiIp,
            Severity::Info,
            "dnsMultiIp",
            detail("dnsMultiIp")
                .arg("count", all.len())
                .arg("ips", all.join(", ")),
            [("ipCount", (all.len() as u64).into())],
        );
    }
    if let Some(d) = d.filter(|d| d.ip_changed) {
        let (previous, current) = (d.previous_ips.join(", "), d.current_ips.join(", "));
        out.push(
            C::DnsChanged,
            Severity::Info,
            "dnsChanged",
            detail("dnsChanged")
                .arg("previous", &previous)
                .arg("current", &current),
            [
                ("currentIps", current.clone().into()),
                ("previousIps", previous.clone().into()),
            ],
        );
    }
}

fn tls_http_rules(
    cur: &LiveCheck,
    prev: Option<&LiveCheck>,
    d: Option<&HistoryDiff>,
    out: &mut Out,
) {
    if let Some(tls) = cur
        .tls
        .as_ref()
        .filter(|t| t.timed.status == TimedStatus::Ok)
    {
        if let Some(days) = tls.days_remaining {
            let ev = [("daysRemaining", Evidence::Num(days as f64))];
            if days <= TLS_EXPIRING_ERROR_DAYS {
                let valid_to = tls.valid_to.clone().unwrap_or_default();
                let msg = detail("tlsExpired")
                    .arg("days", days)
                    .arg("validTo", valid_to);
                out.push(C::TlsExpiring, Severity::Error, "tlsExpired", msg, ev);
            } else if days <= TLS_EXPIRING_WARNING_DAYS {
                let msg = detail("tlsExpiring").arg("days", days);
                out.push(C::TlsExpiring, Severity::Warning, "tlsExpiring", msg, ev);
            }
        }
        if tls.hostname_verified == Some(false) {
            let names = if tls.sans.is_empty() {
                tls.subject.clone().unwrap_or_default()
            } else {
                tls.sans
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            out.push(
                C::TlsSanMismatch,
                Severity::Warning,
                "tlsSanMismatch",
                detail("tlsSanMismatch")
                    .arg("names", names)
                    .arg("host", &cur.host),
                [("host", cur.host.as_str().into())],
            );
        }
        // A publicly trusted leaf renewed for the same names is routine (CDNs rotate often,
        // B-15); anything else is worth a note, not a warning.
        let prev_tls = prev.and_then(|p| p.tls.as_ref());
        let routine = tls.authorized == Some(true)
            && prev_tls.is_some_and(|p| {
                let mut a = p.sans.clone();
                let mut b = tls.sans.clone();
                a.sort();
                b.sort();
                a == b
            });
        if let Some(d) = d.filter(|d| d.tls_cert_changed && !routine) {
            out.push(
                C::TlsFingerprintChanged,
                Severity::Info,
                "tlsFingerprintChanged",
                detail("tlsFingerprintChanged"),
                [
                    (
                        "currentFingerprint",
                        d.current_tls_fingerprint.clone().unwrap_or_default().into(),
                    ),
                    (
                        "previousFingerprint",
                        d.previous_tls_fingerprint
                            .clone()
                            .unwrap_or_default()
                            .into(),
                    ),
                ],
            );
        }
        if tls.authorized == Some(false) {
            let why = tls
                .authorization_error
                .clone()
                .unwrap_or_else(|| "—".into());
            out.push(
                C::TlsUntrusted,
                Severity::Info,
                "tlsUntrusted",
                detail("tlsUntrusted").arg("error", &why),
                [("trustError", why.into())],
            );
        }
    }
    if let Some(http) = cur
        .http
        .as_ref()
        .filter(|h| h.timed.status == TimedStatus::Ok)
    {
        let code = http.status_code.map(|c| c.to_string()).unwrap_or_default();
        if let Some(location) = &http.location_header {
            out.push(
                C::HttpRedirect,
                Severity::Info,
                "httpRedirect",
                detail("httpRedirect")
                    .arg("code", &code)
                    .arg("location", location),
                [
                    ("location", location.as_str().into()),
                    (
                        "statusCode",
                        Evidence::Num(f64::from(http.status_code.unwrap_or(0))),
                    ),
                ],
            );
        }
        if let Some(status) = http.status_code.filter(|c| *c >= 500) {
            out.push(
                C::HttpUnexpectedStatus,
                Severity::Warning,
                "httpServerError",
                detail("httpServerError").arg("code", status),
                [("statusCode", Evidence::Num(f64::from(status)))],
            );
        }
    }
}
