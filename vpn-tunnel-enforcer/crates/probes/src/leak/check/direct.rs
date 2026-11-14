//! The direct-out audit: engine connections routed outside the tunnel, judged by their rule.
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use vpnte_base::Msg;
use vpnte_core::net::{self};

use super::{CheckItem, CheckStatus};

/// One engine connection as the Clash API reports it (`/connections`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnRecord {
    /// Outbound chain, e.g. `["direct-out"]`.
    pub chains: Vec<String>,
    /// The matched rule; `final` (or empty) = no rule matched.
    pub rule: String,
    pub host: Option<String>,
    pub destination_ip: Option<IpAddr>,
    pub process_path: Option<String>,
}

/// Direct-out traffic of the session, classified by what routed it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectAudit {
    /// Public destinations sent direct without any rule (up to 5 examples, IP or host).
    pub leaked: Vec<String>,
    pub leaked_count: usize,
    /// Sent direct by a configured rule (split tunnel, domain rules, Smart RU …).
    pub by_rule: usize,
    /// Of `by_rule`: Russian destinations while Smart RU is on.
    pub smart_ru: usize,
    /// The app's own engines and recognised local VPN cores (anti-loop, always direct).
    pub core: usize,
}

/// Classifies direct-out connections (B-LC-8): private destinations are legitimate (§2.6);
/// a recognised core process is expected; a configured rule is expected; `final` is a leak.
/// `is_core_process` is the engine crate's process list (one list for config and checks).
pub fn audit_direct(
    conns: &[ConnRecord],
    smart_ru: bool,
    is_core_process: &dyn Fn(&str) -> bool,
) -> DirectAudit {
    let mut audit = DirectAudit::default();
    for c in conns
        .iter()
        .filter(|c| c.chains.iter().any(|h| h == "direct-out"))
    {
        if c.destination_ip.is_some_and(|ip| !net::is_public_ip(ip)) {
            continue;
        }
        if c.process_path.as_deref().is_some_and(is_core_process) {
            audit.core += 1;
        } else if !c.rule.is_empty() && !c.rule.eq_ignore_ascii_case("final") {
            audit.by_rule += 1;
            if smart_ru && c.host.as_deref().is_some_and(is_ru_hostname) {
                audit.smart_ru += 1;
            }
        } else {
            audit.leaked_count += 1;
            let target = c
                .destination_ip
                .map(|ip| ip.to_string())
                .or_else(|| c.host.clone());
            if let Some(target) = target
                && audit.leaked.len() < 5
                && !audit.leaked.contains(&target)
            {
                audit.leaked.push(target);
            }
        }
    }
    audit
}

/// `direct-out`: judged only from the current session's connections (`None` = no data).
pub fn direct_out_item(audit: Option<&DirectAudit>, tunnel_up: bool) -> CheckItem {
    let key = |k: &str| Msg::new(format!("probes.leak.check.directOut.{k}"));
    if !tunnel_up {
        return CheckItem::new("direct-out", CheckStatus::NotChecked, key("tunnelOff"));
    }
    let Some(a) = audit else {
        return CheckItem::new("direct-out", CheckStatus::NotChecked, key("noData"));
    };
    if a.leaked_count > 0 {
        let value = key("leaked").arg("count", a.leaked_count);
        return CheckItem::new("direct-out", CheckStatus::Fail, value)
            .detail(key("examples").arg("list", a.leaked.join(", ")));
    }
    let value = key(if a.by_rule + a.core == 0 {
        "none"
    } else {
        "expected"
    });
    let counts = key("counts")
        .arg("rules", a.by_rule)
        .arg("smartRu", a.smart_ru)
        .arg("core", a.core);
    CheckItem::new("direct-out", CheckStatus::Ok, value).detail(counts)
}

/// Russian hostnames: `.ru` / `.su` / `.рф` and the big Russian services on other TLDs (a
/// label for Smart RU traffic only, never a leak decision).
pub fn is_ru_hostname(host: &str) -> bool {
    const TLDS: [&str; 3] = ["ru", "su", "xn--p1ai"];
    const SERVICES: [&str; 21] = [
        ".yandex.net",
        ".yandex.com",
        ".ya.ru",
        ".yandex",
        ".vk.com",
        ".vk.me",
        ".vkuser.net",
        ".userapi.com",
        ".mail.ru",
        ".dzen.ru",
        ".ozon.ru",
        ".wildberries.ru",
        ".wb.ru",
        ".avito.ru",
        ".tinkoff.ru",
        ".tbank.ru",
        ".sberbank.ru",
        ".sber.ru",
        ".rutube.ru",
        ".hh.ru",
        ".kinopoisk.ru",
    ];
    let host = host.trim().trim_end_matches('.').to_lowercase();
    if host.is_empty() {
        return false;
    }
    let by_tld = TLDS.iter().any(|tld| {
        host == *tld
            || host
                .strip_suffix(tld)
                .is_some_and(|rest| rest.ends_with('.'))
    });
    by_tld || SERVICES.iter().any(|s| host.ends_with(s) || host == s[1..])
}
