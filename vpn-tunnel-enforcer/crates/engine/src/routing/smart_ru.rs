//! Smart RU split: Russian services leave with the real (RU) address, everything else through
//! the tunnel. The lists are copied verbatim from the field-tested old generator
//! (`smartRoute.ts`); the rule order lives in `plan`.
//!
//! Never use `geosite-category-ru`: it means "popular in Russia" (YouTube, Google included) and
//! sent YouTube down the throttled ISP path. Rule sets are always `local`: a `remote` set whose
//! first download failed was a fatal engine start error (no TUN, real address exposed).
use std::collections::HashSet;
use std::path::Path;

use serde_json::{Value, json};

use super::domain::{DomainAction, DomainPattern, DomainRule};
use super::matcher::Matcher;

/// Tag of the destination-IP country set.
pub const GEOIP_RU: &str = "geoip-ru";
/// Tag of the curated government / banks domain set (the only RU domain set used).
pub const GOV_RU: &str = "geosite-category-gov-ru";
/// Tag of the sites blocked in Russia (domain suffixes only, so DNS rules may use it too).
pub const RU_BLOCKED_SITES: &str = "geosite-ru-blocked";
/// Tag of the addresses blocked in Russia (IPv4 nets only; never in a DNS rule).
pub const RU_BLOCKED_IPS: &str = "geoip-ru-blocked";
/// `(tag, file name, upstream URL)` of every rule set, in emission order. The blocked pair is
/// runetfreedom's (rebuilt from the RKN registry every ~6 h): a site blocked in Russia but hosted
/// there, or one the ISP resolver answers with its block-page stub, would otherwise go direct.
pub const RULE_SETS: [(&str, &str, &str); 4] = [
    (
        GEOIP_RU,
        "geoip-ru.srs",
        "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs",
    ),
    (
        GOV_RU,
        "geosite-category-gov-ru.srs",
        "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-gov-ru.srs",
    ),
    (
        RU_BLOCKED_SITES,
        "geosite-ru-blocked.srs",
        "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-ru-blocked.srs",
    ),
    (
        RU_BLOCKED_IPS,
        "geoip-ru-blocked.srs",
        "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geoip/geoip-ru-blocked.srs",
    ),
];

/// DNS-only: resolved by the ISP-visible resolver, routed by `geoip-ru` on the answer (a
/// Cloudflare-fronted `.ru` site still goes through the tunnel).
pub const RU_TLD_SUFFIXES: &[&str] = &[".ru", ".su", ".xn--p1ai"];
/// DNS-only, like the TLD list: RU services that also serve from .com / .net CDNs.
pub const RU_COMMERCIAL_SERVICE_SUFFIXES: &[&str] = &[
    ".vk.com",
    ".vk.me",
    ".vkuser.net",
    ".userapi.com",
    ".mail.ru",
    ".dzen.ru",
    ".yandex.net",
    ".yandex.com",
    ".ya.ru",
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
/// Direct only when the user enables "maps directly", otherwise pinned to the tunnel.
pub const MAPS_DOMAIN_SUFFIXES: &[&str] = &[
    ".maps.yandex.net",
    ".maps.yandex.ru",
    ".2gis.com",
    ".2gis.ru",
];
/// Pinned to the tunnel: Google Global Cache nodes inside RU split one Google session across
/// two addresses and trigger "unusual traffic" checks.
pub const GOOGLE_AND_GEMINI_PINNED_SUFFIXES: &[&str] = &[
    ".gemini.google.com",
    ".generativelanguage.googleapis.com",
    ".proactivebackend-pa.googleapis.com",
    ".alkalimakersuite-pa.googleapis.com",
    ".aistudio.google.com",
    ".cloudaicompanion-pa.googleapis.com",
    ".deepmind.google",
    ".deepmind.com",
    ".google.com",
    ".googleapis.com",
    ".gstatic.com",
    ".googleusercontent.com",
    ".googlevideo.com",
    ".gvt1.com",
    ".1e100.net",
];
/// Direct, after `geoip-ru`: Moonshot coding APIs are geo-fenced against foreign datacenters.
pub const KIMI_MOONSHOT_DOMAIN_SUFFIXES: &[&str] = &[
    ".kimi.com",
    ".kimi.ai",
    ".moonshot.cn",
    ".volces.com",
    ".aliyun.com",
    ".trustdecision.com",
];
/// Pinned to the tunnel: YouTube resolves to RU cache nodes that the ISP throttles.
pub const VPN_PINNED_MEDIA_SUFFIXES: &[&str] = &[
    ".youtube.com",
    ".youtu.be",
    ".youtube-nocookie.com",
    ".googlevideo.com",
    ".ytimg.com",
    ".ggpht.com",
    ".youtubei.googleapis.com",
    ".youtube-ui.l.google.com",
];
/// Pinned first: an RU-hosted checker going direct would show the real address ("VPN leaks").
/// The routing self-test must not pick one of these as its RU probe.
pub const IP_CHECKER_SUFFIXES: &[&str] = &[
    ".ipify.org",
    ".ipinfo.io",
    ".myip.com",
    ".ifconfig.me",
    ".icanhazip.com",
    ".ipapi.co",
    ".ip-api.com",
    ".geojs.io",
    ".whatismyipaddress.com",
    ".whatismyip.com",
    ".iplocation.net",
    ".ipleak.net",
    ".browserleaks.com",
    ".dnsleaktest.com",
    ".whoer.net",
    ".wtfismyip.com",
    ".myexternalip.com",
    ".getmyip.com",
    ".ip.sb",
    ".seeip.org",
    ".bigdatacloud.net",
    ".2ip.ru",
    ".2ip.io",
    ".myip.ru",
    ".smart-ip.net",
    ".ip-ping.ru",
];

/// The user's Smart RU switches.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SmartRu {
    pub enabled: bool,
    pub maps_direct: bool,
}

/// Where Smart RU itself sends a site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmartRoute {
    Direct,
    Vpn,
}

impl SmartRu {
    /// Smart RU's own route for `host`, read from its name lists in rule order: pins → VPN,
    /// maps when direct, RU TLDs, RU services and Kimi → direct. RU-TLD names are routed by
    /// `geoip-ru` on the answer, which for them is nearly always direct; the blocked-in-Russia
    /// list (a file, read by the engine only) sends a few of them through the tunnel instead. Any
    /// other name is left to the address country, which a name alone cannot tell: `None`.
    pub fn route_of(&self, host: &str) -> Option<SmartRoute> {
        if !self.enabled {
            return None;
        }
        let hit = |list: &[&str]| list.iter().any(|s| suffix_matches(s, host));
        let pinned = [
            IP_CHECKER_SUFFIXES,
            GOOGLE_AND_GEMINI_PINNED_SUFFIXES,
            VPN_PINNED_MEDIA_SUFFIXES,
        ];
        if pinned.iter().any(|l| hit(l)) {
            return Some(SmartRoute::Vpn);
        }
        if hit(MAPS_DOMAIN_SUFFIXES) {
            return Some(if self.maps_direct {
                SmartRoute::Direct
            } else {
                SmartRoute::Vpn
            });
        }
        let direct = [
            RU_TLD_SUFFIXES,
            RU_COMMERCIAL_SERVICE_SUFFIXES,
            KIMI_MOONSHOT_DOMAIN_SUFFIXES,
        ];
        direct.iter().any(|l| hit(l)).then_some(SmartRoute::Direct)
    }

    /// Smart RU's route for the site of a user rule that sends it the other way (the user's
    /// rule wins, owner answer 4); `None` when they agree, Smart RU is off or undecided, the
    /// rule blocks, or the pattern is a keyword (no site to name).
    pub fn overridden_by(&self, rule: &DomainRule) -> Option<SmartRoute> {
        let host = match &rule.pattern {
            DomainPattern::Exact(h) | DomainPattern::Subdomains(h) => h,
            DomainPattern::Keyword(_) => return None,
        };
        let own = match rule.action {
            DomainAction::Direct => SmartRoute::Direct,
            DomainAction::Vpn => SmartRoute::Vpn,
            DomainAction::Block => return None,
        };
        self.route_of(host).filter(|r| *r != own)
    }
}

/// The list matcher's semantics (`Matcher::suffix`): `.x.com` covers `x.com` and `*.x.com`.
fn suffix_matches(suffix: &str, host: &str) -> bool {
    host.ends_with(suffix) || suffix.strip_prefix('.') == Some(host)
}

/// `route.rule_set` entries for the files in `dir` (forward slashes, as the old generator).
pub(crate) fn rule_sets(dir: &Path) -> Vec<Value> {
    let dir = dir.to_string_lossy().replace('\\', "/");
    let dir = dir.trim_end_matches('/');
    RULE_SETS
        .iter()
        .map(|(tag, file, _)| {
            json!({ "type": "local", "tag": tag, "format": "binary", "path": format!("{dir}/{file}") })
        })
        .collect()
}

/// The tunnel pins in order: IP checkers, Google / Gemini, media, and maps unless they go
/// direct. A suffix already pinned by an earlier list is not repeated (`.googlevideo.com`).
pub(crate) fn pins(maps_direct: bool) -> Vec<Matcher> {
    let mut lists = vec![
        IP_CHECKER_SUFFIXES,
        GOOGLE_AND_GEMINI_PINNED_SUFFIXES,
        VPN_PINNED_MEDIA_SUFFIXES,
    ];
    if !maps_direct {
        lists.push(MAPS_DOMAIN_SUFFIXES);
    }
    let mut seen = HashSet::new();
    lists
        .into_iter()
        .map(|list| {
            let mut m = Matcher::default();
            for s in list.iter().filter(|s| seen.insert(**s)) {
                m.suffix(s);
            }
            m
        })
        .collect()
}

/// A matcher over the given suffix lists.
pub(crate) fn suffixes(lists: &[&[&str]]) -> Matcher {
    let mut m = Matcher::default();
    for s in lists.iter().flat_map(|l| l.iter()) {
        m.suffix(s);
    }
    m
}

/// `{"rule_set": [tag]}` (always the array form).
pub(crate) fn rule_set_ref(tag: &str) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("rule_set".to_owned(), json!([tag]));
    m
}

#[cfg(test)]
#[path = "smart_ru_tests.rs"]
mod tests;
