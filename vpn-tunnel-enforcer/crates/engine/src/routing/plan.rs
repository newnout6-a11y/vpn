//! The one routing generator: every route / DNS fragment in the owner's fixed order (owner
//! answer 4 of 12.11.2026, which replaced ТЗ-06 §10.4: the user's own rules win over Smart RU).
//! Pure: same inputs, same output.
//!
//! Route order (first match wins), placed by engine-config around its own guards:
//! - process rules, right after the inbound rules: P1 engine paths → direct, P2 third-party
//!   cores (local-proxy mode) → direct, P3 user direct apps / commands, P4 user VPN apps;
//! - domain rules, after hijack-dns / private / UDP guards / STUN pin: D1 user block →
//!   D2 user direct / VPN rules in the user's order → DB blocked in Russia (domains or
//!   addresses) → proxy → D3 Smart RU pins → proxy → D4 gov rule set (+ maps when direct) →
//!   direct → D5 `geoip-ru` + Kimi → direct; final = proxy.
//!
//! «VPN только для выбранных приложений» ([`Scope::OnlyListed`], re-check item 16): no P4; the
//! listed VPN apps and the app itself are the scope instead. Right after DB every other app
//! leaves directly (one inverted process rule), so the user's own rules still apply to every
//! app first (answer 4) and Smart RU and `final` see only the scope.
//!
//! DNS rules mirror it: R1 block (REFUSED) → R2 user rules → `dns-direct` / `dns-remote` →
//! RB blocked domains → `dns-remote` → R3 pins → `dns-remote` → R4 gov (+ maps) → `dns-direct`
//! → R5 RU TLDs + RU services + Kimi → `dns-direct`; final = `dns-remote`. A domain that leaves
//! directly must be resolved by the ISP-visible resolver, or the answer is the VPN-nearest CDN
//! node and `geoip-ru` misses it; a blocked one must not be, or the answer is the ISP's
//! block-page stub.
use std::net::Ipv4Addr;
use std::path::Path;

use serde_json::{Map, Value, json};
use vpnte_base::Msg;

use super::dns::{self, DnsAddr};
use super::domain::{DomainAction, DomainRule};
use super::matcher::Matcher;
use super::process::{
    AppPath, InactiveApp, InactiveReason, ResolvedSplit, third_party_core_regexes,
};
use super::smart_ru::{self, GEOIP_RU, GOV_RU, SmartRu};
use crate::singbox_config::{RoutingParts, direct_dns_server, usable_physical_dns};
use crate::tags::{DIRECT_OUT, DNS_DIRECT, DNS_REMOTE, PROXY_OUT};

/// Everything the generator reads, gathered by the tunnel at each (re)start.
#[derive(Debug, Clone, Copy)]
pub struct RoutingInputs<'a> {
    pub smart: SmartRu,
    /// Directory holding every `.srs` file of `smart_ru::RULE_SETS` (the active rule-set
    /// source). `None` forces Smart RU off for this run, with a warning; it is never emitted
    /// without its files.
    pub rule_set_dir: Option<&'a Path>,
    /// The user's domain rules in priority order.
    pub domain_rules: &'a [DomainRule],
    pub split: &'a ResolvedSplit,
    /// Engines whose own traffic leaves directly, by exact path (our Xray, the external proxy,
    /// the detected local-proxy owner). Never the app's own exe: in-process probes (IP checks,
    /// live checks, speed test) must keep going through the tunnel.
    pub engine_paths: &'a [AppPath],
    /// Local-proxy mode: third-party VPN clients leave directly too (no routing loop).
    pub third_party_cores: bool,
    /// The active resolver; `None` = automatic (Cloudflare DoH through the tunnel).
    pub dns: Option<&'a DnsAddr>,
    /// IPv4 resolvers of the physical adapters, read at this (re)start.
    pub physical_dns: &'a [Ipv4Addr],
    /// The VPN endpoint (or a WireGuard peer) is a host name: only the warning about resolving
    /// it without the network's own DNS comes from here (engine-config adds the bootstrap DNS).
    pub endpoint_is_hostname: bool,
}

/// Which apps take the tunnel past the user's domain rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope<'a> {
    /// Every app; the split's VPN apps are forced in ahead of every domain rule (P4).
    All,
    /// Only the split's VPN apps and `own`: the app's exe (`process_path_regex` values), whose
    /// in-process probes must use the tunnel. Every other app leaves directly after the user's
    /// domain rules and the blocked-in-Russia step.
    OnlyListed { own: &'a [String] },
}

/// The fragments for `singbox_config::ConfigInputs::routing` + what the user must be told.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RoutingFragments {
    /// P1-P4 as `process_rules` (placed right after the loopback inbound rules), D1-D5 as
    /// `domain_rules` (after the DNS hijack, private-address, UDP and STUN rules), local
    /// `rule_sets`, `dns-remote` always and `dns-direct` when something resolves directly.
    pub parts: RoutingParts,
    pub warnings: Vec<RoutingWarning>,
}

/// A degradation of this run the user must see (owner: no silent fallbacks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingWarning {
    /// Smart RU is on but its rule sets are unavailable: everything goes through the tunnel.
    SmartRuDisabled,
    /// The upstream dials a server name and the physical adapters have no usable resolver: the
    /// name is resolved only through public resolvers (the DoH / TCP order of
    /// `vpnte_core::resolve` in the app, sing-box's bootstrap order), with no step at the
    /// network's own DNS, the one that still answers under mobile whitelists (ru-2026 Ф9).
    BootstrapDnsFallback,
    /// A split-tunnel app got no rule; its traffic stays in the tunnel.
    InactiveApp(InactiveApp),
    /// [`Scope::OnlyListed`]: a split-tunnel app got no rule; like every unlisted app, its
    /// traffic leaves directly.
    InactiveAppDirect(InactiveApp),
}

impl RoutingWarning {
    /// User-facing text.
    pub fn msg(&self) -> Msg {
        match self {
            RoutingWarning::SmartRuDisabled => Msg::new("engine.routing.warn.smartRuDisabled"),
            RoutingWarning::BootstrapDnsFallback => {
                Msg::new("engine.routing.warn.bootstrapDnsFallback")
            }
            RoutingWarning::InactiveApp(a) => Msg::new(match a.reason {
                InactiveReason::FileMissing => "engine.routing.warn.appMissing",
                InactiveReason::NotAFile => "engine.routing.warn.appNotAFile",
            })
            .arg("name", &a.name),
            RoutingWarning::InactiveAppDirect(a) => Msg::new(match a.reason {
                InactiveReason::FileMissing => "engine.routing.warn.appMissingDirect",
                InactiveReason::NotAFile => "engine.routing.warn.appNotAFileDirect",
            })
            .arg("name", &a.name),
        }
    }
}

/// Builds every fragment in the fixed order for every app (see the module docs).
pub fn build(i: &RoutingInputs) -> RoutingFragments {
    build_scoped(i, Scope::All)
}

/// [`build`] for the apps page's scope.
pub fn build_scoped(i: &RoutingInputs, scope: Scope) -> RoutingFragments {
    let mut warnings = Vec::new();
    let mut out = RoutingParts::default();
    let smart_dir = i.rule_set_dir.filter(|_| i.smart.enabled);
    if i.smart.enabled && smart_dir.is_none() {
        warnings.push(RoutingWarning::SmartRuDisabled);
    }
    let maps_direct = i.smart.maps_direct;

    // P1-P4
    let mut engines: Vec<String> = Vec::new();
    for p in i.engine_paths {
        if !engines.contains(&p.regex()) {
            engines.push(p.regex());
        }
    }
    let cores = if i.third_party_cores {
        third_party_core_regexes()
    } else {
        Vec::new()
    };
    let forced_vpn = match scope {
        Scope::All => i.split.vpn.clone(),
        // The listed apps are the scope instead: they meet the user's rules and Smart RU.
        Scope::OnlyListed { .. } => Vec::new(),
    };
    for (regexes, outbound) in [
        (engines, DIRECT_OUT),
        (cores, DIRECT_OUT),
        (i.split.direct.clone(), DIRECT_OUT),
        (forced_vpn, PROXY_OUT),
    ] {
        if !regexes.is_empty() {
            out.process_rules
                .push(json!({ "process_path_regex": regexes, "outbound": outbound }));
        }
    }

    // D1 / R1: every user block rule, one merged object (REFUSED for DNS; `no_drop` stops
    // sing-box from silently switching to drop after 50 hits in 30 s).
    let reject = [
        ("action", json!("reject")),
        ("method", json!("default")),
        ("no_drop", json!(true)),
    ];
    for (_, m) in merged(i.domain_rules, |a| a == DomainAction::Block) {
        let fields = m.into_fields();
        out.domain_rules.push(extend(fields.clone(), &reject));
        out.dns_rules.push(extend(fields, &reject));
    }
    // D2 / R2: the user's direct and VPN rules, in the user's own order, before every Smart RU
    // rule: what the user set by hand wins, and removing the rule brings Smart RU's choice back.
    let user = merged(i.domain_rules, |a| a != DomainAction::Block);
    let user_direct = user.iter().any(|(a, _)| *a == DomainAction::Direct);
    for (action, m) in user {
        let (outbound, server) = match action {
            DomainAction::Direct => (DIRECT_OUT, DNS_DIRECT),
            _ => (PROXY_OUT, DNS_REMOTE),
        };
        let fields = m.into_fields();
        out.domain_rules
            .push(extend(fields.clone(), &[("outbound", json!(outbound))]));
        out.dns_rules
            .push(extend(fields, &[("server", json!(server))]));
    }
    // DB / RB: sites and addresses blocked in Russia go through the tunnel even when hosted in
    // RU (D5 would send them direct, to the RKN stub). Below the user's rules (answer 4).
    if smart_dir.is_some() {
        out.domain_rules.push(json!({
            "rule_set": [smart_ru::RU_BLOCKED_SITES, smart_ru::RU_BLOCKED_IPS],
            "outbound": PROXY_OUT,
        }));
        out.dns_rules.push(json!({
            "rule_set": [smart_ru::RU_BLOCKED_SITES],
            "server": DNS_REMOTE,
        }));
    }
    // The scope: below the user's rules (answer 4) and the blocked step (a site blocked in
    // Russia is unreachable directly for any app). DNS keeps its final: the DNS Client service
    // sends every app's queries, so no DNS rule can tell the apps apart.
    if let Scope::OnlyListed { own } = scope {
        let listed = in_scope(&i.split.vpn, own);
        out.domain_rules.push(outside_scope(&listed));
        out.listed_only = Some(listed);
    }
    // D3 / R3: Smart RU pins, before every RU rule so sniffed SNI beats the IP country.
    if smart_dir.is_some() {
        for m in smart_ru::pins(maps_direct) {
            let fields = m.into_fields();
            out.domain_rules
                .push(extend(fields.clone(), &[("outbound", json!(PROXY_OUT))]));
            out.dns_rules
                .push(extend(fields, &[("server", json!(DNS_REMOTE))]));
        }
    }
    // D4 / R4: RU government / banks (+ maps when the user wants them direct).
    if smart_dir.is_some() {
        let mut ru_domains = vec![smart_ru::rule_set_ref(GOV_RU)];
        if maps_direct {
            ru_domains.push(smart_ru::suffixes(&[smart_ru::MAPS_DOMAIN_SUFFIXES]).into_fields());
        }
        for fields in ru_domains {
            out.domain_rules
                .push(extend(fields.clone(), &[("outbound", json!(DIRECT_OUT))]));
            out.dns_rules
                .push(extend(fields, &[("server", json!(DNS_DIRECT))]));
        }
    }
    // D5 / R5: RU addresses and Kimi direct; RU TLDs, RU services and Kimi resolve directly.
    if let Some(dir) = smart_dir {
        let kimi = smart_ru::suffixes(&[smart_ru::KIMI_MOONSHOT_DOMAIN_SUFFIXES]).into_fields();
        let ru = smart_ru::suffixes(&[
            smart_ru::RU_TLD_SUFFIXES,
            smart_ru::RU_COMMERCIAL_SERVICE_SUFFIXES,
        ])
        .into_fields();
        for fields in [smart_ru::rule_set_ref(GEOIP_RU), kimi.clone()] {
            out.domain_rules
                .push(extend(fields, &[("outbound", json!(DIRECT_OUT))]));
        }
        for fields in [ru, kimi] {
            out.dns_rules
                .push(extend(fields, &[("server", json!(DNS_DIRECT))]));
        }
        out.rule_sets = smart_ru::rule_sets(dir);
    }

    out.dns_servers.push(dns::remote_server(i.dns));
    let scoped = matches!(scope, Scope::OnlyListed { .. });
    if smart_dir.is_some() || user_direct || scoped {
        // The scope needs it too: under proxy capture `direct-out` resolves the names of the
        // apps outside the scope on it (appsplit-b3, engine-config `direct_out`).
        out.dns_servers.push(direct_dns_server(i.physical_dns));
    }
    if i.endpoint_is_hostname && usable_physical_dns(i.physical_dns).is_none() {
        warnings.push(RoutingWarning::BootstrapDnsFallback);
    }
    let inactive = i.split.inactive.iter().cloned();
    warnings.extend(inactive.map(match scope {
        Scope::All => RoutingWarning::InactiveApp,
        Scope::OnlyListed { .. } => RoutingWarning::InactiveAppDirect,
    }));
    RoutingFragments {
        parts: out,
        warnings,
    }
}

/// The apps in the scope: the listed VPN apps and the app itself, each once.
fn in_scope(listed: &[String], own: &[String]) -> Vec<String> {
    let mut regexes: Vec<String> = Vec::new();
    for r in listed.iter().chain(own) {
        if !regexes.iter().any(|x| x.eq_ignore_ascii_case(r)) {
            regexes.push(r.clone());
        }
    }
    regexes
}

/// Every app outside the scope leaves directly: `invert` matches a process that is none of
/// them, and a connection whose process is unknown.
fn outside_scope(regexes: &[String]) -> Value {
    if regexes.is_empty() {
        // Nothing is in scope: every connection leaves directly.
        return json!({ "network": ["tcp", "udp"], "outbound": DIRECT_OUT });
    }
    json!({ "process_path_regex": regexes, "invert": true, "outbound": DIRECT_OUT })
}

/// Consecutive user rules with the same action share one matcher object: first-match
/// semantics are unchanged (they are adjacent) and a long list stays a few objects.
fn merged(
    rules: &[DomainRule],
    keep: impl Fn(DomainAction) -> bool,
) -> Vec<(DomainAction, Matcher)> {
    let mut out: Vec<(DomainAction, Matcher)> = Vec::new();
    for r in rules.iter().filter(|r| keep(r.action)) {
        match out.last_mut() {
            Some((action, m)) if *action == r.action => m.pattern(&r.pattern),
            _ => {
                let mut m = Matcher::default();
                m.pattern(&r.pattern);
                out.push((r.action, m));
            }
        }
    }
    out
}

fn extend(mut fields: Map<String, Value>, tail: &[(&str, Value)]) -> Value {
    for (k, v) in tail {
        fields.insert((*k).to_owned(), v.clone());
    }
    Value::Object(fields)
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "plan_scope_tests.rs"]
mod scope_tests;
