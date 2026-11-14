//! The pure part: a parsed Happ routing profile against the user's rules gives what an import
//! adds (the [`Plan`]) and what the page shows first (the preview). Mapping decisions are in
//! `crates/profiles/progress/p-provider-routing.md`.
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use vpnte_engine::routing::domain::{DomainAction, DomainPattern, DomainRule, PatternError};
use vpnte_profiles::text::{Entry, Route, RouteEntry, RoutingProfile, RoutingValue};
use vpnte_ui::split_tunnel::{
    EntryNote, Kept, PreviewEntry, PreviewRule, RouteKind, RoutingPreview, SmartRuStep,
};

/// geosite categories of Russian sites that Smart RU covers (RU domains, the big RU services,
/// state sites): in a «direct» list they mean "turn Smart RU on".
const RU_SITES: [&str; 6] = [
    "category-ru",
    "category-gov-ru",
    "ru-available-only-inside",
    "yandex",
    "vk",
    "mailru",
];
/// geoip sets of Russian addresses (Smart RU sends `geoip-ru` direct).
const RU_IPS: [&str; 1] = ["ru"];
/// The local network's category and set: always direct (the private-destination rule).
const LOCAL: &str = "private";

/// What an import does, fixed when the preview is made.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Plan {
    /// Rules appended to the user's list, in the profile's order.
    pub rules: Vec<(DomainPattern, DomainAction)>,
    /// Smart RU is switched on.
    pub smart_ru: bool,
}

/// One entry, judged.
enum Judged {
    Site(DomainPattern),
    SmartRu,
    Covered(EntryNote),
    Skipped(EntryNote),
}

/// The plan and the preview (token 0: the caller numbers it) of `value` against the user's
/// `rules`, with Smart RU on or off now.
pub(crate) fn plan(
    value: &RoutingValue,
    rules: &[DomainRule],
    smart_on: bool,
) -> (Plan, RoutingPreview) {
    let mut preview = RoutingPreview {
        token: 0,
        name: None,
        off: false,
        add: Vec::new(),
        smart_ru: None,
        covered: Vec::new(),
        skipped: Vec::new(),
        kept: Vec::new(),
    };
    let profile = match value {
        RoutingValue::Off => {
            preview.off = true;
            return (Plan::default(), preview);
        }
        RoutingValue::Profile(profile) => profile,
    };
    preview.name = profile.name.clone();
    let mine: HashMap<&DomainPattern, DomainAction> =
        rules.iter().map(|r| (&r.pattern, r.action)).collect();
    let mut planned: HashSet<DomainPattern> = HashSet::new();
    let mut plan = Plan::default();
    let mut smart_from = Vec::new();
    for item in &profile.entries {
        let route = route_kind(action(item.route));
        let shown = |note| PreviewEntry {
            text: item.raw.clone(),
            route,
            note,
        };
        match judge(item) {
            // The user's own rule for the site stays as it is (answer 4).
            Judged::Site(pattern) => match mine.get(&pattern) {
                Some(&own) if own == action(item.route) => {
                    preview.covered.push(shown(EntryNote::Present))
                }
                Some(&own) => preview
                    .skipped
                    .push(shown(EntryNote::YourRule(route_kind(own)))),
                None if planned.contains(&pattern) => {
                    preview.skipped.push(shown(EntryNote::Repeated))
                }
                None => {
                    preview.add.push(PreviewRule {
                        pattern: pattern.to_string(),
                        route,
                    });
                    planned.insert(pattern.clone());
                    plan.rules.push((pattern, action(item.route)));
                }
            },
            Judged::SmartRu => smart_from.push(item.raw.clone()),
            Judged::Covered(note) => preview.covered.push(shown(note)),
            Judged::Skipped(note) => preview.skipped.push(shown(note)),
        }
    }
    if !smart_from.is_empty() {
        plan.smart_ru = !smart_on;
        preview.smart_ru = Some(SmartRuStep {
            turn_on: !smart_on,
            from: smart_from,
        });
    }
    preview.kept = kept(profile);
    (plan, preview)
}

/// What an entry of the profile becomes in the user's world.
fn judge(item: &RouteEntry) -> Judged {
    let direct = item.route == Route::Direct;
    match &item.entry {
        // Our `x.com` covers the apex and its subdomains, Happ's `domain:x.com` exactly; `full:`
        // has no exact-only twin here and the preview shows the rule as it will be.
        Entry::Domain(name) | Entry::Full(name) => site(DomainPattern::parse(name)),
        // A bare dotted name is the site the provider meant; a bare word stays a keyword.
        Entry::Plain(name) => site(DomainPattern::parse_legacy(name)),
        Entry::Keyword(word) => site(DomainPattern::parse(&format!("~{word}"))),
        Entry::Regexp(_) => Judged::Skipped(EntryNote::Regexp),
        Entry::Geosite(tag) => list(tag, &RU_SITES, direct),
        Entry::Geoip(tag) => list(tag, &RU_IPS, direct),
        Entry::Ip(net) if is_local(net.network(), net.prefix_len()) => local(direct),
        Entry::Ip(_) => Judged::Skipped(EntryNote::IpRule),
        Entry::External(_) => Judged::Skipped(EntryNote::NotShipped),
        Entry::Unknown(_) => Judged::Skipped(EntryNote::Invalid),
    }
}

fn site(parsed: Result<DomainPattern, PatternError>) -> Judged {
    match parsed {
        Ok(pattern) => Judged::Site(pattern),
        Err(PatternError::IpLiteral) => Judged::Skipped(EntryNote::IpRule),
        Err(_) => Judged::Skipped(EntryNote::Invalid),
    }
}

/// A geosite / geoip name: the local network, Russian sites (Smart RU's) or a list not shipped.
fn list(tag: &str, russian: &[&str], direct: bool) -> Judged {
    if tag == LOCAL {
        return local(direct);
    }
    match (russian.contains(&tag), direct) {
        (true, true) => Judged::SmartRu,
        // Smart RU is never switched off by a profile: it stays as the user set it.
        (true, false) => Judged::Skipped(EntryNote::RussianSites),
        (false, _) => Judged::Skipped(EntryNote::NotShipped),
    }
}

fn local(direct: bool) -> Judged {
    match direct {
        true => Judged::Covered(EntryNote::Local),
        false => Judged::Skipped(EntryNote::Local),
    }
}

/// Private, loopback, link-local and multicast ranges as `(base, prefix)`, IPv4 then IPv6.
const LOCAL_V4: [(u128, u8); 6] = [
    (0x0A00_0000, 8),
    (0xAC10_0000, 12),
    (0xC0A8_0000, 16),
    (0x7F00_0000, 8),
    (0xA9FE_0000, 16),
    (0xE000_0000, 4),
];
const LOCAL_V6: [(u128, u8); 4] = [
    (0xFC00 << 112, 7),
    (0xFE80 << 112, 10),
    (0xFF00 << 112, 8),
    (1, 128),
];

/// The whole range is local: the engine's private-destination rule (sing-box `ip_is_private`)
/// sends it direct before any user rule.
pub(super) fn is_local(network: IpAddr, prefix: u8) -> bool {
    let (bits, width, ranges): (u128, u8, &[(u128, u8)]) = match network {
        IpAddr::V4(v4) => (u128::from(u32::from(v4)), 32, &LOCAL_V4),
        IpAddr::V6(v6) => (u128::from(v6), 128, &LOCAL_V6),
    };
    ranges.iter().any(|&(base, len)| {
        let shift = u32::from(width - len);
        prefix >= len && bits.checked_shr(shift) == base.checked_shr(shift)
    })
}

fn action(route: Route) -> DomainAction {
    match route {
        Route::Block => DomainAction::Block,
        Route::Proxy => DomainAction::Vpn,
        Route::Direct => DomainAction::Direct,
    }
}

fn route_kind(action: DomainAction) -> RouteKind {
    match action {
        DomainAction::Vpn => RouteKind::Vpn,
        DomainAction::Direct => RouteKind::Direct,
        DomainAction::Block => RouteKind::Block,
    }
}

/// The profile's settings that stay as the user has them.
fn kept(profile: &RoutingProfile) -> Vec<Kept> {
    let mut kept = Vec::new();
    if !profile.global_proxy {
        kept.push(Kept::RestDirect);
    }
    if !profile.dns.is_empty() {
        kept.push(Kept::Dns(profile.dns.join(", ")));
    }
    if profile.dns_hosts > 0 {
        kept.push(Kept::DnsHosts(profile.dns_hosts));
    }
    if profile.fake_dns {
        kept.push(Kept::FakeDns);
    }
    kept
}
