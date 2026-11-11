//! Which profile a slot runs (spec 3.6–3.8 with B-1, B-15, B-16). The country filter compares
//! ISO codes and whole words, never substrings (the old `includes` matched `us` in "Russia" and
//! `de` in "Sweden"). Auto-picks spread slots over servers no other slot uses, take the main
//! VPN's server only when nothing else is left (a proxy on it exits through the same IP) and
//! try known-offline servers last.
use std::collections::HashSet;

use vpnte_profiles::countries::{self, Iso2};

use super::ProxyProfile;
use crate::model::{Action, ServerStatus};

/// The old `COUNTRY_ALIASES` (spec 2.10): a query equal to one of these names that country.
const ALIASES: &[(&str, &[&str])] = &[
    ("RU", &["ru", "rus", "russia", "россия", "рф"]),
    ("DE", &["de", "deu", "germany", "германия", "немец"]),
    (
        "NL",
        &[
            "nl",
            "nld",
            "netherlands",
            "holland",
            "нидерланды",
            "голланд",
        ],
    ),
    (
        "GB",
        &[
            "gb",
            "uk",
            "united kingdom",
            "great britain",
            "britain",
            "англия",
            "британия",
            "великобритания",
        ],
    ),
    (
        "US",
        &["us", "usa", "united states", "america", "сша", "америка"],
    ),
    ("SE", &["se", "swe", "sweden", "швеция"]),
    ("FI", &["fi", "fin", "finland", "финляндия"]),
    ("FR", &["fr", "fra", "france", "франция"]),
    ("TR", &["tr", "turkey", "турция"]),
    ("JP", &["jp", "jpn", "japan", "япония"]),
    ("SG", &["sg", "singapore", "сингапур"]),
    ("KZ", &["kz", "kazakhstan", "казахстан"]),
];

/// The country a text names: an alias of the old table, an ISO code, or what the profiles
/// crate recognises (country names in English / Russian, flags).
pub(super) fn country_code(text: &str) -> Option<Iso2> {
    let text = text.trim().to_lowercase();
    if text.is_empty() {
        return None;
    }
    ALIASES
        .iter()
        .find(|(_, names)| names.contains(&text.as_str()))
        .and_then(|(code, _)| Iso2::new(code))
        .or_else(|| Iso2::new(&text))
        .or_else(|| countries::infer(&text))
}

/// Whether `p` matches the country filter `query` (empty = everything). A query that names a
/// country matches the profile's own country, or, when it has none, the country its name
/// claims; any other query must appear as whole words in "<country> <name>".
pub(super) fn matches_country(p: &ProxyProfile, query: &str) -> bool {
    if query.trim().is_empty() {
        return true;
    }
    if let Some(code) = country_code(query) {
        let own = p.country.as_deref().and_then(country_code);
        return own.or_else(|| countries::infer(&p.name)) == Some(code);
    }
    let haystack = words(&format!(
        "{} {}",
        p.country.as_deref().unwrap_or(""),
        p.name
    ));
    let needle = words(query);
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|w| w == needle.as_slice())
}

fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// What a start asks for.
#[derive(Debug, Clone, Copy)]
pub(super) struct Want<'a> {
    /// Explicit profile id (trimmed, non-empty).
    pub profile_id: Option<&'a str>,
    pub action: Action,
    /// The slot's current profile (rotation moves on from it).
    pub current: Option<&'a str>,
}

/// Picks the profile for a slot among `usable` (country-filtered, list order). `used` holds the
/// profiles of the OTHER configured slots, `active_vpn` the main VPN's profile. An explicit id
/// must be in `usable`; `connect` never auto-picks. A rotation moves round-robin to the next
/// profile after the current one within the best tier; with no other profile it restarts the
/// current one.
pub(super) fn pick<'a>(
    usable: &[&'a ProxyProfile],
    want: Want<'_>,
    used: &HashSet<&str>,
    active_vpn: Option<&str>,
) -> Option<&'a ProxyProfile> {
    if let Some(id) = want.profile_id {
        return usable.iter().copied().find(|p| p.id == id);
    }
    if want.action == Action::Connect {
        return None;
    }
    let rank = |p: &ProxyProfile| {
        (
            used.contains(p.id.as_str()),
            active_vpn == Some(p.id.as_str()),
            match p.status {
                ServerStatus::Online => 0u8,
                ServerStatus::Unknown => 1,
                ServerStatus::Offline => 2,
            },
        )
    };
    if want.action == Action::Rotate
        && let Some(current) = want.current
    {
        let others = usable.iter().filter(|p| p.id != current);
        let Some(best) = others.map(|p| rank(p)).min() else {
            return usable.iter().copied().find(|p| p.id == current);
        };
        let after = usable
            .iter()
            .position(|p| p.id == current)
            .map_or(0, |i| i + 1);
        return (0..usable.len())
            .map(|k| usable[(after + k) % usable.len()])
            .find(|p| p.id != current && rank(p) == best);
    }
    let best = usable.iter().map(|p| rank(p)).min()?;
    usable.iter().copied().find(|p| rank(p) == best)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::tests::{named, sample};

    fn ids<'a>(list: &[&'a ProxyProfile], query: &str) -> Vec<&'a str> {
        list.iter()
            .filter(|p| matches_country(p, query))
            .map(|p| p.id.as_str())
            .collect()
    }

    /// B-1: two-letter codes never match inside other words; codes, aliases, names and flags
    /// of the same country do.
    #[test]
    fn country_filter_matches_whole_countries_only() {
        let all = [
            named("ru", "Moscow 1", Some("Russia")),
            named("by", "Minsk", Some("Belarus")),
            named("cy", "Limassol", Some("Cyprus")),
            named("au", "Sydney", Some("Australia")),
            named("se", "Stockholm", Some("Sweden")),
            named("kr", "Seoul", Some("South Korea")),
            named("at", "Vienna", Some("Austria")),
            named("za", "Johannesburg", Some("South Africa")),
            named("pe", "Lima", Some("Peru")),
            named("us", "New York", Some("US")),
            named("nl", "Amsterdam", Some("Нидерланды")),
            named("de-flag", "🇩🇪 Frankfurt", None),
            named("de-code", "DE-1 premium", None),
            named("online", "online-backup", None),
        ];
        let all: Vec<&ProxyProfile> = all.iter().collect();
        assert_eq!(ids(&all, "us"), ["us"]);
        assert_eq!(ids(&all, "USA"), ["us"]);
        assert_eq!(ids(&all, "de"), ["de-flag", "de-code"]);
        assert_eq!(ids(&all, "Germany"), ["de-flag", "de-code"]);
        assert_eq!(ids(&all, "se"), ["se"]);
        assert_eq!(ids(&all, "tr"), Vec::<&str>::new());
        assert_eq!(ids(&all, "nl"), ["nl"]);
        assert_eq!(ids(&all, "holland"), ["nl"]);
        assert_eq!(ids(&all, "fr"), Vec::<&str>::new());
        assert_eq!(ids(&all, "ru"), ["ru"]);
        assert_eq!(ids(&all, " "), ids(&all, ""));
        assert_eq!(ids(&all, "").len(), all.len());
        assert_eq!(ids(&all, "new york"), ["us"]);
        assert_eq!(ids(&all, "york new"), Vec::<&str>::new());
        assert_eq!(ids(&all, "backup"), ["online"]);
        assert_eq!(ids(&all, "back"), Vec::<&str>::new());
    }

    fn with_status(n: u32, status: ServerStatus) -> ProxyProfile {
        ProxyProfile {
            status,
            ..sample(n)
        }
    }

    fn start() -> Want<'static> {
        Want {
            profile_id: None,
            action: Action::Start,
            current: None,
        }
    }

    fn rotate(current: &str) -> Want<'_> {
        Want {
            profile_id: None,
            action: Action::Rotate,
            current: Some(current),
        }
    }

    /// Spec external-proxy §3.8 with B-15 / B-16: unused servers first, the main VPN's server
    /// last, online before unknown before offline; explicit ids must be usable here.
    #[test]
    fn auto_pick_order() {
        let list = [
            with_status(1, ServerStatus::Online),
            with_status(2, ServerStatus::Offline),
            with_status(3, ServerStatus::Unknown),
        ];
        let usable: Vec<&ProxyProfile> = list.iter().collect();
        let none = HashSet::new();
        let id = |p: Option<&ProxyProfile>| p.map(|p| p.id.clone());
        assert_eq!(
            id(pick(&usable, start(), &none, None)),
            Some("profile-1".into())
        );
        let vpn = Some("profile-1");
        assert_eq!(
            id(pick(&usable, start(), &none, vpn)),
            Some("profile-3".into())
        );
        let used: HashSet<&str> = ["profile-3"].into();
        assert_eq!(
            id(pick(&usable, start(), &used, vpn)),
            Some("profile-2".into())
        );
        let used: HashSet<&str> = ["profile-2", "profile-3"].into();
        assert_eq!(
            id(pick(&usable, start(), &used, vpn)),
            Some("profile-1".into())
        );
        let explicit = Want {
            profile_id: Some("profile-2"),
            ..start()
        };
        assert_eq!(
            id(pick(&usable, explicit, &none, None)),
            Some("profile-2".into())
        );
        let missing = Want {
            profile_id: Some("profile-9"),
            ..start()
        };
        assert_eq!(id(pick(&usable, missing, &none, None)), None);
        let connect = Want {
            action: Action::Connect,
            ..start()
        };
        assert_eq!(id(pick(&usable, connect, &none, None)), None);
        assert_eq!(id(pick(&[], start(), &none, None)), None);
    }

    /// Spec external-proxy §3.8 / §3.22: rotation is round-robin after the current profile
    /// within the best tier; with one usable profile it restarts that one.
    #[test]
    fn rotation_moves_round_robin() {
        let list = [sample(1), sample(2), sample(3)];
        let usable: Vec<&ProxyProfile> = list.iter().collect();
        let none = HashSet::new();
        let id = |p: Option<&ProxyProfile>| p.map(|p| p.id.clone()).unwrap_or_default();
        assert_eq!(
            id(pick(&usable, rotate("profile-1"), &none, None)),
            "profile-2"
        );
        assert_eq!(
            id(pick(&usable, rotate("profile-3"), &none, None)),
            "profile-1"
        );
        assert_eq!(id(pick(&usable, rotate("gone"), &none, None)), "profile-1");
        let used: HashSet<&str> = ["profile-2"].into();
        assert_eq!(
            id(pick(&usable, rotate("profile-1"), &used, None)),
            "profile-3"
        );
        assert_eq!(
            id(pick(&usable[..1], rotate("profile-1"), &none, None)),
            "profile-1"
        );
        let list = [
            sample(1),
            with_status(2, ServerStatus::Offline),
            with_status(3, ServerStatus::Online),
        ];
        let usable: Vec<&ProxyProfile> = list.iter().collect();
        assert_eq!(
            id(pick(&usable, rotate("profile-1"), &none, None)),
            "profile-3"
        );
        assert_eq!(
            id(pick(&usable, rotate("profile-3"), &none, None)),
            "profile-1"
        );
    }
}
