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
