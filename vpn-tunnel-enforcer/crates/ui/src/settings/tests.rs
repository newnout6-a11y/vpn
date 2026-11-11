//! Package-level gates: used locale keys (ui-pages §7.12) and AT-00-009 (no planned WP-12
//! feature on the page, §7.2).
/// Every source file of the module (scanned for literal catalog keys).
const SOURCES: &[&str] = &[
    include_str!("mod.rs"),
    include_str!("advanced.rs"),
    include_str!("behaviour.rs"),
    include_str!("connection.rs"),
    include_str!("demo.rs"),
    include_str!("dns.rs"),
    include_str!("domains.rs"),
    include_str!("fmt.rs"),
    include_str!("general.rs"),
    include_str!("kill_switch.rs"),
    include_str!("model.rs"),
    include_str!("notifications.rs"),
    include_str!("privacy.rs"),
    include_str!("protection.rs"),
    include_str!("rotation.rs"),
    include_str!("save_bar.rs"),
    include_str!("smart_ru.rs"),
    include_str!("transfer.rs"),
];

const RU: &str = include_str!("../../locales/ui-settings.ru.json");
const EN: &str = include_str!("../../locales/ui-settings.en.json");

/// The string literals that look like catalog keys (`"a.b"` / `"a.b.c"` with key characters).
fn literal_keys() -> Vec<String> {
    let mut out = Vec::new();
    for source in SOURCES {
        for chunk in source.split('"').skip(1).step_by(2) {
            let looks_like_key = chunk.contains('.')
                && !chunk.ends_with('.')
                && chunk.split('.').all(|seg| {
                    !seg.is_empty() && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                })
                && chunk.chars().next().is_some_and(|c| c.is_ascii_lowercase());
            if looks_like_key {
                out.push(chunk.to_owned());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// §7.12: every literal key the page uses exists in both languages (old catalog, a UI fragment
/// or the canonical errors). Non-key literals with dots (file names, hosts) are skipped by prefix.
#[test]
fn every_used_key_exists_in_both_languages() {
    let namespaces = [
        "ui.",
        "settings.",
        "killSwitch.",
        "domainRouting.",
        "notifications.",
        "common.",
        "onboarding.",
        "themes.",
        "errors.",
    ];
    let mut keys: Vec<String> = literal_keys()
        .into_iter()
        .filter(|key| namespaces.iter().any(|ns| key.starts_with(ns)))
        .collect();
    assert!(
        keys.len() > 200,
        "the key scan found only {} keys",
        keys.len()
    );
    // dynamic keys: `notifications.<event>` for every event, the section labels
    keys.extend(
        super::NotifyEvent::ALL
            .iter()
            .map(|e| format!("notifications.{}", e.key())),
    );
    keys.extend(
        super::ConfigSection::ALL
            .iter()
            .map(|s| s.label_key().to_owned()),
    );
    crate::test_locales::assert_resolve(
        &crate::test_locales::catalogs(&[]),
        keys.iter().map(String::as_str),
    );
}

/// AT-00-009: no planned-feature control or text (mihomo, AmneziaWG, browser boxes, account
/// isolation, process monitor) in either advanced-mode state — none exists in the catalog the
/// page renders from.
#[test]
fn no_planned_feature_text() {
    let banned = [
        "mihomo",
        "amneziawg",
        "изоляция аккаунтов",
        "процессный монитор",
    ];
    for json in [RU, EN] {
        for (key, value) in crate::test_locales::flatten(json) {
            let lower = value.to_lowercase();
            assert!(!banned.iter().any(|b| lower.contains(b)), "{key}: {value}");
            // the old gate's /browser.boxes/: any one character between the words
            let boxes = lower.match_indices("browser").any(|(i, _)| {
                lower[i + "browser".len()..]
                    .chars()
                    .skip(1)
                    .take(5)
                    .collect::<String>()
                    == "boxes"
            });
            assert!(!boxes, "{key}: {value}");
        }
    }
}
