//! Locale checks of the panel row: every key the panels render exists in both languages with
//! exactly the placeholders the code supplies (the fragment rules are checked crate-wide).
use super::model::ProxyHealth;
use crate::test_locales::{catalogs, placeholders};

/// Keys rendered by the panels, with the arguments the code passes.
const USED: &[(&str, &[&str])] = &[
    ("swiss.traffic", &[]),
    ("swiss.live", &[]),
    ("swiss.noData", &[]),
    ("swiss.download", &[]),
    ("swiss.upload", &[]),
    ("swiss.session", &[]),
    ("swiss.mbps", &[]),
    ("swiss.gb", &[]),
    ("view.traffic.hover", &["mbps", "n"]),
    ("swiss.servers", &[]),
    ("swiss.pingAll", &[]),
    ("swiss.serversEmpty", &[]),
    ("swiss.bestPing", &[]),
    ("swiss.pingOne", &[]),
    ("swiss.best", &[]),
    ("swiss.offline", &[]),
    ("swiss.unchecked", &[]),
    ("swiss.online", &[]),
    ("swiss.justNow", &[]),
    ("swiss.minAgo", &["n"]),
    ("swiss.pingFailed", &[]),
    ("swiss.serverSelectFailed", &[]),
    ("ui.panels.proxy.title", &[]),
    ("ui.panels.proxy.stopAll", &[]),
    ("ui.panels.proxy.stopAllTitle", &[]),
    ("ui.panels.proxy.running", &[]),
    ("ui.panels.proxy.pickerLabel", &[]),
    ("ui.panels.proxy.pickerPlaceholder", &[]),
    ("ui.panels.proxy.pickerNone", &[]),
    ("ui.panels.proxy.start", &[]),
    ("ui.panels.proxy.startTitle", &[]),
    ("ui.panels.proxy.empty", &[]),
    ("ui.panels.proxy.unnamed", &[]),
    ("ui.panels.proxy.metaStarting", &[]),
    ("ui.panels.proxy.metaLatency", &["ms"]),
    ("ui.panels.proxy.rotate", &["slot"]),
    ("ui.panels.proxy.stop", &["slot"]),
    ("ui.panels.proxy.inProxy", &[]),
    ("ui.panels.proxy.vpnServer", &[]),
    ("ui.panels.proxy.serverUp", &[]),
    ("ui.panels.proxy.serverDown", &[]),
    ("ui.panels.proxy.serverUnchecked", &[]),
    ("ui.panels.proxy.pickFirst", &[]),
    ("ui.panels.proxy.failed", &[]),
    ("ui.panels.proxy.started", &["slot"]),
    ("ui.panels.proxy.rotated", &["slot"]),
    ("ui.panels.proxy.stopped", &["slot"]),
    ("ui.panels.proxy.stoppedAll", &["n"]),
    ("ui.panels.proxy.stopAllFailed", &[]),
    ("ui.panels.proxy.detail", &["text"]),
    ("ui.panels.demo.slab", &[]),
];

/// Country codes the old country detector could emit (64 table entries + Hong Kong).
const COUNTRIES: [&str; 65] = [
    "PL", "NO", "SE", "FI", "DK", "IS", "LV", "LT", "EE", "DE", "FR", "NL", "BE", "LU", "CH", "AT",
    "IT", "ES", "PT", "IE", "GB", "CZ", "SK", "HU", "RO", "BG", "GR", "UA", "MD", "RS", "HR", "CY",
    "RU", "BY", "TR", "AM", "GE", "AZ", "JP", "KR", "CN", "TW", "SG", "MY", "TH", "VN", "ID", "PH",
    "IN", "PK", "KZ", "UZ", "IL", "AE", "US", "CA", "MX", "BR", "AR", "CL", "AU", "NZ", "ZA", "EG",
    "HK",
];

/// AT-09-011: every text of the panel row comes from the i18n tables in both languages, with
/// exactly the placeholders the code fills (health words and country names included).
#[test]
fn every_rendered_key_resolves() {
    let [ru, en] = catalogs(vpnte_view::LOCALES);
    let health = [
        ProxyHealth::Stopped,
        ProxyHealth::Starting,
        ProxyHealth::Healthy,
        ProxyHealth::Degraded,
        ProxyHealth::Rotating,
        ProxyHealth::Quarantined,
        ProxyHealth::Failed,
    ]
    .map(|h| (h.i18n_key().to_owned(), Vec::new()));
    let countries = COUNTRIES.map(|c| (format!("ui.panels.country.{c}"), Vec::new()));
    let used = USED
        .iter()
        .map(|(k, args)| {
            (
                (*k).to_owned(),
                args.iter().map(|a| (*a).to_owned()).collect(),
            )
        })
        .chain(health)
        .chain(countries);
    for (key, mut args) in used {
        args.sort();
        for catalog in [&ru, &en] {
            let text = catalog.get(&key).unwrap_or_else(|| panic!("missing {key}"));
            assert_eq!(placeholders(text), args, "{key}");
        }
    }
}
