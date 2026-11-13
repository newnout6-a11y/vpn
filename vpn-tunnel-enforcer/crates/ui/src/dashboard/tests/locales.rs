//! Locale checks: every key the start page renders exists in both languages with exactly the
//! placeholders the code supplies (AT-09-011). The fragment rules are checked crate-wide.
use crate::test_locales::{catalogs, placeholders};

/// Keys the page renders through `t!`, with the arguments it passes.
const USED: &[(&str, &[&str])] = &[
    ("dashboard.vpnToggle", &[]),
    ("dashboard.swissSitesSee", &[]),
    ("dashboard.swissCopy", &[]),
    ("dashboard.swissCopied", &[]),
    ("dashboard.swissRealAddress", &[]),
    ("dashboard.swissNode", &[]),
    ("dashboard.swissNoServer", &[]),
    ("dashboard.swissInTunnel", &[]),
    ("dashboard.firewallChecking", &[]),
    ("dashboard.firewallRecheck", &[]),
    ("dashboard.connectionError", &[]),
    ("dashboard.connectionCancelled", &[]),
    ("dashboard.cancelledWithWarnings", &[]),
    ("dashboard.cancelFailed", &[]),
    ("dashboard.routeCheckFailed", &["message"]),
    ("swiss.labelMode", &[]),
    ("swiss.labelSmart", &[]),
    ("swiss.labelKs", &[]),
    ("swiss.labelLeaks", &[]),
    ("swiss.smartPending", &[]),
    ("swiss.smartSaveFailed", &[]),
    ("swiss.check", &[]),
    ("swiss.checkAria", &[]),
    ("swiss.progressHint", &[]),
    ("ui.dashboard.netmodeWhitelist", &[]),
    ("ui.dashboard.restartTitle", &[]),
    ("ui.dashboard.restartBody", &[]),
    ("ui.dashboard.competingTitle", &[]),
    ("ui.dashboard.competingBody", &[]),
    ("ui.dashboard.releaseKillSwitch", &[]),
    ("ui.dashboard.leakTitle", &[]),
    ("ui.dashboard.leakBody", &[]),
    ("ui.dashboard.offWithWarnings", &[]),
    ("ui.dashboard.recheckFailed", &[]),
    ("ui.dashboard.releaseFailed", &[]),
    ("ui.dashboard.foreignVpn.title", &[]),
    ("ui.dashboard.foreignVpn.body", &[]),
    ("ui.dashboard.proxyTaken.title", &[]),
    ("ui.dashboard.proxyTaken.body", &[]),
    ("ui.dashboard.proxyTaken.restore", &[]),
    ("ui.dashboard.proxyTaken.failed", &[]),
    ("ui.dashboard.pause.title", &[]),
    ("ui.dashboard.pause.reconnecting", &[]),
    ("ui.dashboard.pause.nextAttempt", &["wait"]),
    ("ui.dashboard.pause.manual", &[]),
    ("ui.dashboard.pause.keyRejected", &[]),
    ("ui.dashboard.pause.connect", &[]),
    ("common.close", &[]),
];

/// The runtime catalogs with the view crate's fragments (the slab renders its `Msg`s).
fn view_catalogs() -> [std::collections::BTreeMap<String, String>; 2] {
    catalogs(vpnte_view::LOCALES)
}

/// AT-09-011: every text the page renders exists in both languages with the placeholders the
/// code fills (the restart / competing titles take their data as a second text node).
#[test]
fn every_rendered_key_resolves() {
    let [ru, en] = view_catalogs();
    for (key, args) in USED {
        let mut args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        args.sort();
        for catalog in [&ru, &en] {
            let text = catalog.get(*key).unwrap_or_else(|| panic!("missing {key}"));
            assert_eq!(placeholders(text), args, "{key}");
        }
    }
}
