//! The documents: one step per owning crate, each through that crate's own legacy conversion.
use std::path::Path;

use serde_json::Value;
use vpnte_automation::hardening;
use vpnte_automation::rotation::RotationConfig;
use vpnte_automation::scheduler::Schedules;
use vpnte_automation::tweaks::journal::TweakDoc;
use vpnte_automation::tweaks::{self, Journal, legacy::LegacySources};
use vpnte_base::Msg;
use vpnte_base::types::KillSwitchLevel;
use vpnte_core::settings::{RoutingMode, Settings, import_kill_switch};
use vpnte_core::store::Document;
use vpnte_engine::routing::RulesDoc;
use vpnte_forensics::domains::DomainsDoc;
use vpnte_forensics::enrichment::EnrichmentDoc;
use vpnte_probes::availability::UrlChecks;
use vpnte_probes::speedtest::SpeedTests;
use vpnte_tunnel::history::History;

use super::ImportReport;
use super::run::Ctx;
use crate::svc_core::docs::{ProtectionDoc, ThemesDoc};

mod servers;

/// Every document of the old directory, in an order where nothing depends on a later step.
/// Not imported (storage §6.6, with this build's owners): `smart-route-rule-sets` (bundled /
/// downloaded again), `external-proxy-leases` (regenerated), `adaptive-bypass` (a learning cache
/// its crate has no importer for; the install secret is generated anew), `live-server-checks`
/// (no owner yet: `vpnte_probes::live` is a placeholder).
pub(super) fn all(cx: &mut Ctx<'_>) {
    let settings = cx.open("settings");
    settings_docs(cx, settings.as_ref());
    servers::import(cx, settings.as_ref());
    rules(cx);
    history(cx);
    automation(cx);
    probes(cx);
    forensics(cx);
}

/// `settings.json` (with `i18n`, `themes`, `notification-prefs` and the kill-switch level of
/// `granular-kill-switch`), `protection.json` and `themes.json`.
fn settings_docs(cx: &mut Ctx<'_>, old: Option<&Value>) {
    let granular = cx.open("granular-kill-switch");
    let i18n = cx.open("i18n");
    let themes = cx.open("themes");
    let prefs = cx.open("notification-prefs");
    let flag = old
        .and_then(|old| old.get("settings").filter(|s| s.is_object()).or(Some(old)))
        .and_then(|s| s.get("firewallKillSwitch"))
        .and_then(Value::as_bool);
    let level = granular
        .as_ref()
        .and_then(|g| g.get("killSwitchLevel"))
        .and_then(Value::as_str);
    if old.is_some() || granular.is_some() {
        let (protection, dropped) = ProtectionDoc::from_legacy(granular.as_ref(), flag);
        cx.report.dropped += dropped;
        let rows = protection.settings.exceptions.len().max(1);
        cx.write_new(protection, rows);
    }
    if let Some(old_themes) = &themes {
        let doc = ThemesDoc::from_legacy(old_themes);
        let listed = list_len(old_themes.get("customThemes"));
        cx.report.dropped += listed.saturating_sub(doc.custom_themes.len());
        let rows = doc.custom_themes.len();
        cx.write_new(doc, rows);
    }
    if old.is_none() && i18n.is_none() && themes.is_none() && prefs.is_none() {
        return;
    }
    let (mut settings, warnings) = old.map(Settings::from_legacy).unwrap_or_default();
    cx.report.notes.extend(warnings);
    settings.kill_switch = import_kill_switch(level, flag);
    settings.apply_legacy_stores(i18n.as_ref(), themes.as_ref(), prefs.as_ref());
    // A sealed copy that does not open again must not be stored as if it were the password.
    if let Some(proxy) = &mut settings.proxy_override
        && proxy
            .credentials
            .as_ref()
            .is_some_and(|c| c.verify().is_err())
    {
        proxy.credentials = None;
        cx.report.locked += 1;
    }
    unelevated(cx, &mut settings);
    cx.write_new(settings, 1);
}

/// NOADMIN §0 / §2: an app that is not elevated has no TUN and no WFP. The old app always ran
/// elevated and defaulted to Hard, so an imported Hard becomes Soft, the first-start default of an
/// unelevated app (said in a note: never silently). The strict kill switch is kept, because
/// lowering a protection the user chose is not the import's call: the note says how to connect.
fn unelevated(cx: &mut Ctx<'_>, settings: &mut Settings) {
    if cx.elevated {
        return;
    }
    if settings.routing_mode == RoutingMode::Hard {
        settings.routing_mode = RoutingMode::Soft;
        cx.note(Msg::new("app.import.softMode"));
    }
    if settings.kill_switch == KillSwitchLevel::Strict {
        cx.note(Msg::new("app.import.strictNeedsAdmin"));
    }
}

/// Entries of an old JSON array (0 when absent or not an array).
fn list_len(v: Option<&Value>) -> usize {
    v.and_then(Value::as_array).map_or(0, Vec::len)
}

/// `rules.json`: domain rules, DNS profiles, split tunnel. Each warning names how many entries of
/// one section were refused (`count`).
fn rules(cx: &mut Ctx<'_>) {
    let domain = cx.open("domain-routing");
    let dns = cx.open("dns-profiles");
    let split = cx.open("split-tunnel");
    if domain.is_none() && dns.is_none() && split.is_none() {
        return;
    }
    let (doc, warnings) = RulesDoc::from_legacy(domain.as_ref(), dns.as_ref(), split.as_ref());
    cx.report.dropped += warnings.iter().map(count_arg).sum::<usize>();
    cx.report.notes.extend(warnings);
    let rows = doc.domain_rules.len() + doc.dns.custom.len() + doc.split_tunnel.apps.len();
    cx.write_new(doc, rows);
}

/// `history/connections.json`: merged by id, so the user's newer sessions stay.
fn history(cx: &mut Ctx<'_>) {
    let Some(old) = cx.open("connection-history") else {
        return;
    };
    match History::open(cx.root).import_legacy(&old) {
        Ok(done) => {
            cx.report.dropped += done.dropped;
            cx.report.notes.extend(done.warning());
            if done.imported > 0 {
                cx.imported(
                    vpnte_tunnel::history::ConnectionHistory::FILE,
                    done.imported,
                );
            }
        }
        Err(err) => cx.write_failed(vpnte_tunnel::history::ConnectionHistory::FILE, &err),
    }
}

/// `schedules.json` and `rotation.json`: written now although this build has no page for them,
/// because the import runs once.
fn automation(cx: &mut Ctx<'_>) {
    if let Some(old) = cx.open("scheduler") {
        let (doc, warnings) = Schedules::from_legacy(&old);
        cx.report.dropped += warnings.len();
        cx.report.notes.extend(warnings);
        let rows = doc.schedules.len();
        cx.write_new(doc, rows);
    }
    if let Some(old) = cx.open("profile-rotation") {
        cx.write_new(RotationConfig::from_legacy(&old), 1);
    }
}

/// `history/speed-tests.json` and `history/url-checks.json`: rows without the figures a row
/// needs are refused by the owning crate.
fn probes(cx: &mut Ctx<'_>) {
    if let Some(old) = cx.open("speed-test") {
        let doc = SpeedTests::from_legacy(&old);
        let rows = doc.history.len();
        cx.report.dropped += list_len(old.get("history")).saturating_sub(rows);
        cx.write_new(doc, rows);
    }
    if let Some(old) = cx.open("url-availability") {
        let doc = UrlChecks::from_legacy(&old);
        let rows = doc.history.len();
        cx.report.dropped += list_len(old.get("history")).saturating_sub(rows);
        cx.write_new(doc, rows);
    }
}

/// `history/traffic-domains.json` and `cache/domain-info.json`. What these leave out is policy
/// (names not recorded today, unfinished lookups), not invalid data: not counted as dropped.
fn forensics(cx: &mut Ctx<'_>) {
    if let Some(old) = cx.open("traffic-domains") {
        let doc = DomainsDoc::from_legacy(&old);
        let rows = doc.domains.len();
        cx.write_new(doc, rows);
    }
    if let Some(old) = cx.open("domain-intelligence") {
        let doc = EnrichmentDoc::from_legacy(&old);
        let rows = doc.entries.len();
        cx.write_new(doc, rows);
    }
}

/// Adopts the old app's Soft-mode leftovers (environment variables, Git, Gradle, Android
/// Studio: all per user) into the tweak journal, so the tunnel's start-up recovery rolls back
/// exactly the old values. Runs once (the journal keeps its own marker); only reads the system.
pub(super) fn tweaks(
    report: &mut ImportReport,
    root: &Path,
    sources: &LegacySources,
    system: &dyn tweaks::Backend,
) {
    // The same allow-list as the tunnel's journal, so no record is dropped on the next load.
    let journal = Journal::open(root, hardening::admit);
    if let Some(notice) = journal.notice() {
        tracing::warn!(key = %notice.key, "tweak journal not usable for the old app's leftovers");
    }
    let done = tweaks::legacy::import(&journal, system, sources);
    if done.adopted > 0 {
        report
            .imported
            .push((TweakDoc::FILE.to_owned(), done.adopted));
    }
    report.notes.extend(done.notice);
}

/// The `count` argument of an owning crate's "n entries dropped" warning.
fn count_arg(msg: &Msg) -> usize {
    msg.args
        .iter()
        .find(|(name, _)| name == "count")
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0)
}
