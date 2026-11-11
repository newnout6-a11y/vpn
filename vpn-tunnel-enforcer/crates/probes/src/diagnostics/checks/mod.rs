//! Pure builders of the report items from plain data (the OS reads happen in `report.rs`).
mod network;
mod runtime;

use std::sync::LazyLock;

use regex::Regex;
use vpnte_base::Msg;
use vpnte_base::types::Verdict;

use super::sysinfo::OsInfo;
use super::{Category, CheckItem};

pub use network::{
    ProxyState, adapter_items, client_items, dns_item, proxy_item, routes_item, system_proxy_rows,
};
pub use runtime::{CORE_SERVICES, OTHER_SERVICES, app_log_item, service_items, tun_log_item};
#[cfg(test)]
pub use runtime::{FRESH_PROBLEM_MS, engine_errors, is_benign_engine_noise};

static USERINFO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)([a-z][a-z0-9+.-]*://)[^/@\s]*@").expect("static regex"));

/// A proxy URL without its `user:password@` part: credentials never reach the report.
pub fn strip_userinfo(url: &str) -> String {
    USERINFO.replace_all(url, "$1").into_owned()
}

/// `runtime-app`: OS, architecture, app version, elevation and directories.
pub fn app_item(os: &OsInfo, version: &str, elevated: bool, dirs: &[(&str, String)]) -> CheckItem {
    let os_label = match (&os.product, &os.build) {
        (Some(p), Some(b)) => format!("{p} ({b})"),
        (Some(p), None) => p.clone(),
        (None, Some(b)) => format!("Windows ({b})"),
        (None, None) => "Windows".to_owned(),
    };
    let mut rows = vec![format!("elevated={elevated}")];
    rows.extend(dirs.iter().map(|(k, v)| format!("{k}={v}")));
    let value = Msg::new("probes.diag.app.value")
        .arg("os", os_label)
        .arg("arch", os.arch)
        .arg("version", version);
    CheckItem::new(
        "runtime-app",
        Category::App,
        "probes.diag.app.label",
        None,
        value,
    )
    .details(rows, 12)
}

/// `runtime-settings`: the settings that shape routing, as `key=value` rows.
pub fn settings_item(summary: Msg, rows: Vec<String>) -> CheckItem {
    CheckItem::new(
        "runtime-settings",
        Category::App,
        "probes.diag.settings.label",
        None,
        summary,
    )
    .details(rows, 24)
}

/// `runtime-tun-status`: `Ok` while our TUN runs, informational when it is stopped.
pub fn tun_item(running: bool, upstream: Option<&str>) -> CheckItem {
    let (verdict, value) = match running {
        true => (
            Some(Verdict::Ok),
            Msg::new("probes.diag.tun.running").arg("upstream", upstream.unwrap_or("-")),
        ),
        false => (None, Msg::new("probes.diag.tun.stopped")),
    };
    CheckItem::new(
        "runtime-tun-status",
        Category::Tun,
        "probes.diag.tun.label",
        verdict,
        value,
    )
}

/// `binaries`: every bundled engine file present (sizes) plus the engines' own version lines.
pub fn binaries_item(
    files: &[(&str, Option<u64>)],
    versions: &[(&str, Option<String>)],
) -> CheckItem {
    let missing: Vec<&str> = files
        .iter()
        .filter(|(_, s)| s.is_none())
        .map(|(n, _)| *n)
        .collect();
    let mut rows: Vec<String> = files
        .iter()
        .map(|(name, size)| match size {
            Some(bytes) => format!("{name}: {} KB", bytes.div_ceil(1024)),
            None => format!("{name}: missing"),
        })
        .collect();
    rows.extend(
        versions
            .iter()
            .map(|(name, v)| format!("{name} version: {}", v.as_deref().unwrap_or("not run"))),
    );
    let (verdict, value) = match missing.is_empty() {
        true => (Verdict::Ok, Msg::new("probes.diag.binaries.present")),
        false => (
            Verdict::Fail,
            Msg::new("probes.diag.binaries.missing").arg("files", missing.join(", ")),
        ),
    };
    CheckItem::new(
        "binaries",
        Category::Tun,
        "probes.diag.binaries.label",
        Some(verdict),
        value,
    )
    .details(rows, 8)
}

/// Facts of the active profile, taken by the app from `vpnte_profiles::caps::capabilities`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileFacts {
    pub name: String,
    /// Protocol label (`vless`, `hysteria2`, …).
    pub protocol: String,
    /// Stealth label (`reality`, `ech`, `naive`, …).
    pub stealth: String,
    pub tls: bool,
    pub ech: bool,
    /// Hysteria2 only.
    pub hy2: Option<Hy2Facts>,
    /// What the user should know before connecting, most important first.
    pub warnings: Vec<Msg>,
}

/// Hysteria2 transport facts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hy2Facts {
    pub obfs: Option<String>,
    pub server_ports: Option<String>,
    pub hop_interval: Option<String>,
}

/// `active-profile-capabilities`: protocol, disguise and what to know (a warning if anything).
pub fn profile_item(profile: Option<&ProfileFacts>) -> CheckItem {
    let id = "active-profile-capabilities";
    let label = "probes.diag.profile.label";
    let Some(p) = profile else {
        return CheckItem::new(
            id,
            Category::Profile,
            label,
            None,
            Msg::new("probes.diag.profile.none"),
        );
    };
    let mut rows = vec![
        format!("name={}", vpnte_core::redact::text(&p.name)),
        format!("protocol={}", p.protocol),
        format!("stealthPreset={}", p.stealth),
        format!("tlsConfigured={}", p.tls),
        format!("echConfigured={}", p.ech),
    ];
    if let Some(h) = &p.hy2 {
        rows.push("hy2Transport=QUIC/UDP".to_owned());
        rows.extend(h.obfs.as_ref().map(|v| format!("hy2Obfs={v}")));
        rows.extend(
            h.server_ports
                .as_ref()
                .map(|v| format!("hy2ServerPorts={v}")),
        );
        rows.extend(
            h.hop_interval
                .as_ref()
                .map(|v| format!("hy2HopInterval={v}")),
        );
    }
    let value = Msg::new("probes.diag.profile.value")
        .arg("protocol", &p.protocol)
        .arg("stealth", &p.stealth)
        .arg("count", p.warnings.len());
    let verdict = (!p.warnings.is_empty()).then_some(Verdict::Warn);
    let mut item = CheckItem::new(id, Category::Profile, label, verdict, value).details(rows, 16);
    item.notes = p.warnings.clone();
    item
}

/// Longest details text in a logged finding.
pub const FINDING_DETAILS_MAX: usize = 4_000;

/// A warn / fail item as it goes to the log: redacted and bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub check: String,
    pub status: Verdict,
    pub value: String,
    pub details: String,
}

/// The log rows of a report: one per warn / fail item, everything through the log redactor.
pub fn findings(items: &[CheckItem]) -> Vec<Finding> {
    items
        .iter()
        .filter_map(|i| {
            let status = i
                .verdict
                .filter(|v| matches!(v, Verdict::Warn | Verdict::Fail))?;
            let value = std::iter::once(i.value.key.to_string())
                .chain(i.value.args.iter().map(|(k, v)| format!("{k}={v}")))
                .collect::<Vec<_>>()
                .join(" ");
            let details: String = i
                .details
                .join(" | ")
                .chars()
                .take(FINDING_DETAILS_MAX)
                .collect();
            Some(Finding {
                check: i.id.clone(),
                status,
                value: vpnte_core::redact::for_log(&value).into_owned(),
                details: vpnte_core::redact::for_log(&details).into_owned(),
            })
        })
        .collect()
}
