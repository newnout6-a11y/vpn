//! Pure rules of the panel row: the proxy column's refresh cadence, slot choice, country
//! summary, picker labels and selection, row read-outs, and the servers panel's rows with the
//! pings measured from the panel.
use std::collections::HashMap;
use std::time::Duration;

use vpnte_base::Msg;
use vpnte_base::types::UnixMs;
use vpnte_view::fmt::minutes_ago;
use vpnte_view::identity::{LocalPing, ServerHealth, best_index, ping_of};
use vpnte_view::labels::health_label;

use super::model::{ProxiesView, ProxyChoice, ProxyHealth, ProxyRowView, ServersView};

/// Refresh cadence while a running proxy is starting or unhealthy.
pub const UNSTABLE_REFRESH: Duration = Duration::from_secs(3);
/// Refresh cadence while every running proxy is healthy.
pub const HEALTHY_REFRESH: Duration = Duration::from_secs(10);
/// Refresh cadence while no proxy process runs.
pub const IDLE_REFRESH: Duration = Duration::from_secs(10);
/// At most this many countries are named in the summary; the rest become « +N».
pub const SUMMARY_COUNTRIES: usize = 6;
/// Separator of compound labels («Poland · Warsaw · PL · HYSTERIA2»).
pub const DOT: &str = " · ";
/// Placeholder for a missing value.
pub const DASH: &str = "—";

/// How often the proxy column asks the backend to re-read the slots' health: quickly while a
/// running route is not yet ready or not healthy, slowly otherwise.
pub fn refresh_interval(view: &ProxiesView) -> Duration {
    let mut running = view.rows.iter().filter(|r| r.process_running).peekable();
    if running.peek().is_none() {
        return IDLE_REFRESH;
    }
    if running.any(|r| !r.ready || r.health != ProxyHealth::Healthy) {
        UNSTABLE_REFRESH
    } else {
        HEALTHY_REFRESH
    }
}

/// Number of slots whose engine process runs (the big count).
pub fn running_count(rows: &[ProxyRowView]) -> usize {
    rows.iter().filter(|r| r.process_running).count()
}

/// Slot for a new proxy: the smallest slot from 1 not taken by a running process (a failed or
/// auto-disabled slot is reused).
pub fn first_free_slot(rows: &[ProxyRowView]) -> u16 {
    (1..=u16::MAX)
        .find(|s| !rows.iter().any(|r| r.process_running && r.slot == *s))
        .unwrap_or(u16::MAX)
}

/// The countries of the running proxies: shown text and full list (tooltip).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountrySummary {
    pub text: String,
    pub title: String,
}

/// Distinct countries of the running proxies in slot order; `None` when there are none.
pub fn country_summary(rows: &[ProxyRowView]) -> Option<CountrySummary> {
    let mut countries: Vec<&str> = Vec::new();
    for c in rows
        .iter()
        .filter(|r| r.process_running)
        .filter_map(|r| r.country.as_deref())
        .filter(|c| !c.is_empty())
    {
        if !countries.contains(&c) {
            countries.push(c);
        }
    }
    if countries.is_empty() {
        return None;
    }
    let title = countries.join(", ");
    let text = if countries.len() <= SUMMARY_COUNTRIES {
        title.clone()
    } else {
        let head = countries[..SUMMARY_COUNTRIES].join(", ");
        format!("{head} +{}", countries.len() - SUMMARY_COUNTRIES)
    };
    Some(CountrySummary { text, title })
}

/// Colour of a picker option's status dot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Indicator {
    Success,
    Danger,
    Muted,
}

impl Indicator {
    /// The dot for a server's health.
    pub fn of(health: ServerHealth) -> Indicator {
        match health {
            ServerHealth::Online => Indicator::Success,
            ServerHealth::Offline => Indicator::Danger,
            ServerHealth::Unknown => Indicator::Muted,
        }
    }

    /// Accessible name of the dot.
    pub fn label(self) -> Msg {
        Msg::new(match self {
            Indicator::Success => "ui.panels.proxy.serverUp",
            Indicator::Danger => "ui.panels.proxy.serverDown",
            Indicator::Muted => "ui.panels.proxy.serverUnchecked",
        })
    }
}

/// Why an option cannot be picked, as a label suffix.
pub fn assignment(choice: &ProxyChoice) -> Option<Msg> {
    if choice.in_proxy {
        Some(Msg::new("ui.panels.proxy.inProxy"))
    } else if choice.vpn_server {
        Some(Msg::new("ui.panels.proxy.vpnServer"))
    } else {
        None
    }
}

/// Option label: name · country · PROTOCOL · assignment, empty parts left out.
pub fn choice_label(choice: &ProxyChoice, render: impl Fn(&Msg) -> String) -> String {
    let protocol = choice.protocol.as_deref().map(str::to_uppercase);
    let assignment = assignment(choice).map(|m| render(&m));
    [
        Some(choice.name.clone()),
        choice.country.clone(),
        protocol,
        assignment,
    ]
    .into_iter()
    .flatten()
    .filter(|part| !part.is_empty())
    .collect::<Vec<_>>()
    .join(DOT)
}

/// The picker's value after a refresh: the current one while it stays usable, else the first
/// usable server, else nothing.
pub fn keep_selection(current: Option<&str>, choices: &[ProxyChoice]) -> Option<String> {
    let usable = |id: &str| choices.iter().any(|c| c.id == id && c.usable());
    current
        .filter(|id| usable(id))
        .map(str::to_owned)
        .or_else(|| choices.iter().find(|c| c.usable()).map(|c| c.id.clone()))
}

/// Classes of a proxy row's health dot: hollow and blinking while starting, orange when not
/// healthy.
pub fn proxy_dot_class(row: &ProxyRowView) -> &'static str {
    if row.starting() {
        "swiss-health-dot shrink-0 is-unknown is-wait"
    } else if row.health != ProxyHealth::Healthy {
        "swiss-health-dot shrink-0 is-offline"
    } else {
        "swiss-health-dot shrink-0"
    }
}

/// Tooltip of a proxy row's health dot: the last error, else the health word.
pub fn proxy_dot_title(row: &ProxyRowView) -> Msg {
    row.last_error
        .clone()
        .unwrap_or_else(|| Msg::new(row.health.i18n_key()))
}

/// The meta line of a proxy row as the two text nodes the reference renders: the address
/// (`:18001`, else the URL, else «—») and, when there is one, « · запуск…» or « · 46 мс».
pub fn proxy_meta(row: &ProxyRowView, render: impl Fn(&Msg) -> String) -> (String, Option<String>) {
    let head = match (row.port, &row.proxy_url) {
        (Some(port), _) => format!(":{port}"),
        (None, Some(url)) => url.clone(),
        (None, None) => DASH.to_owned(),
    };
    let tail = if row.starting() {
        Some(render(&Msg::new("ui.panels.proxy.metaStarting")))
    } else {
        row.latency_ms
            .map(|ms| render(&Msg::new("ui.panels.proxy.metaLatency").arg("ms", ms)))
    };
    (head, tail.map(|t| format!("{DOT}{t}")))
}

/// Pings measured from the servers panel, valid for one route (see [`ServersView::tun_running`]).
/// Shared with the slab's node line, so both show the same number.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LocalPings {
    route: u64,
    pings: HashMap<String, LocalPing>,
}

impl LocalPings {
    /// The panel's measurement for a server, if any.
    pub fn get(&self, id: &str) -> Option<LocalPing> {
        self.pings.get(id).copied()
    }

    /// Marks a measurement as started; returns the route it belongs to.
    pub fn begin(&mut self, id: &str) -> u64 {
        self.pings.insert(id.to_owned(), LocalPing::Pinging);
        self.route
    }

    /// Stores a finished measurement unless the route changed since it started.
    pub fn finish(&mut self, id: &str, route: u64, ms: Option<u32>) {
        if route == self.route {
            self.pings.insert(id.to_owned(), LocalPing::Done(ms));
        }
    }

    /// Forgets every measurement (after «ping all» stored fresh values).
    pub fn clear(&mut self) {
        self.pings.clear();
    }

    /// The route changed: forget everything and discard measurements still in flight.
    pub fn new_route(&mut self) {
        self.route += 1;
        self.pings.clear();
    }
}

/// One rendered row of the servers panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerLine {
    pub id: String,
    pub name: String,
    pub country: Option<String>,
    /// The active server (ink row).
    pub selected: bool,
    /// Offline and not selected (muted row).
    pub muted: bool,
    /// Lowest ping among servers that are not offline (orange chip).
    pub best: bool,
    /// A measurement from the panel is in flight (spinner, button disabled).
    pub pinging: bool,
    /// Ping to show, ms.
    pub ping: Option<u32>,
    pub health: ServerHealth,
    /// Health cell text: offline, not checked, or the age of the last check.
    pub health_text: Msg,
}

/// The servers panel's rows at `now`.
pub fn server_lines(view: &ServersView, local: &LocalPings, now: UnixMs) -> Vec<ServerLine> {
    let pings: Vec<Option<u32>> = view
        .rows
        .iter()
        .map(|r| ping_of(local.get(&r.id), r.ping, r.health_latency))
        .collect();
    let best = best_index(
        pings
            .iter()
            .copied()
            .zip(view.rows.iter().map(|r| r.health)),
    );
    view.rows
        .iter()
        .zip(pings)
        .enumerate()
        .map(|(i, (row, ping))| {
            let selected = view.active_id.as_deref() == Some(row.id.as_str());
            ServerLine {
                id: row.id.clone(),
                name: row.name.clone(),
                country: row.country.clone().filter(|c| !c.is_empty()),
                selected,
                muted: row.health == ServerHealth::Offline && !selected,
                best: best == Some(i),
                pinging: local.get(&row.id) == Some(LocalPing::Pinging),
                ping,
                health: row.health,
                health_text: health_label(row.health, minutes_ago(row.checked_at, now)),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests;
