//! Server detail: basics, device persona and uTLS fingerprint, group context, location, the passive
//! endpoint probe, the live check, key export. It renders from the live snapshot by id (S-20)
//! and its body is keyed by the server id: closing the dialog or switching the server drops the
//! probe, the geo lookup and a running live check.
use std::time::Duration;

use dioxus::prelude::*;
use vpnte_base::AppResult;
use vpnte_base::types::ClientDevice;

use super::actions::Actions;
use super::live::LiveCheckPanel;
use super::model::{ArchiveReason, GeoInfo, GroupSource, GroupStatus, LatencyStats, ProbeReport};
use super::present::{
    DEVICES, device_label, displayed_ping, fingerprint, group_of, group_status_key,
    group_status_tone, is_removed_from_subscription, relative_time,
};
use super::row::Flag;
use crate::t;
use crate::widgets::{
    Badge, Button, ButtonKind, Field, Modal, ModalSize, Select, SelectOption, Spinner, Tone,
};

/// The UI gives the passive probe and the geo lookup this long before calling them failed.
pub(crate) const PROBE_UI_TIMEOUT: Duration = Duration::from_secs(10);

/// Outcome of a dialog-scoped read.
#[derive(Debug, Clone, PartialEq)]
enum Read<T> {
    Running,
    Done(T),
    Failed,
}

/// Runs `fut` with the UI deadline: a timeout or an error reads as failed, a cancellation as
/// nothing at all (the dialog is going away).
async fn with_deadline<T>(
    limit: Duration,
    fut: impl Future<Output = AppResult<T>>,
) -> Option<Read<T>> {
    match tokio::time::timeout(limit, fut).await {
        Ok(Ok(value)) => Some(Read::Done(value)),
        Ok(Err(err)) if err.kind == vpnte_base::ErrorKind::Cancelled => None,
        Ok(Err(_)) | Err(_) => Some(Read::Failed),
    }
}

#[component]
pub(crate) fn ServerDetail() -> Element {
    let actions = use_context::<Actions>();
    let mut detail = actions.store.detail;
    let open = use_memo(move || detail.read().is_some());
    let id = detail();
    let server = id.as_ref().and_then(|id| {
        actions
            .store
            .view
            .read()
            .servers
            .iter()
            .find(|s| &s.id == id)
            .cloned()
    });
    let title = server.as_ref().map(|s| s.name.clone()).unwrap_or_default();
    let exporting = id.as_ref().is_some_and(|id| {
        actions
            .store
            .rows
            .read()
            .get(id)
            .is_some_and(|r| r.exporting)
    });
    let (a_save, a_copy) = (actions.clone(), actions.clone());
    let (s_save, s_copy) = (server.clone(), server.clone());
    let footer = rsx! {
        Button {
            busy: exporting,
            disabled: server.is_none(),
            onclick: move |_| {
                if let Some(s) = &s_save {
                    a_save.export_key(s, true);
                }
            },
            {t!("serverDetail.saveKey")}
        }
        Button {
            kind: ButtonKind::Ghost,
            disabled: server.is_none() || exporting,
            title: t!("ui.servers.detail.copyTitle"),
            onclick: move |_| {
                if let Some(s) = &s_copy {
                    a_copy.export_key(s, false);
                }
            },
            {t!("serverDetail.copyKey")}
        }
        span { class: "srv-detail-foot-gap" }
        Button { kind: ButtonKind::Ghost, onclick: move |_| detail.set(None), {t!("common.close")} }
    };
    rsx! {
        Modal {
            open,
            title,
            on_close: move |_| detail.set(None),
            close_label: t!("common.close"),
            size: ModalSize::Lg,
            footer,
            if let Some(id) = id {
                DetailBody { key: "{id}", id }
            }
        }
    }
}

#[component]
fn DetailBody(id: String) -> Element {
    let actions = use_context::<Actions>();
    let store = actions.store;
    // Hooks first: the server can vanish from the snapshot between two renders.
    let geo_off = store.view.peek().geo_lookup_disabled;
    let mut probe = use_signal(|| Read::<ProbeReport>::Running);
    let mut geo = use_signal(|| {
        if geo_off {
            Read::Done(None)
        } else {
            Read::<Option<GeoInfo>>::Running
        }
    });
    use_hook({
        let (api, id) = (actions.api.clone(), id.clone());
        move || {
            let (probe_api, probe_id) = (api.clone(), id.clone());
            spawn(async move {
                if let Some(read) =
                    with_deadline(PROBE_UI_TIMEOUT, probe_api.probe(&probe_id)).await
                {
                    probe.set(read);
                }
            });
            if !geo_off {
                spawn(async move {
                    if let Some(read) = with_deadline(PROBE_UI_TIMEOUT, api.geo(&id)).await {
                        geo.set(read);
                    }
                });
            }
        }
    });
    let view = store.view.read();
    let Some(server) = view.servers.iter().find(|s| s.id == id).cloned() else {
        return rsx! {};
    };
    let group = group_of(&view, &server).cloned();
    let tunnel_running = view.tunnel_running;
    let connected = tunnel_running && view.active_id.as_deref() == Some(id.as_str());
    drop(view);
    let live_ping = store
        .rows
        .read()
        .get(&id)
        .map(|r| r.ping)
        .unwrap_or_default();
    let ping = displayed_ping(server.ping_ms, live_ping);

    let fingerprint = fingerprint(&server);
    let removed = is_removed_from_subscription(&server, group.as_ref());
    let purge_when = server
        .archived
        .filter(|a| a.reason == ArchiveReason::User)
        .map(|a| relative_time(a.purge_at, (store.now)(), *crate::lang::LANG.read()));
    let host = if server.host.is_empty() {
        "—".to_owned()
    } else {
        server.host.clone()
    };
    rsx! {
        div { class: "srv-detail",
            div { class: "srv-detail-head",
                Flag { country: server.country.clone() }
                span { class: "srv-detail-proto swiss-mono", "{server.protocol.to_uppercase()}" }
                if connected {
                    Badge { tone: Tone::Ok, {t!("ui.servers.row.connected")} }
                }
            }
            dl { class: "srv-kv",
                div { dt { class: "swiss-label", {t!("serverDetail.protocol")} } dd { class: "swiss-mono", "{server.protocol.to_uppercase()}" } }
                div { dt { class: "swiss-label", {t!("serverDetail.host")} } dd { class: "swiss-mono", title: "{host}", "{host}" } }
                div { dt { class: "swiss-label", {t!("serverDetail.port")} } dd { class: "swiss-mono", "{server.port}" } }
                div { dt { class: "swiss-label", {t!("serverDetail.ping")} } dd { class: "swiss-mono",
                    {ping.map_or_else(|| "—".to_owned(), |ms| t!("ui.servers.row.ms", ms = ms))}
                } }
            }
            if let Some(when) = purge_when {
                p { class: "srv-strip is-warn", {t!("ui.servers.detail.deleted", when = when)} }
            }
            DeviceRow { id: id.clone(), device: server.device, fingerprint, connected }
            if let Some(group) = group {
                section { class: "srv-detail-card",
                    h3 { class: "swiss-label", {t!("serverDetail.group")} }
                    div { class: "srv-detail-line",
                        span { class: "srv-group-tag swiss-mono",
                            {if group.source == GroupSource::Subscription { "SUB" } else { "KEYS" }}
                        }
                        strong { "{group.name}" }
                        Badge { tone: group_status_tone(group.status), {t!(group_status_key(group.status))} }
                    }
                    if group.status == GroupStatus::Expired {
                        p { class: "srv-detail-note", {t!("serverDetail.groupExpiredHint")} }
                    }
                    if removed {
                        p { class: "srv-detail-note is-alert", {t!("serverDetail.removedFromSubscription")} }
                    }
                }
            }
            GeoCard { geo: geo(), country: server.country.clone(), geo_off }
            ProbeCards { probe: probe(), tunnel_running }
            LiveCheckPanel { id: id.clone() }
        }
    }
}

/// Device persona select with the uTLS fingerprint it implies; the connected server reconnects.
#[component]
fn DeviceRow(id: String, device: ClientDevice, fingerprint: String, connected: bool) -> Element {
    let actions = use_context::<Actions>();
    let mut saving = use_signal(|| false);
    let mut failed = use_signal(|| false);
    let options: Vec<SelectOption<ClientDevice>> = DEVICES
        .iter()
        .map(|&d| SelectOption::new(d, device_label(d)))
        .collect();
    let api = actions.api.clone();
    rsx! {
        div { class: "srv-detail-device",
            Field { label: t!("ui.servers.detail.device"), hint: t!("ui.servers.add.deviceHint"),
                Select {
                    options,
                    value: Some(device),
                    disabled: saving(),
                    on_change: move |next: ClientDevice| {
                        let (api, id) = (api.clone(), id.clone());
                        saving.set(true);
                        failed.set(false);
                        spawn(async move {
                            let result = api.set_device(&id, next).await;
                            saving.set(false);
                            failed.set(matches!(&result, Err(e) if e.kind != vpnte_base::ErrorKind::Cancelled));
                        });
                    },
                }
            }
            div { class: "srv-detail-fp",
                span { class: "swiss-label", {t!("ui.servers.detail.fingerprint")} }
                Badge { tone: if failed() { Tone::Fail } else { Tone::Neutral }, "{fingerprint}" }
                if saving() {
                    span { class: "srv-detail-note", role: "status",
                        Spinner {}
                        if connected { {t!("ui.servers.detail.reconnecting")} } else { {t!("ui.servers.detail.saving")} }
                    }
                } else if failed() {
                    span { class: "srv-detail-note is-alert", role: "alert", {t!("ui.servers.detail.saveFailed")} }
                } else if connected {
                    span { class: "srv-detail-note", {t!("ui.servers.detail.reconnectNote")} }
                }
            }
        }
    }
}

/// Location of the resolved address; the stored country is the fallback (free geo tiers are
/// rate-limited, and the card must not vanish because of that).
#[component]
fn GeoCard(geo: Read<Option<GeoInfo>>, country: Option<String>, geo_off: bool) -> Element {
    if geo_off {
        return rsx! {
            section { class: "srv-detail-card",
                h3 { class: "swiss-label", {t!("serverDetail.location")} }
                p { class: "srv-detail-note", {t!("ui.servers.detail.geoOff")} }
            }
        };
    }
    let info = match &geo {
        Read::Running => {
            return rsx! {
                p { class: "srv-detail-note", role: "status", Spinner {} {t!("serverDetail.loading")} }
            };
        }
        Read::Done(Some(info)) => Some(info.clone()),
        Read::Done(None) | Read::Failed => None,
    };
    if info.is_none() && country.is_none() {
        return rsx! {};
    }
    let info = info.unwrap_or_default();
    let dash = || "—".to_owned();
    let fields = [
        (
            t!("serverDetail.country"),
            info.country.clone().or(country).unwrap_or_else(dash),
        ),
        (
            t!("serverDetail.city"),
            info.city.clone().unwrap_or_else(dash),
        ),
        (
            t!("serverDetail.org"),
            info.org.clone().unwrap_or_else(dash),
        ),
        (
            t!("serverDetail.timezone"),
            info.timezone.clone().unwrap_or_else(dash),
        ),
    ];
    rsx! {
        section { class: "srv-detail-card",
            h3 { class: "swiss-label", {t!("serverDetail.location")} }
            dl { class: "srv-kv",
                for (label , value) in fields {
                    div { key: "{label}", dt { class: "swiss-label", "{label}" } dd { "{value}" } }
                }
            }
        }
    }
}

/// The passive probe's cards: network, ASN, TCP latency, the server's own port.
#[component]
fn ProbeCards(probe: Read<ProbeReport>, tunnel_running: bool) -> Element {
    let report = match probe {
        Read::Running => {
            return rsx! {
                p { class: "srv-detail-note", role: "status", Spinner {} {t!("serverDetail.probing")} }
            };
        }
        Read::Failed => {
            return rsx! {
                p { class: "srv-detail-note is-alert", {t!("serverDetail.probeError")} }
            };
        }
        Read::Done(report) => report,
    };
    let ips: Vec<String> = report
        .resolved_ips
        .iter()
        .map(ToString::to_string)
        .collect();
    rsx! {
        div { class: "srv-detail-grid",
            section { class: "srv-detail-card",
                h3 { class: "swiss-label", {t!("serverDetail.network")} }
                div { class: "srv-kv-line",
                    span { class: "srv-kv-label", {t!("serverDetail.resolvedIps")} }
                    span { class: "srv-chips",
                        for ip in ips {
                            span { key: "{ip}", class: "srv-chip swiss-mono", "{ip}" }
                        }
                    }
                }
                if !report.reverse_dns.is_empty() {
                    div { class: "srv-kv-line",
                        span { class: "srv-kv-label", {t!("serverDetail.reverseDns")} }
                        span { class: "swiss-mono srv-kv-value", {report.reverse_dns.join(", ")} }
                    }
                }
            }
            if let Some(asn) = &report.asn {
                section { class: "srv-detail-card",
                    h3 { class: "swiss-label", {t!("serverDetail.asn")} }
                    div { class: "srv-kv-line", span { class: "srv-kv-label", "ASN" } span { class: "swiss-mono", "{asn.asn}" } }
                    div { class: "srv-kv-line", span { class: "srv-kv-label", {t!("serverDetail.org")} } span { "{asn.org}" } }
                    if let Some(network) = &asn.network {
                        div { class: "srv-kv-line", span { class: "srv-kv-label", {t!("serverDetail.network_")} } span { class: "swiss-mono", "{network}" } }
                    }
                    if let Some(country) = &asn.country {
                        div { class: "srv-kv-line", span { class: "srv-kv-label", {t!("serverDetail.country")} } span { "{country}" } }
                    }
                }
            }
            section { class: "srv-detail-card",
                h3 { class: "swiss-label", {t!("serverDetail.latency")} }
                if let Some(latency) = &report.latency {
                    LatencyCard { latency: latency.clone() }
                } else if tunnel_running {
                    p { class: "srv-detail-note", {t!("ui.servers.detail.latencyTunnel")} }
                } else {
                    p { class: "srv-detail-note", {t!("ui.servers.detail.latencyNone")} }
                }
            }
            section { class: "srv-detail-card",
                h3 { class: "swiss-label", {t!("serverDetail.openPorts")} }
                if report.open_ports.is_empty() {
                    p { class: "srv-detail-note", {t!("ui.servers.detail.portClosed")} }
                } else {
                    div { class: "srv-chips",
                        for port in report.open_ports.iter() {
                            Badge { key: "{port.port}", tone: Tone::Ok,
                                "{port.port}"
                                if let Some(service) = &port.service { " — {service}" }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Min / avg / max, jitter, failed connects and the samples as a tiny bar chart.
#[component]
pub(crate) fn LatencyCard(latency: LatencyStats) -> Element {
    let loss_tone = if latency.loss > 0.2 {
        Tone::Fail
    } else if latency.loss > 0.0 {
        Tone::Warn
    } else {
        Tone::Ok
    };
    let top = latency.samples.iter().copied().max().unwrap_or(1).max(1);
    let stats = [
        (t!("serverDetail.latencyMin"), latency.min, false),
        (t!("serverDetail.latencyAvg"), latency.avg, true),
        (t!("serverDetail.latencyMax"), latency.max, false),
        (t!("serverDetail.jitter"), latency.jitter, false),
    ];
    rsx! {
        div { class: "srv-latency",
            for (label , value , main) in stats {
                div { key: "{label}", class: "srv-latency-stat", class: if main { "is-main" },
                    span { class: "swiss-label", "{label}" }
                    span { class: "swiss-mono", {t!("ui.servers.row.ms", ms = value)} }
                }
            }
            div { class: "srv-latency-stat",
                span { class: "swiss-label", {t!("serverDetail.loss")} }
                Badge { tone: loss_tone, {format!("{}%", (latency.loss * 100.0).round())} }
            }
        }
        if !latency.samples.is_empty() {
            div { class: "srv-spark", aria_hidden: "true",
                for (i , sample) in latency.samples.iter().enumerate() {
                    span {
                        key: "{i}",
                        class: "srv-spark-bar",
                        title: t!("ui.servers.row.ms", ms = sample),
                        style: "height:{(f64::from(*sample) / f64::from(top) * 100.0).max(8.0):.0}%",
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use vpnte_base::AppError;

    use super::*;

    /// §7.6 "cancels on the UI deadline and does not display a late result" and "keeps typed
    /// cancellation quiet": past the deadline (10 s in the dialog) the read is failed; a
    /// cancellation is no outcome at all.
    #[tokio::test]
    async fn probe_reads_have_a_ui_deadline() {
        let limit = Duration::from_millis(30);
        let started = tokio::time::Instant::now();
        let hung = with_deadline(limit, std::future::pending::<AppResult<u32>>()).await;
        assert_eq!(hung, Some(Read::Failed));
        assert!(started.elapsed() >= limit);
        assert_eq!(
            with_deadline(limit, async { Ok(7) }).await,
            Some(Read::Done(7))
        );
        let cancelled = with_deadline(limit, async { Err::<u32, _>(AppError::cancelled()) });
        assert_eq!(cancelled.await, None);
        let timeout = with_deadline(limit, async { Err::<u32, _>(AppError::timeout()) });
        assert_eq!(timeout.await, Some(Read::Failed));
        assert_eq!(PROBE_UI_TIMEOUT, Duration::from_secs(10));
    }
}
