//! [`ServersApi`] of the demo: store edits, imports, exports, groups and proxies over the
//! fake store; the live checks delegate to `live.rs`.
use std::num::NonZeroU32;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;
use vpnte_base::types::{ClientDevice, now_ms};
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

use super::*;
use crate::servers::api::ServersApi;
use crate::servers::demo_data::{DEMO_PC_ID, demo_verdict, test_ip};
use crate::servers::links_model::{LinkSchemes, QrCode};

#[async_trait::async_trait(?Send)]
impl ServersApi for DemoServersApi {
    fn state(&self) -> watch::Receiver<ServersView> {
        self.state.subscribe()
    }

    fn expanded_groups(&self) -> Vec<String> {
        self.expanded.borrow().clone()
    }

    async fn save_expanded_groups(&self, ids: Vec<String>) -> AppResult<()> {
        *self.expanded.borrow_mut() = ids;
        Ok(())
    }

    async fn resolve_ips(&self) -> AppResult<()> {
        delay(400).await;
        self.edit(|v| {
            for (i, s) in v.servers.iter_mut().enumerate() {
                if s.resolved_ip.is_none() {
                    s.resolved_ip = Some(test_ip(200 + (i % 50) as u8));
                }
            }
        });
        Ok(())
    }

    async fn add(
        &self,
        input: String,
        target: AddTarget,
        device: ClientDevice,
        request: SubscriptionRequest,
    ) -> AppResult<ImportReport> {
        delay(1_200).await;
        let text = input.trim();
        if text.is_empty() {
            return Err(AppError::validation(Msg::new("ui.servers.demo.emptyInput")));
        }
        if let AddTarget::Group(id) = &target
            && !self.view().groups.iter().any(|g| &g.id == id)
        {
            return Err(AppError::conflict(Msg::new("ui.servers.demo.unknownGroup")));
        }
        let now = now_ms();
        let n = self.next_run();
        let lower = text.to_ascii_lowercase();
        if lower.starts_with("https://") || lower.starts_with("http://") {
            let gid = format!("sub-{n}");
            let fresh = [
                ("Austria · Vienna", "vless", "AT", Stealth::Reality),
                ("Norway · Oslo", "trojan", "NO", Stealth::Tls),
                ("Spain · Madrid", "hysteria2", "ES", Stealth::Obfs),
            ];
            self.edit(|v| {
                v.groups.push(GroupView {
                    id: gid.clone(),
                    name: format!("Subscription {n}"),
                    source: GroupSource::Subscription,
                    status: GroupStatus::Active,
                    imported_at: now,
                    last_fetched_at: Some(now),
                    last_fetch_attempt_at: Some(now),
                    send_hwid: request.send_hwid,
                    device_id: Some(DEMO_PC_ID.into()),
                    header_names: header_names(&request.headers),
                    ..GroupView::default()
                });
                for (i, (name, protocol, country, stealth)) in fresh.iter().enumerate() {
                    v.servers.push(ServerView {
                        id: format!("{gid}-{i}"),
                        name: (*name).into(),
                        protocol: (*protocol).into(),
                        host: format!("{gid}-{i}.vpn.example.net"),
                        port: 443,
                        country: Some((*country).into()),
                        device,
                        has_outbound: true,
                        stealth: Some(*stealth),
                        group_id: Some(gid.clone()),
                        last_seen_in_subscription_at: Some(now),
                        enabled: true,
                        ..ServerView::default()
                    });
                }
            });
            let providers = if lower.contains("clash") {
                vec![ProviderLine {
                    name: "Main".into(),
                    servers: 3,
                    error: None,
                }]
            } else {
                Vec::new()
            };
            return Ok(ImportReport {
                group_name: format!("Subscription {n}"),
                subscription: true,
                added: 3,
                providers,
                ..ImportReport::default()
            });
        }
        let mut keys = Vec::new();
        let mut skipped = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let lower = line.to_ascii_lowercase();
            match SCHEMES.iter().find(|s| lower.starts_with(*s)) {
                Some(scheme) => keys.push((
                    scheme.trim_end_matches("://"),
                    line.split_once('#').map(|(_, n)| n.to_owned()),
                )),
                None => skipped.push(SkippedLine {
                    line: u32::try_from(i + 1).unwrap_or(u32::MAX),
                    reason: Msg::new("ui.servers.demo.unsupportedLine"),
                }),
            }
        }
        if keys.is_empty() {
            return Err(AppError::validation(Msg::new("ui.servers.demo.noProfiles")));
        }
        let gid = match target {
            AddTarget::Group(id) => id,
            AddTarget::Auto => "keys".to_owned(),
        };
        let added = u32::try_from(keys.len()).unwrap_or(u32::MAX);
        self.edit(|v| {
            if !v.groups.iter().any(|g| g.id == gid) {
                v.groups.push(GroupView {
                    id: gid.clone(),
                    name: "Ручные ключи".into(),
                    imported_at: now,
                    ..GroupView::default()
                });
            }
            for (i, (scheme, label)) in keys.into_iter().enumerate() {
                let protocol = match scheme {
                    "ss" => "shadowsocks",
                    "hy2" => "hysteria2",
                    other => other,
                };
                v.servers.push(ServerView {
                    id: format!("key-{n}-{i}"),
                    name: label.unwrap_or_else(|| format!("imported-{n}-{}", i + 1)),
                    protocol: protocol.into(),
                    host: format!("key-{n}-{i}.vpn.example.net"),
                    port: 443,
                    device,
                    has_outbound: true,
                    group_id: Some(gid.clone()),
                    enabled: true,
                    ..ServerView::default()
                });
            }
        });
        let group_name = self
            .view()
            .groups
            .iter()
            .find(|g| g.id == gid)
            .map(|g| g.name.clone())
            .unwrap_or_default();
        Ok(ImportReport {
            group_name,
            subscription: false,
            added,
            updated: 0,
            unchanged: 0,
            skipped,
            providers: Vec::new(),
        })
    }

    async fn remove(&self, id: &str) -> AppResult<()> {
        delay(300).await;
        self.known(id)?;
        let now = now_ms();
        self.edit(|v| {
            if let Some(s) = v.servers.iter_mut().find(|s| s.id == id) {
                // The purge clock keeps running from the first archiving.
                let at = s.archived.map_or(now, |a| a.at);
                s.archived = Some(Archive {
                    reason: ArchiveReason::User,
                    at,
                    purge_at: at + ARCHIVE_TTL_MS,
                });
            }
            if v.active_id.as_deref() == Some(id) {
                v.active_id = None;
            }
        });
        Ok(())
    }

    async fn restore(&self, id: &str) -> AppResult<()> {
        delay(250).await;
        self.known(id)?;
        self.edit_server(id, |s| s.archived = None);
        Ok(())
    }

    async fn purge(&self, id: &str) -> AppResult<()> {
        delay(300).await;
        self.known(id)?;
        self.edit(|v| {
            v.servers.retain(|s| s.id != id);
            if v.active_id.as_deref() == Some(id) {
                v.active_id = None;
            }
        });
        Ok(())
    }

    async fn select(&self, id: &str) -> AppResult<SelectOutcome> {
        let server = self.known(id)?;
        if server
            .archived
            .is_some_and(|a| a.reason == ArchiveReason::User)
            || !server.enabled
        {
            return Err(AppError::conflict(Msg::new("ui.servers.demo.unavailable")));
        }
        if !self.state.borrow().tunnel_running {
            delay(150).await;
            self.edit(|v| v.active_id = Some(id.to_owned()));
            return Ok(SelectOutcome::Switched);
        }
        self.edit(|v| v.switching_to = Some(id.to_owned()));
        let marker = SwitchMarker(self);
        let cancelled = tokio::select! {
            () = delay(2_600) => false,
            () = self.cancel_switch.notified() => true,
        };
        if !cancelled {
            self.edit(|v| v.active_id = Some(id.to_owned()));
        }
        drop(marker);
        Ok(if cancelled {
            SelectOutcome::Cancelled
        } else {
            SelectOutcome::Switched
        })
    }

    async fn cancel_switch(&self) -> AppResult<()> {
        self.cancel_switch.notify_waiters();
        Ok(())
    }

    async fn ping_one(&self, id: &str) -> AppResult<Option<u32>> {
        delay(350 + fastrand::u64(0..500)).await;
        self.known(id)?;
        let ms = self.measure(id);
        self.record_ping(id, ms);
        Ok(ms)
    }

    async fn ping_many(
        &self,
        ids: Vec<String>,
        results: mpsc::UnboundedSender<(String, Option<u32>)>,
    ) -> AppResult<()> {
        for chunk in ids.chunks(5) {
            delay(450 + fastrand::u64(0..300)).await;
            for id in chunk {
                let ms = self.measure(id);
                self.record_ping(id, ms);
                let _ = results.send((id.clone(), ms));
            }
        }
        Ok(())
    }

    async fn verify_country(&self, id: &str) -> AppResult<CountryCheck> {
        delay(900).await;
        let server = self.known(id)?;
        if self.state.borrow().geo_lookup_disabled {
            return Ok(CountryCheck::GeoDisabled);
        }
        if server.ping_ms.is_none() {
            return Ok(CountryCheck::Failed);
        }
        let country = server.country.unwrap_or_else(|| "NL".into());
        let code = country.clone();
        self.edit_server(id, move |s| {
            s.country = Some(code);
            s.exit_ip = Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                203, 0, 113, 47,
            )));
        });
        Ok(CountryCheck::Verified(country))
    }

    async fn copy_key(&self, id: &str) -> AppResult<Duration> {
        delay(150).await;
        shareable(self.known(id)?)?;
        Ok(Duration::from_secs(60))
    }

    async fn save_key(&self, id: &str) -> AppResult<Option<String>> {
        delay(500).await;
        let server = shareable(self.known(id)?)?;
        let name: String = server
            .name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect();
        Ok(Some(format!(
            r"C:\Users\Demo\Desktop\{}-{}.txt",
            server.protocol,
            name.trim_matches('-')
        )))
    }

    async fn export_all_keys(&self) -> AppResult<Option<ExportReport>> {
        delay(1_400).await;
        let view = self.view();
        let hidden = view.servers.iter().filter(|s| s.config_hidden).count();
        let count = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        let total = count(view.servers.len() - hidden);
        Ok(Some(ExportReport {
            path: r"C:\Users\Demo\Desktop\vpn-keys-20261111-0912.txt".into(),
            exported: total.saturating_sub(1),
            skipped: u32::from(total > 0),
            hidden: count(hidden),
        }))
    }

    async fn export_proxy_list(&self) -> AppResult<Option<ExportReport>> {
        delay(1_100).await;
        Err(AppError::new(ErrorKind::Internal))
    }

    async fn start_proxies(&self, ids: Vec<String>) -> AppResult<ProxyStartReport> {
        delay(700).await;
        let view = self.view();
        let mut report = ProxyStartReport::default();
        let mut slot = 1;
        for id in ids {
            let Some(server) = view.servers.iter().find(|s| s.id == id) else {
                continue;
            };
            if view.active_id.as_deref() == Some(id.as_str()) {
                report.skipped.push((id, ProxySkip::ActiveVpn));
            } else if server.archived.is_some() || !server.enabled {
                report.skipped.push((id, ProxySkip::Unavailable));
            } else if id == "de-fra" {
                report.already_running.push(id);
            } else {
                report.started.push(StartedProxy {
                    profile_id: id,
                    slot,
                    listen: Some(format!("127.0.0.1:{}", 18_000 + slot)),
                });
                slot += 1;
            }
        }
        Ok(report)
    }

    async fn refresh_group(&self, id: &str) -> AppResult<RefreshOutcome> {
        delay(1_500).await;
        let group = self
            .view()
            .groups
            .into_iter()
            .find(|g| g.id == id)
            .ok_or_else(|| AppError::validation(Msg::new("ui.servers.demo.unknownGroup")))?;
        let now = now_ms();
        if group.status == GroupStatus::Expired {
            self.edit(|v| {
                if let Some(g) = v.groups.iter_mut().find(|g| g.id == id) {
                    g.last_fetch_attempt_at = Some(now);
                    g.last_fetch_error = Some(FetchError::Empty);
                }
            });
            return Ok(RefreshOutcome::Failed(FetchError::Empty));
        }
        self.edit(|v| {
            if let Some(g) = v.groups.iter_mut().find(|g| g.id == id) {
                g.last_fetched_at = Some(now);
                g.last_fetch_attempt_at = Some(now);
                g.last_fetch_error = None;
                g.status = GroupStatus::Active;
            }
            for s in v
                .servers
                .iter_mut()
                .filter(|s| s.group_id.as_deref() == Some(id))
            {
                if s.archived.is_none() {
                    s.last_seen_in_subscription_at = Some(now);
                }
            }
        });
        Ok(RefreshOutcome::Refreshed {
            added: 0,
            updated: 2,
            removed: 0,
            expired: false,
        })
    }

    async fn set_refresh_interval(&self, id: &str, minutes: Option<NonZeroU32>) -> AppResult<()> {
        delay(250).await;
        self.edit(|v| {
            if let Some(g) = v.groups.iter_mut().find(|g| g.id == id) {
                g.refresh_minutes = minutes;
            }
        });
        Ok(())
    }

    async fn set_send_hwid(&self, id: &str, on: bool) -> AppResult<()> {
        delay(200).await;
        self.edit(|v| {
            if let Some(g) = v.groups.iter_mut().find(|g| g.id == id) {
                g.send_hwid = on;
            }
        });
        Ok(())
    }

    async fn set_own_device_id(&self, id: &str, own: bool) -> AppResult<()> {
        delay(200).await;
        let fresh = format!("{:016x}", 0x3f9c_0b7e_5d2a_4c81_u64 ^ self.next_run());
        self.edit(|v| {
            if let Some(g) = v.groups.iter_mut().find(|g| g.id == id) {
                g.own_device_id = own;
                g.device_id = Some(if own { fresh } else { DEMO_PC_ID.into() });
            }
        });
        Ok(())
    }

    async fn set_request_headers(&self, id: &str, lines: String) -> AppResult<Vec<String>> {
        delay(300).await;
        let names = header_names(&lines);
        self.edit(|v| {
            if let Some(g) = v.groups.iter_mut().find(|g| g.id == id) {
                g.header_names = names.clone();
            }
        });
        Ok(names)
    }

    async fn rename_group(&self, id: &str, name: String) -> AppResult<()> {
        delay(200).await;
        let name: String = name.trim().chars().take(60).collect();
        if name.is_empty() {
            return Err(AppError::validation(Msg::new("ui.servers.demo.emptyName")));
        }
        self.edit(|v| {
            if let Some(g) = v.groups.iter_mut().find(|g| g.id == id) {
                g.name = name;
            }
        });
        Ok(())
    }

    async fn delete_group(&self, id: &str, delete_servers: bool) -> AppResult<()> {
        delay(500).await;
        self.edit(|v| {
            v.groups.retain(|g| g.id != id);
            if delete_servers {
                let active = v.active_id.clone();
                v.servers.retain(|s| s.group_id.as_deref() != Some(id));
                if active.is_some_and(|a| !v.servers.iter().any(|s| s.id == a)) {
                    v.active_id = None;
                }
            } else {
                for s in v
                    .servers
                    .iter_mut()
                    .filter(|s| s.group_id.as_deref() == Some(id))
                {
                    s.group_id = None;
                }
            }
        });
        Ok(())
    }

    async fn check_group_health(&self, id: &str) -> AppResult<HealthReport> {
        delay(2_000).await;
        let now = now_ms();
        let results: Vec<(String, KeyHealth)> = self
            .view()
            .servers
            .iter()
            .filter(|s| s.group_id.as_deref() == Some(id) && s.archived.is_none())
            .map(|s| {
                let online = s.ping_ms.is_some() || s.id == "se-sto";
                let health = KeyHealth {
                    online,
                    latency_ms: online.then(|| 300 + fastrand::u32(0..400)),
                    reason: (!online).then_some(KeyHealthReason::AuthFailed),
                    checked_at: now,
                };
                (s.id.clone(), health)
            })
            .collect();
        if results.is_empty() {
            return Err(AppError::validation(Msg::new(
                "ui.servers.demo.noCurrentServers",
            )));
        }
        self.edit(|v| {
            for (sid, health) in &results {
                if let Some(s) = v.servers.iter_mut().find(|s| &s.id == sid) {
                    s.health = Some(health.clone());
                    let kind = if health.online {
                        VerdictKind::Healthy
                    } else {
                        VerdictKind::KeyRejected
                    };
                    s.verdict = Some(demo_verdict(kind, None, now));
                }
            }
        });
        Ok(HealthReport {
            results,
            not_checked: 0,
        })
    }

    async fn check_all_health(
        &self,
        results: mpsc::UnboundedSender<(String, KeyHealth)>,
    ) -> AppResult<HealthReport> {
        let ids: Vec<(String, bool)> = (self.view().servers.iter())
            .filter(|s| s.archived.is_none())
            .map(|s| (s.id.clone(), s.ping_ms.is_some() || s.id == "se-sto"))
            .collect();
        let mut done = Vec::new();
        // Five probes at a time, like the real check (its per-name budget only slows it down).
        for chunk in ids.chunks(5) {
            delay(1_200 + fastrand::u64(0..600)).await;
            let now = now_ms();
            for (id, online) in chunk {
                let health = KeyHealth {
                    online: *online,
                    latency_ms: online.then(|| 300 + fastrand::u32(0..400)),
                    reason: (!online).then_some(KeyHealthReason::AuthFailed),
                    checked_at: now,
                };
                self.edit_server(id, |s| s.health = Some(health.clone()));
                let _ = results.send((id.clone(), health.clone()));
                done.push((id.clone(), health));
            }
        }
        Ok(HealthReport {
            results: done,
            not_checked: 0,
        })
    }

    async fn set_device(&self, id: &str, device: ClientDevice) -> AppResult<()> {
        delay(400).await;
        self.known(id)?;
        self.edit_server(id, |s| {
            s.device = device;
            s.fingerprint = None;
        });
        Ok(())
    }

    async fn set_engine(&self, id: &str, engine: vpnte_base::types::EnginePref) -> AppResult<()> {
        delay(300).await;
        self.known(id)?;
        self.edit_server(id, |s| s.engine = engine);
        Ok(())
    }

    async fn set_whitelist_ready(&self, id: &str, on: bool) -> AppResult<()> {
        delay(200).await;
        self.known(id)?;
        self.edit_server(id, |s| {
            s.whitelist = on.then(|| WhitelistReady {
                marked: true,
                worked_at: s.whitelist.and_then(|w| w.worked_at),
            });
        });
        Ok(())
    }

    async fn tls_tricks(&self, id: &str) -> AppResult<Option<TricksView>> {
        delay(150).await;
        let server = self.known(id)?;
        // Tricks cut a TLS ClientHello over TCP: QUIC, WireGuard, plain and REALITY keys (its
        // hello names a camouflage site, neither engine cuts it) have none.
        let tcp = !matches!(server.protocol.as_str(), "hysteria2" | "tuic" | "wireguard");
        let tls = matches!(
            server.stealth,
            Some(Stealth::Tls | Stealth::Utls | Stealth::Ech)
        );
        if !(tcp && tls) {
            return Ok(None);
        }
        // One key arrives with its provider's own split, so the demo shows that state too.
        let provider = (server.stealth == Some(Stealth::Utls)).then_some(TricksChoice::Custom {
            record: false,
            split: TricksSplit {
                len: (40, 60),
                interval_ms: (30, 50),
            },
        });
        let stored = self.tricks.borrow().get(id).copied();
        Ok(Some(TricksView {
            choice: stored.or(provider).unwrap_or(TricksChoice::Default),
            default_strong: false,
            provider,
        }))
    }

    async fn set_tls_tricks(&self, id: &str, choice: TricksChoice) -> AppResult<()> {
        delay(250).await;
        self.known(id)?;
        self.tricks.borrow_mut().insert(id.to_owned(), choice);
        Ok(())
    }

    async fn probe(&self, id: &str) -> AppResult<ProbeReport> {
        self.demo_probe(id).await
    }

    async fn geo(&self, id: &str) -> AppResult<Option<GeoInfo>> {
        self.demo_geo(id).await
    }

    async fn live_check(
        &self,
        id: &str,
        mode: LiveMode,
        progress: mpsc::UnboundedSender<LiveProgress>,
    ) -> AppResult<LiveCheck> {
        self.demo_live_check(id, mode, progress).await
    }

    async fn live_history(&self, id: &str) -> AppResult<Vec<LiveCheck>> {
        self.demo_live_history(id).await
    }

    async fn live_batch(
        &self,
        ids: Vec<String>,
        stop: CancellationToken,
        progress: mpsc::UnboundedSender<BatchProgress>,
    ) -> AppResult<BatchResult> {
        self.demo_live_batch(ids, stop, progress).await
    }

    async fn open_url(&self, _url: String) -> AppResult<()> {
        // The demo never starts a browser (unattended machine); the link text is not logged
        // either: a provider panel URL can carry an account token.
        tracing::info!("demo: provider link requested");
        Ok(())
    }

    async fn copy_text(&self, _text: String) -> AppResult<()> {
        // The demo leaves the user's clipboard alone.
        tracing::info!("demo: a request for the provider was copied");
        Ok(())
    }

    fn link_arrivals(&self) -> watch::Receiver<u64> {
        self.links.arrivals()
    }

    fn take_link(&self) -> Option<String> {
        self.links.take()
    }

    async fn read_clipboard(&self) -> AppResult<String> {
        delay(150).await;
        Ok(links::FAKE_KEY.to_owned())
    }

    async fn read_key_file(&self) -> AppResult<Option<String>> {
        delay(300).await;
        Ok(Some(format!(
            "{}
",
            links::FAKE_KEY
        )))
    }

    async fn scan_qr_file(&self) -> AppResult<Option<String>> {
        self.links.scan().await.map(Some)
    }

    async fn scan_qr_screen(&self, captured: oneshot::Sender<()>) -> AppResult<String> {
        delay(100).await;
        let _ = captured.send(());
        self.links.scan().await
    }

    async fn key_qr(&self, id: &str) -> AppResult<QrCode> {
        delay(200).await;
        let server = self.known(id)?;
        if server.config_hidden {
            return Err(AppError::validation(Msg::new("ui.servers.hidden.refused")));
        }
        Ok(links::fake_qr(id))
    }

    async fn link_schemes(&self) -> AppResult<LinkSchemes> {
        delay(150).await;
        Ok(self.links.schemes())
    }

    async fn set_link_scheme(&self, scheme: String, on: bool) -> AppResult<LinkSchemes> {
        Ok(self.links.set(&scheme, on).await)
    }

    async fn adopt_link_schemes(&self) -> AppResult<LinkSchemes> {
        Ok(self.links.adopt().await)
    }
}

/// The demo's header check: the names of `Name: value` lines.
fn header_names(lines: &str) -> Vec<String> {
    lines
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(name, _)| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .collect()
}

/// A server whose key the demo may hand out (its provider does not hide it).
fn shareable(server: ServerView) -> AppResult<ServerView> {
    if server.config_hidden {
        return Err(AppError::validation(Msg::new("ui.servers.hidden.refused")));
    }
    Ok(server)
}
