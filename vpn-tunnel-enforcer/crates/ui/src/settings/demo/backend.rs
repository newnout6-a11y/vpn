//! The demo backend's answers: [`SettingsApi`] over the in-memory state, with short delays and
//! the failures of the `failures` scene.
use async_trait::async_trait;
use tokio::sync::watch;
use vpnte_base::types::now_ms;
use vpnte_base::{AppError, AppResult, ErrorKind, Msg};

use super::*;
use crate::settings::api::SettingsApi;

/// Which saved fields restart a running tunnel, and which apply at the next connect.
fn save_effects(patch: &SettingsPatch) -> (bool, bool) {
    let restart = patch.leak_protection.is_some()
        || patch.public_wifi_compatibility.is_some()
        || patch.stealth_mode.is_some()
        || patch.adaptive_bypass.is_some();
    let next = patch.connection_mode.is_some()
        || patch.routing_mode.is_some()
        || patch.proxy_engine.is_some()
        || patch.smart_ru_split.is_some()
        || patch.smart_ru_maps_direct.is_some()
        || patch.smart_ru_auto_update.is_some()
        || patch.soft_git.is_some()
        || patch.soft_gradle.is_some()
        || patch.soft_studio.is_some();
    (restart, next)
}

#[async_trait(?Send)]
impl SettingsApi for DemoSettingsApi {
    fn state(&self) -> watch::Receiver<SettingsState> {
        self.state.subscribe()
    }
    fn kill_switch(&self) -> watch::Receiver<KillSwitchView> {
        self.kill.subscribe()
    }
    fn rotation(&self) -> watch::Receiver<RotationView> {
        self.rotation.subscribe()
    }
    fn dns(&self) -> watch::Receiver<DnsView> {
        self.dns.subscribe()
    }
    fn domains(&self) -> watch::Receiver<DomainsView> {
        self.domains.subscribe()
    }
    fn notifications(&self) -> watch::Receiver<NotificationsView> {
        self.notifications.subscribe()
    }

    async fn save(&self, patch: SettingsPatch) -> AppResult<SaveReport> {
        pause(500).await;
        if self.failures {
            return Err(demo_err(ErrorKind::Permission, "errors.permission"));
        }
        let (restart, next_connect) = save_effects(&patch);
        let connected = self.state.borrow().connected;
        self.state.send_modify(|s| {
            patch.apply_to(&mut s.settings);
            s.settings.proxy_override = s.settings.proxy_override.trim().to_owned();
            if let Some(proxy) = &patch.proxy_override
                && let Some((_, addr)) = proxy.rsplit_once('@')
            {
                // credentials are kept by the backend, never shown again
                s.settings.proxy_override = addr.trim().to_owned();
                s.proxy_credentials_saved = true;
            }
        });
        self.domains
            .send_modify(|d| d.smart_ru = self.state.borrow().settings.smart_ru_split);
        Ok(SaveReport {
            settings: self.state.borrow().settings.clone(),
            restart: (restart && connected).then_some(Ok(())),
            next_connect,
        })
    }

    async fn set_language(&self, lang: Lang) -> AppResult<()> {
        self.state.send_modify(|s| s.locale = Some(lang));
        Ok(())
    }

    async fn set_theme(&self, id: String) -> AppResult<()> {
        let Some(mode) = self
            .state
            .borrow()
            .themes
            .iter()
            .find(|t| t.id == id)
            .map(|t| t.mode)
        else {
            return Err(AppError::new(ErrorKind::Validation));
        };
        // The demo has no custom palettes: a custom theme shows its built-in mode.
        *crate::theme::THEME.write() = crate::theme::Theme::builtin(mode);
        self.state.send_modify(|s| s.active_theme_id = id);
        Ok(())
    }

    async fn set_autostart(&self, on: bool) -> AppResult<bool> {
        pause(400).await;
        self.state.send_modify(|s| s.autostart = on);
        Ok(on)
    }

    async fn set_location_privacy(&self, on: bool) -> AppResult<LocationOutcome> {
        pause(600).await;
        let connected = self.state.borrow().connected;
        self.state.send_modify(|s| s.location_privacy = on);
        Ok(if connected {
            LocationOutcome::Applied
        } else {
            LocationOutcome::Stored
        })
    }

    async fn apply_browser_protection(&self) -> AppResult<BrowserView> {
        pause(900).await;
        let view = BrowserView {
            browsers: browsers(|name| {
                if name.contains("Firefox") {
                    BrowserStatus::NotInstalled
                } else if self.failures && name.contains("Edge") {
                    BrowserStatus::Failed(Msg::new("errors.permission"))
                } else {
                    BrowserStatus::Protected
                }
            }),
            restart_required: true,
        };
        self.state.send_modify(|s| s.browser = view.clone());
        Ok(view)
    }

    async fn rollback_browser_protection(&self) -> AppResult<BrowserView> {
        pause(700).await;
        let view = BrowserView {
            browsers: browsers(|name| {
                if name.contains("Firefox") {
                    BrowserStatus::NotInstalled
                } else {
                    BrowserStatus::NotProtected
                }
            }),
            restart_required: false,
        };
        self.state.send_modify(|s| s.browser = view.clone());
        Ok(view)
    }

    async fn retry_adaptive(&self) -> AppResult<bool> {
        pause(400).await;
        let connected = self.state.borrow().connected;
        if connected {
            self.state.send_modify(|s| {
                s.adaptive.phase = AdaptivePhase::Verifying;
                s.adaptive.message = Some(Msg::new("ui.settings.demo.adaptiveVerifying"));
            });
        }
        Ok(connected)
    }

    async fn reset_adaptive_learning(&self) -> AppResult<()> {
        pause(300).await;
        Ok(())
    }

    async fn refresh_rule_sets(&self) -> AppResult<()> {
        self.state.send_modify(|s| s.rule_sets.refreshing = true);
        pause(1500).await;
        let failed = self.failures;
        self.state.send_modify(|s| {
            s.rule_sets.refreshing = false;
            if failed {
                s.rule_sets.last_error = Some(Msg::new("errors.network"));
            } else {
                s.rule_sets = RuleSetView {
                    active_source: RuleSource::Managed,
                    managed_at: Some(now_ms()),
                    refreshing: false,
                    last_error: None,
                };
            }
        });
        if failed {
            return Err(demo_err(ErrorKind::Network, "errors.network"));
        }
        Ok(())
    }

    async fn open_wizard(&self) -> AppResult<()> {
        tracing::info!(target: "ui", "demo: the wizard would open now");
        Ok(())
    }

    async fn open_logs_folder(&self) -> AppResult<()> {
        pause(200).await;
        Ok(())
    }

    async fn export_diagnostics(&self) -> AppResult<DiagnosticsExport> {
        self.state
            .send_modify(|s| s.diagnostics_export_running = true);
        pause(1500).await;
        self.state
            .send_modify(|s| s.diagnostics_export_running = false);
        if self.failures {
            return Err(AppError::new(ErrorKind::Permission));
        }
        Ok(DiagnosticsExport {
            path: r"C:\Users\demo\Desktop\vpn-tunnel-enforcer-diagnostics-2026-11-11T09-30-00-000Z.zip".into(),
            cleanup_failed: false,
        })
    }

    async fn clear_captures(&self) -> AppResult<()> {
        pause(600).await;
        self.state.send_modify(|s| s.capture_used_bytes = Some(0));
        Ok(())
    }

    async fn set_kill_switch_level(&self, level: KillSwitchLevel) -> AppResult<()> {
        pause(900).await;
        if self.failures && level == KillSwitchLevel::Strict {
            return Err(demo_err(ErrorKind::Permission, "errors.permission"));
        }
        let connected = self.state.borrow().connected;
        self.kill.send_modify(|k| {
            k.level = level;
            k.status = match (level, connected) {
                (KillSwitchLevel::Off, _) => ProtectionStatus::Off,
                (_, true) => ProtectionStatus::Engaged,
                (KillSwitchLevel::Standard, false) => ProtectionStatus::Armed,
                (KillSwitchLevel::Strict, false) => ProtectionStatus::Blocking,
            };
        });
        Ok(())
    }

    async fn add_exception(
        &self,
        kind: ExceptionKind,
        value: String,
        label: String,
    ) -> AppResult<()> {
        pause(400).await;
        let ok = match kind {
            ExceptionKind::App => {
                let lower = value.to_ascii_lowercase();
                lower.ends_with(".exe") && lower.as_bytes().get(1) == Some(&b':')
            }
            ExceptionKind::Ip => value.parse::<std::net::IpAddr>().is_ok() || value.contains('/'),
        };
        if !ok {
            let key = match kind {
                ExceptionKind::App => "ui.settings.demo.badApp",
                ExceptionKind::Ip => "ui.settings.demo.badIp",
            };
            return Err(AppError::validation(Msg::new(key)));
        }
        let broad =
            matches!(value.rsplit_once('/'), Some((_, p)) if p.parse::<u8>().is_ok_and(|p| p < 8));
        let id = self.id("ex");
        self.kill.send_modify(|k| {
            k.exceptions.push(ExceptionView {
                id,
                kind,
                value,
                label,
                broad,
            });
        });
        Ok(())
    }

    async fn remove_exception(&self, id: String) -> AppResult<()> {
        pause(300).await;
        self.kill
            .send_modify(|k| k.exceptions.retain(|e| e.id != id));
        Ok(())
    }

    async fn pick_app(&self) -> AppResult<Option<PickedApp>> {
        pause(300).await;
        Ok(Some(PickedApp {
            path: r"C:\Program Files\Demo\Telegram.exe".into(),
            name: "Telegram".into(),
        }))
    }

    async fn set_rotation(&self, patch: RotationPatch) -> AppResult<()> {
        pause(300).await;
        if self.failures && patch.interval_minutes.is_some() {
            return Err(demo_err(ErrorKind::Permission, "errors.permission"));
        }
        self.rotation.send_modify(|r| {
            if let Some(on) = patch.enabled {
                r.enabled = on;
                r.next_rotation_at = on.then(|| now_ms() + i64::from(r.interval_minutes) * 60_000);
            }
            if let Some(minutes) = patch.interval_minutes {
                r.interval_minutes = minutes;
                r.next_rotation_at = r.enabled.then(|| now_ms() + i64::from(minutes) * 60_000);
            }
            if let Some(order) = patch.order {
                r.order = order;
            }
        });
        Ok(())
    }

    async fn set_rotation_profile(&self, id: String, included: bool) -> AppResult<()> {
        pause(200).await;
        self.rotation.send_modify(|r| {
            r.profile_ids.retain(|p| *p != id);
            if included {
                r.profile_ids.push(id);
            }
        });
        Ok(())
    }

    async fn rotate_now(&self) -> AppResult<RotationOutcome> {
        pause(1200).await;
        if !self.state.borrow().direct_session {
            return Ok(RotationOutcome::NothingToRotate);
        }
        if self.failures {
            return Ok(RotationOutcome::Failed {
                reason: Msg::new("errors.network"),
                restored_previous: true,
            });
        }
        let rot = self.rotation.borrow().clone();
        if rot.profile_ids.is_empty() {
            return Ok(RotationOutcome::NoProfiles);
        }
        let at = rot
            .current_profile_id
            .as_ref()
            .and_then(|c| rot.profile_ids.iter().position(|p| p == c))
            .map_or(0, |i| (i + 1) % rot.profile_ids.len());
        let next = rot.profile_ids[at].clone();
        if Some(&next) == rot.current_profile_id.as_ref() {
            return Ok(RotationOutcome::NothingToRotate);
        }
        self.rotation.send_modify(|r| {
            r.current_profile_id = Some(next.clone());
            r.next_rotation_at = Some(now_ms() + i64::from(r.interval_minutes) * 60_000);
        });
        Ok(RotationOutcome::Rotated { profile_id: next })
    }

    async fn validate_dns(&self, address: String) -> AppResult<DnsKind> {
        pause(250).await;
        let lower = address.trim().to_ascii_lowercase();
        if lower.starts_with("https://") && lower.len() > "https://".len() + 3 {
            Ok(DnsKind::Doh)
        } else if lower.starts_with("tls://") && lower.len() > "tls://".len() + 3 {
            Ok(DnsKind::Dot)
        } else {
            match lower.parse::<std::net::IpAddr>() {
                Ok(ip) if !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() => {
                    Ok(DnsKind::Plain)
                }
                _ => Err(AppError::validation(Msg::new("settings.dnsInvalidAddress"))),
            }
        }
    }

    async fn create_dns(&self, name: String, address: String) -> AppResult<()> {
        let kind = self.validate_dns(address.clone()).await?;
        let id = self.id("dns");
        self.dns.send_modify(|d| {
            d.profiles.push(DnsProfileView {
                id,
                name,
                address,
                kind,
                builtin: false,
            });
        });
        Ok(())
    }

    async fn delete_dns(&self, id: String) -> AppResult<()> {
        pause(300).await;
        self.dns.send_modify(|d| {
            d.profiles.retain(|p| p.id != id || p.builtin);
            if d.active.as_deref() == Some(id.as_str()) {
                d.active = None;
            }
        });
        Ok(())
    }

    async fn select_dns(&self, id: Option<String>) -> AppResult<()> {
        pause(450).await;
        if self.failures && id.as_deref().is_some_and(|i| !i.starts_with("builtin-")) {
            return Err(demo_err(ErrorKind::Conflict, "errors.conflict"));
        }
        self.dns.send_modify(|d| d.active = id);
        Ok(())
    }

    async fn add_domain_rule(&self, pattern: String, action: DomainAction) -> AppResult<()> {
        pause(300).await;
        let pattern = demo_pattern(&pattern)?;
        let id = self.id("r");
        self.domains.send_modify(|d| {
            d.rules.push(DomainRuleView {
                id,
                pattern,
                action,
                hits: 0,
            })
        });
        Ok(())
    }

    async fn update_domain_rule(
        &self,
        id: String,
        pattern: String,
        action: DomainAction,
    ) -> AppResult<()> {
        pause(300).await;
        let pattern = demo_pattern(&pattern)?;
        self.domains.send_modify(|d| {
            if let Some(r) = d.rules.iter_mut().find(|r| r.id == id) {
                r.pattern = pattern;
                r.action = action;
            }
        });
        Ok(())
    }

    async fn delete_domain_rule(&self, id: String) -> AppResult<()> {
        pause(250).await;
        self.domains.send_modify(|d| d.rules.retain(|r| r.id != id));
        Ok(())
    }

    async fn reorder_domain_rules(&self, ids: Vec<String>) -> AppResult<()> {
        pause(250).await;
        self.domains.send_modify(|d| {
            let mut ordered = Vec::with_capacity(d.rules.len());
            for id in &ids {
                if let Some(pos) = d.rules.iter().position(|r| r.id == *id) {
                    ordered.push(d.rules.remove(pos));
                }
            }
            ordered.append(&mut d.rules);
            d.rules = ordered;
        });
        Ok(())
    }

    async fn pick_domain_list(&self) -> AppResult<Option<DomainImportPreview>> {
        pause(400).await;
        self.picked_domains.set(true);
        Ok(Some(DomainImportPreview {
            file_name: "ru-banks.txt".into(),
            new_rules: 3,
            duplicates: 1,
            invalid: 2,
            over_limit: 0,
        }))
    }

    async fn import_domain_list(&self, action: DomainAction) -> AppResult<DomainImportReport> {
        pause(500).await;
        if !self.picked_domains.replace(false) {
            return Err(AppError::new(ErrorKind::Conflict));
        }
        let names = ["bank.example.ru", "shop.example.ru", "gov.example.ru"];
        for name in names {
            let id = self.id("r");
            self.domains.send_modify(|d| {
                d.rules.push(DomainRuleView {
                    id,
                    pattern: name.into(),
                    action,
                    hits: 0,
                });
            });
        }
        Ok(DomainImportReport {
            added: names.len() as u32,
        })
    }

    async fn discard_domain_list(&self) {
        self.picked_domains.set(false);
    }

    async fn set_notification(&self, change: NotificationChange) -> AppResult<()> {
        pause(150).await;
        self.notifications.send_modify(|n| match change {
            NotificationChange::Enabled(on) => n.enabled = on,
            NotificationChange::Event(event, on) => n.events[event as usize] = on,
            NotificationChange::Method(method) => n.method = method,
            NotificationChange::Sound(on) => n.sound = on,
        });
        Ok(())
    }

    async fn check_os_notifications(&self) -> AppResult<()> {
        Ok(())
    }

    async fn reset_os_notification_block(&self) -> AppResult<ResetReport> {
        pause(500).await;
        self.notifications
            .send_modify(|n| n.os = OsNotifications::Allowed);
        Ok(ResetReport {
            cleared: 1,
            errors: Vec::new(),
        })
    }

    async fn open_windows_notification_settings(&self) -> AppResult<()> {
        Ok(())
    }

    async fn export_config(&self, mode: ExportMode) -> AppResult<()> {
        pause(700).await;
        tracing::info!(target: "ui", ?mode, "demo: config exported");
        Ok(())
    }

    async fn pick_config_import(&self) -> AppResult<Option<ImportPreview>> {
        pause(500).await;
        let preview = ImportPreview {
            file_name: "vpn-tunnel-enforcer-config-1762850000000.json".into(),
            sections: vec![
                ConfigSection::Profiles,
                ConfigSection::ServerGroups,
                ConfigSection::Dns,
                ConfigSection::DomainRouting,
                ConfigSection::KillSwitch,
                ConfigSection::Notifications,
                ConfigSection::AppSettings,
            ],
            conflicts: vec![
                ConfigSection::Dns,
                ConfigSection::DomainRouting,
                ConfigSection::KillSwitch,
            ],
            redacted: true,
            invalid_entries: 1,
        };
        *self.picked_config.borrow_mut() = Some(preview.clone());
        Ok(Some(preview))
    }

    async fn apply_config_import(
        &self,
        sections: Vec<ConfigSection>,
        mode: ImportMode,
    ) -> AppResult<()> {
        // single use: consumed even when the apply fails
        let picked = self.picked_config.borrow_mut().take();
        pause(900).await;
        if picked.is_none() {
            return Err(AppError::new(ErrorKind::Conflict));
        }
        if self.failures {
            return Err(AppError::new(ErrorKind::Permission));
        }
        tracing::info!(target: "ui", ?sections, ?mode, "demo: config applied");
        Ok(())
    }

    async fn discard_config_import(&self) {
        self.picked_config.borrow_mut().take();
    }
}

/// The demo's stand-in for the domain-pattern grammar (routing-dns B-DR-1/3): lower case, an
/// optional `*.`, a `~keyword`, or a name with a dot.
fn demo_pattern(raw: &str) -> AppResult<String> {
    let p = raw.trim().to_lowercase();
    let body = p.strip_prefix("*.").or(p.strip_prefix('~')).unwrap_or(&p);
    let valid = !body.is_empty()
        && !body.contains(char::is_whitespace)
        && (p.starts_with('~') || body.contains('.'));
    if valid {
        Ok(p)
    } else if !p.contains('.') {
        Err(AppError::validation(Msg::new("ui.settings.demo.dotless")))
    } else {
        Err(AppError::validation(Msg::new(
            "ui.settings.demo.badPattern",
        )))
    }
}
