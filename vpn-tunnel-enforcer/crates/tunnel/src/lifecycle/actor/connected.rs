//! The one hook every path that brings protection up goes through, and notices.
use super::*;

/// The one hook every path that brings protection up goes through (H-05).
impl Actor {
    pub(super) async fn on_connected(&mut self, job: &Job, up: Up, by: &Provenance) {
        let holder = match job {
            // A switch or restart continues the session for whoever held it.
            Job::Connect { .. } => by.owner,
            _ => self.session.as_ref().map_or(by.owner, |s| s.holder),
        };
        let ends_as = match job {
            Job::Switch { kind, .. } => *kind,
            _ => OutcomeKind::ServerSwitch,
        };
        match up {
            Up::Idle => return,
            Up::Run {
                profile,
                country,
                generation,
                engine,
                adaptive,
                ..
            } => {
                // An in-place switch keeps the engine run of the session it replaces.
                let run = self.session.as_ref().map(|s| (s.generation, s.engine));
                if self.session.as_ref().is_none_or(|s| s.profile != profile) {
                    let ending = Captured::now(&self.deps);
                    self.close_current(ends_as, None, ending).await;
                    self.deps
                        .forensics
                        .start_session(profile.mode, &profile.name);
                    let mut live = LiveSession::open(profile, Some(by), holder);
                    live.country = country;
                    (live.generation, live.engine) = run.unwrap_or_default();
                    self.session = Some(live);
                }
                if let Some(live) = self.session.as_mut() {
                    live.generation = generation.or(live.generation);
                    live.engine = engine.or(live.engine);
                    live.adaptive = adaptive;
                    live.proxy_down = false;
                }
            }
            Up::Restarted {
                generation,
                engine,
                adaptive,
                ..
            } => {
                let live = self.ensure_session(holder);
                live.generation = Some(generation);
                live.engine = Some(engine);
                live.adaptive = adaptive.unwrap_or(live.adaptive);
                live.proxy_down = false;
            }
        }
        let generation = self.session.as_ref().and_then(|s| s.generation);
        self.deps.monitor.start(generation);
        if matches!(job, Job::Connect { .. }) && generation.is_some() {
            self.notify(Level::Info, "connected", NoticeKind::VpnConnect, None);
        }
        self.announce_up();
    }

    /// The runtime brought a connected tunnel back by itself (crash auto-restart).
    pub(super) fn native_reconnected(&mut self, generation: u64) {
        let attempt = self.status.borrow().restart_attempt;
        let live = self.ensure_session(Owner::Recovery);
        live.generation = Some(generation);
        live.proxy_down = false;
        self.deps.monitor.start(Some(generation));
        let body = Msg::new(notice_key("restored", "body")).arg("attempt", attempt);
        self.notify(Level::Info, "restored", NoticeKind::VpnConnect, Some(body));
        self.announce_up();
    }

    pub(super) fn announce_up(&mut self) {
        self.push_session();
        if let Some(view) = self.session.as_ref().map(LiveSession::view) {
            let _ = self.events.send(SessionEvent::Up(view));
        }
    }

    /// The live session, rebuilt from the runtime status when none is open (old
    /// `ensureSessionForRunningTunnel`): provenance "runtime", ids never the display name.
    pub(super) fn ensure_session(&mut self, holder: Owner) -> &mut LiveSession {
        let status = self.status.borrow().clone();
        let profiles = &self.deps.profiles;
        self.session.get_or_insert_with(|| {
            let profile = match status.mode {
                Some(ModeKind::DirectVpn) => {
                    let active = profiles.resolve(None).map(|c| c.server);
                    match (active, status.profile_name.as_deref()) {
                        (Some(server), Some(name)) if server.profile.name == name => {
                            SessionProfile::direct(&server)
                        }
                        (_, Some(name)) if !name.trim().is_empty() => SessionProfile {
                            name: name.trim().to_owned(),
                            ..SessionProfile::direct_unknown()
                        },
                        _ => SessionProfile::direct_unknown(),
                    }
                }
                _ => match status.proxy_addr.as_deref() {
                    Some(addr) => SessionProfile::local_proxy(addr),
                    None => SessionProfile {
                        name: "Local Proxy".into(),
                        ..SessionProfile::local_proxy("")
                    },
                },
            };
            LiveSession::open(profile, None, holder)
        })
    }

    pub(super) fn notify(
        &self,
        level: Level,
        name: &'static str,
        kind: NoticeKind,
        body: Option<Msg>,
    ) {
        let body = body.unwrap_or_else(|| Msg::new(notice_key(name, "body")));
        let notice = Notice::new(level, Msg::new(notice_key(name, "title"))).body(body);
        self.deps.notifier.notify(notice, kind);
    }
}

pub(super) fn notice_key(name: &str, part: &str) -> String {
    format!("{}.{name}.{part}", key::NOTICE)
}
