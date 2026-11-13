//! An engine switch reaches the tunnel without an app restart (p-follow): the store's active
//! engines go to the tunnel, whose next engine start runs them, and a session of this app that
//! runs the old engine is offered the switch now (a 1–3 s reconnect) or at its next connection.
//! An elevated process holding the WFP filters keeps the start's engines (its permits name those
//! paths): there the switch still waits for the app's restart. Tunnel mode through the helper
//! service runs the service's own pinned engines, whatever the app installed.
use vpnte_base::types::Engine;
use vpnte_base::{AppResult, Msg};
use vpnte_tunnel::api::{CaptureKind, TunStatus};
use vpnte_ui::updates::Note;
use vpnte_update::policy::{self, XRAY};
use vpnte_update::store::Origin;

use super::Updates;
use super::actions::engine_name;

/// How an engine switch reaches the sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Reach {
    /// This process keeps the start's engines: after the app's restart.
    AppRestart,
    /// The next connection in Proxy mode.
    NextConnect,
    /// A session of this app runs the old engine: now or at its next connection.
    Running,
}

impl Updates {
    /// Hands the store's active engines to the tunnel; `false`: this process keeps the start's.
    pub(super) fn apply_engines(&self) -> bool {
        let Ok(tunnel) = self.backend.tunnel() else {
            return false;
        };
        tunnel.set_engines(crate::svc_core::resolve_engines(&self.store))
    }

    /// Engine `id` switched (installed or rolled back by hand): one line on where that reaches;
    /// `restart` is the line for a process that keeps its engines until it restarts.
    pub(super) fn engine_switched(&self, id: &str, restart: Msg) {
        let reach = if !self.apply_engines() {
            Reach::AppRestart
        } else if (self.backend.tunnel()).is_ok_and(|t| runs(&t.runtime_status().borrow(), id)) {
            Reach::Running
        } else {
            Reach::NextConnect
        };
        let note = note(reach, id, &self.active_version(id), restart);
        self.inner.lock().note = Some(note);
        self.refresh();
    }

    /// The version engine `id` runs from its next start on.
    pub(super) fn active_version(&self, id: &str) -> String {
        match self.store.resolve(id).origin {
            Origin::Downloaded { version, .. } => version.to_string(),
            Origin::Bundled => policy::bundled_version(id)
                .map(|v| v.to_string())
                .unwrap_or_default(),
        }
    }

    /// «Сейчас»: the running session reconnects on the new engine.
    pub(super) async fn switch_now(&self) -> AppResult<()> {
        self.inner.lock().note = None;
        self.refresh();
        let tunnel = self.backend.tunnel()?.clone();
        tunnel.reconnect("engine switched".into()).await?;
        Ok(())
    }
}

/// A session of this app (proxy capture) runs engine `id`: sing-box is the core of every one,
/// Xray only of a session whose engine is Xray.
pub(super) fn runs(status: &TunStatus, id: &str) -> bool {
    status.running
        && status.capture == Some(CaptureKind::Proxy)
        && (id != XRAY || status.engine.is_some_and(|e| e.kind == Engine::Xray))
}

/// The line for an engine switch that reaches as far as `reach`.
pub(super) fn note(reach: Reach, id: &str, version: &str, restart: Msg) -> Note {
    let line = |key: &'static str| {
        Msg::new(key)
            .arg("name", engine_name(id))
            .arg("version", version)
    };
    let (msg, switch_now) = match reach {
        Reach::AppRestart => (restart, false),
        Reach::NextConnect => (line("app.update.engineNext"), false),
        Reach::Running => (line("app.update.engineRunning"), true),
    };
    Note {
        msg,
        warn: false,
        switch_now,
    }
}

#[cfg(test)]
mod tests {
    use vpnte_tunnel::api::EngineRun;
    use vpnte_update::policy::SINGBOX;

    use super::*;

    fn proxy_session(engine: Engine) -> TunStatus {
        TunStatus {
            running: true,
            capture: Some(CaptureKind::Proxy),
            engine: Some(EngineRun {
                kind: engine,
                reason: None,
            }),
            ..TunStatus::default()
        }
    }

    /// p-follow: sing-box is the core of every Proxy-mode session of this app, Xray only of one
    /// whose engine is Xray; a Tunnel-mode session (the helper service's engines) and an idle
    /// tunnel run none of the app's.
    #[test]
    fn a_running_session_runs_the_engines_it_starts() {
        let native = proxy_session(Engine::SingBox);
        assert!(runs(&native, SINGBOX) && !runs(&native, XRAY));
        let xray = proxy_session(Engine::Xray);
        assert!(runs(&xray, SINGBOX) && runs(&xray, XRAY));
        let tunnel = TunStatus {
            capture: Some(CaptureKind::Tun),
            ..proxy_session(Engine::Xray)
        };
        assert!(!runs(&tunnel, SINGBOX) && !runs(&tunnel, XRAY));
        assert!(!runs(&TunStatus::default(), SINGBOX));
    }

    /// p-follow (p-updates follow-up): an engine switch says how far it reaches: a session that
    /// runs the old engine is offered «Сейчас» / «При следующем подключении», an idle tunnel
    /// takes it at the next Proxy-mode connection, a process that keeps its engines says so.
    #[test]
    fn an_engine_switch_says_where_it_reaches() {
        let restart = || Msg::new("app.update.engineInstalled");
        let running = note(Reach::Running, SINGBOX, "1.14.5", restart());
        assert!(running.switch_now && !running.warn);
        assert_eq!(running.msg.key, "app.update.engineRunning");
        assert_eq!(running.msg.args[1].1, "1.14.5");
        let next = note(Reach::NextConnect, XRAY, "26.11.10", restart());
        assert!(!next.switch_now);
        assert_eq!(next.msg.key, "app.update.engineNext");
        let kept = note(Reach::AppRestart, SINGBOX, "1.14.5", restart());
        assert!(!kept.switch_now);
        assert_eq!(kept.msg, restart());
    }
}
