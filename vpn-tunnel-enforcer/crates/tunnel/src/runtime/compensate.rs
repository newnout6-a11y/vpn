//! The one compensation of a failed start (tunnel-core §3.4) and the retained / idle states.
use vpnte_base::{AppError, Msg};

use super::actor::{Actor, Phase, Retained};
use super::start::Work;
use crate::api::{TunError, TunStatus, TunStatusKind};

impl Actor {
    /// The one compensation (§3.4): the core's exit is proven first (an unproven exit keeps
    /// everything, the protection included), then Xray stops, then the protection this start
    /// engaged is released. A protection handed over by a preserved stop stays (only a full
    /// stop releases it). Every failed step becomes a warning; no raw OS text.
    pub(super) async fn compensate(&mut self, mut work: Work, cause: AppError) -> TunError {
        let mut warnings = std::mem::take(&mut work.warnings);
        let held = work.prior.is_some();
        let plan = work.plan.take().or(work.prior.take());
        let holding = held || work.began;
        if let Some(core) = work.core.take() {
            match core.terminate(self.deps.timings.exit).await {
                Ok(info) => self.record_exit(&info),
                Err(e) => {
                    // A failed exit proof is no evidence the child is gone: keep its protection.
                    tracing::error!(error = %e, "sing-box exit not proven: protection retained");
                    let retained = Retained {
                        core: Some(core),
                        slots: work.slots.take(),
                        plan,
                    };
                    let key = "tunnel.runtime.cleanup.exitUnproven";
                    return self.retain(retained, cause, warnings, key);
                }
            }
        }
        if let Some(mut slots) = work.slots.take()
            && let Err(e) = slots.slots.stop_all().await
        {
            tracing::error!(error = %e, "Xray exit not proven: protection retained");
            let retained = Retained {
                core: None,
                slots: Some(slots),
                plan,
            };
            return self.retain(retained, cause, warnings, "tunnel.runtime.cleanup.xray");
        }
        match (held, plan) {
            (true, Some(plan)) => {
                self.phase = Phase::Adapting(plan);
                let status = self.idle_status();
                self.publish(|s| *s = status);
                self.announce(TunStatusKind::Adapting);
            }
            _ => {
                // A start that failed before its capture began released nothing: a release an
                // earlier failure left owed stays owed for the next stop (p-fix-review4).
                if holding {
                    let released = self.capture.release().await;
                    self.protection_dirty = released.is_err();
                    if let Err(e) = released {
                        tracing::error!(error = %e, "protection not released after a failed start");
                        warnings.push(Msg::new("tunnel.runtime.cleanup.protection"));
                    }
                }
                self.phase = Phase::Idle;
                let status = self.idle_status();
                self.publish(|s| *s = status);
                self.announce(TunStatusKind::Stopped);
            }
        }
        TunError {
            error: cause,
            warnings,
        }
    }

    /// Exit not proven: everything stays owned and blocking; the status says so.
    pub(super) fn retain(
        &mut self,
        retained: Retained,
        cause: AppError,
        mut warnings: Vec<Msg>,
        key: &'static str,
    ) -> TunError {
        let warning = Msg::new(key);
        warnings.push(warning.clone());
        self.phase = Phase::Faulted(Box::new(retained));
        let status = TunStatus {
            warning: Some(warning.clone()),
            ..self.idle_status()
        };
        self.publish(|s| *s = status);
        self.announce(TunStatusKind::Error { warning });
        TunError {
            error: cause,
            warnings,
        }
    }

    /// Nothing running; the crash-restart counter stays visible.
    pub(super) fn idle_status(&self) -> TunStatus {
        TunStatus {
            restart_attempt: self.attempt,
            ..TunStatus::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use tokio_util::sync::CancellationToken;
    use vpnte_base::types::EnginePref;

    use super::super::tests::{NATIVE_KEY, World, deps, vpn_req};
    use crate::api::{Runtime, StopOptions};
    use crate::runtime::TunnelHandle;

    /// A TUIC key: Xray has no client for it, so a start that asks for Xray is refused before
    /// any effect.
    const TUIC_KEY: &str = "tuic://00000000-0000-4000-8000-000000000005:fake-pass@203.0.113.15:443?sni=example.com&congestion_control=bbr#Fake%20T";

    /// p-fix-review4 (p-wire5): a start refused before its capture began released nothing, so
    /// the release an earlier failed start still owes stays owed and the next stop makes it.
    #[tokio::test]
    async fn a_start_failing_before_its_capture_keeps_an_owed_release() {
        let w = World::new();
        let h = TunnelHandle::spawn(deps(&w));
        w.ready_fail.store(true, Ordering::SeqCst);
        w.release_fail.store(true, Ordering::SeqCst);
        let first = vpn_req(NATIVE_KEY, EnginePref::Auto);
        h.start(first, CancellationToken::new())
            .await
            .expect_err("the capture never became ready");
        w.ready_fail.store(false, Ordering::SeqCst);
        w.release_fail.store(false, Ordering::SeqCst);
        let owed = w.count("release");
        let refused = vpn_req(TUIC_KEY, EnginePref::Xray);
        h.start(refused, CancellationToken::new())
            .await
            .expect_err("Xray cannot run TUIC");
        assert_eq!(w.count("release"), owed, "nothing was attempted");
        let receipt = h.stop(StopOptions::default()).await;
        assert_eq!(w.count("release"), owed + 1, "{:?}", w.log());
        assert_eq!(receipt.protection_released, Some(true));
    }
}
