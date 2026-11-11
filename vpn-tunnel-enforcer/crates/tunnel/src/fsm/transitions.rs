//! Transitions of the state machine. Each takes the evidence read right before the call.
use super::*;

impl Fsm {
    /// A lane operation (connect / disconnect / rotation) started or ended.
    ///
    /// Only a disconnect may pre-empt a running operation. A terminal record must match the
    /// running one; success counts only on evidence, a failure keeps the previous protection
    /// only when [`Fsm::keep_previous`] accepted it, otherwise the state becomes `Error`
    /// (`Blocked` / `Unknown` stay).
    pub fn op_changed(&mut self, op: &OpMeta, e: Option<Evidence>) -> Result<(), Invalid> {
        let transition = match op.kind {
            OpKind::Connect => Transition::Connecting,
            OpKind::Disconnect => Transition::Disconnecting,
            OpKind::Rotation => Transition::Reconnecting,
            _ => return Err(Invalid),
        };
        if op.status == OpStatus::Running {
            if self.running_op().is_some() && op.kind != OpKind::Disconnect {
                return Err(Invalid);
            }
            if op.kind == OpKind::Rotation && !self.can_rotate() {
                return Err(Invalid);
            }
            self.upstream = None;
            self.rotation = (op.kind == OpKind::Rotation).then_some(Rotation {
                mode: self.snap.mode,
                evidence: e,
            });
            self.kept = None;
            self.fault = false;
            self.reconnect_eligible = false;
            self.expected_native_gen = None;
            self.commit(e, |s| {
                s.operation = Some(op.clone());
                s.cleanup_required = true;
                s.transition = Some(transition);
            });
            return Ok(());
        }
        if self.running_op().map(|cur| cur.id) != Some(op.id) {
            return Err(Invalid);
        }
        let kept = self.kept == Some(op.id);
        let rotation_end = if self.rotation.and_then(|r| r.mode).is_none() {
            TunnelState::Disconnected
        } else {
            TunnelState::Connected
        };
        let state = if op.status == OpStatus::Success {
            match op.kind {
                OpKind::Rotation if self.can_confirm_rotation(e) => rotation_end,
                OpKind::Connect if self.can_confirm_start(e) => TunnelState::Connected,
                OpKind::Disconnect if self.can_confirm_stop(e) => TunnelState::Disconnected,
                _ => TunnelState::Unknown,
            }
        } else if op.kind == OpKind::Rotation && kept && self.can_retain_rotation(e) {
            rotation_end
        } else if matches!(self.snap.state, TunnelState::Blocked | TunnelState::Unknown) {
            self.snap.state
        } else {
            TunnelState::Error
        };
        self.kept = None;
        let running = e.is_some_and(|e| e.running);
        let mode = e.map_or(TunnelMode::Tun, |e| e.mode());
        self.commit(e, |s| {
            s.operation = Some(op.clone());
            s.transition = None;
            s.state = state;
            s.mode = (state == TunnelState::Connected).then_some(mode);
            s.cleanup_required = state != TunnelState::Disconnected;
            s.proxy_status = if running {
                ProxyStatus::Running
            } else {
                ProxyStatus::Stopped
            };
        });
        Ok(())
    }

    /// Forces a fault state. Always accepted; a running operation keeps its transition.
    pub fn fault(&mut self, state: FaultState, e: Option<Evidence>) {
        self.upstream = None;
        self.kept = None;
        self.fault = true;
        self.reconnect_eligible = false;
        self.expected_native_gen = None;
        let keep_transition = self.running_op().is_some();
        self.commit(e, |s| {
            s.state = state.into();
            s.mode = None;
            s.cleanup_required = true;
            if !keep_transition {
                s.transition = None;
            }
        });
    }

    /// The running rotation's effect failed but read back the previous protection unchanged.
    /// Accepted only while that operation runs and the evidence still proves the old state.
    pub fn keep_previous(&mut self, op: OpId, e: Option<Evidence>) -> Result<(), Invalid> {
        let Some(cur) = self.running_op().filter(|cur| cur.id == op) else {
            return Err(Invalid);
        };
        let allowed = cur.kind == OpKind::Rotation && self.can_retain_rotation(e);
        if !allowed {
            return Err(Invalid);
        }
        self.kept = Some(op);
        Ok(())
    }

    /// A runtime status change. Never confirms a connection by itself: `Running` only refreshes
    /// the upstream status, `Stopped` outside an operation means "unknown" (a process exit is no
    /// rollback receipt), `Adapting` / `Restarting` outside an operation hand the tunnel to
    /// native recovery. `Stopping` (and `Stopped` / `Adapting` / `Restarting` during an
    /// operation, `PostTrialFailover`) are rejected, after fencing a pending upstream switch.
    pub fn runtime(&mut self, status: &TunStatusKind, e: Option<Evidence>) -> Result<(), Invalid> {
        let active = self.running_op().is_some();
        if matches!(status, TunStatusKind::Stopping | TunStatusKind::Stopped) {
            self.upstream = None;
        }
        let running = e.is_some_and(|e| e.running);
        match status {
            TunStatusKind::Error { .. } => self.fault(FaultState::Error, e),
            TunStatusKind::KillSwitchActive => self.fault(FaultState::Blocked, e),
            TunStatusKind::Adapting | TunStatusKind::Restarting { .. } if !active => {
                // Native recovery owns the tunnel now; its reconnect must outlive a late
                // receipt of the older upstream switch.
                self.upstream = None;
                if self.snap.transition != Some(Transition::Reconnecting) {
                    self.expected_native_gen = None;
                }
                self.reconnect_eligible |= self.snap.state == TunnelState::Connected;
                self.commit(e, |s| {
                    s.transition = Some(Transition::Reconnecting);
                    if !running {
                        s.proxy_status = ProxyStatus::Stopped;
                    }
                });
            }
            TunStatusKind::Stopped if !active => {
                self.reconnect_eligible = false;
                self.expected_native_gen = None;
                self.commit(e, |s| {
                    s.state = TunnelState::Unknown;
                    s.transition = None;
                    s.mode = None;
                    s.proxy_status = ProxyStatus::Stopped;
                    s.cleanup_required = true;
                });
            }
            TunStatusKind::CompetingTun { name } => {
                self.commit(e, |s| s.competing_tun = Some(name.clone()))
            }
            TunStatusKind::CompetingTunCleared => self.commit(e, |s| s.competing_tun = None),
            TunStatusKind::ProxyDown { .. } => {
                self.commit(e, |s| s.proxy_status = ProxyStatus::ProxyDown)
            }
            TunStatusKind::Running => self.commit(e, |s| {
                s.proxy_status = if running {
                    ProxyStatus::Running
                } else {
                    ProxyStatus::Stopped
                };
            }),
            _ => return Err(Invalid),
        }
        Ok(())
    }

    /// The runtime began native start `generation` (strictly increasing). Bookkeeping only: no
    /// revision bump. Outside an operation, during a native reconnect, it becomes the generation
    /// whose finish may confirm the tunnel.
    pub fn native_start_began(&mut self, generation: u64) -> Result<(), Invalid> {
        if generation <= self.native_gen {
            return Err(Invalid);
        }
        self.upstream = None;
        self.native_gen = generation;
        self.expected_native_gen = (self.running_op().is_none()
            && self.snap.transition == Some(Transition::Reconnecting))
        .then_some(generation);
        Ok(())
    }

    /// Native start `generation` finished outside the lane (auto-restart). Confirms "connected"
    /// only for the expected generation of a tunnel that was connected before, on evidence.
    pub fn native_start_finished(
        &mut self,
        generation: u64,
        ok: bool,
        e: Option<Evidence>,
    ) -> Result<(), Invalid> {
        if self.running_op().is_some()
            || self.snap.transition != Some(Transition::Reconnecting)
            || self.expected_native_gen != Some(generation)
        {
            return Err(Invalid);
        }
        self.expected_native_gen = None;
        let confirmed = ok && self.reconnect_eligible && self.can_confirm_start(e);
        self.reconnect_eligible = false;
        self.commit(e, |s| {
            s.state = if confirmed {
                TunnelState::Connected
            } else if ok {
                TunnelState::Unknown
            } else {
                TunnelState::Error
            };
            s.transition = None;
            s.mode = e.filter(|_| confirmed).map(|e| e.mode());
            s.proxy_status = if confirmed {
                ProxyStatus::Running
            } else {
                ProxyStatus::Stopped
            };
        });
        Ok(())
    }

    /// An in-place upstream switch `generation` (strictly increasing, independent of native
    /// generations) began on an idle, connected, proven engine run (Hard or Soft).
    pub fn upstream_began(&mut self, generation: u64, e: Option<Evidence>) -> Result<(), Invalid> {
        let Some(evidence) = e.filter(Evidence::native_ready) else {
            return Err(Invalid);
        };
        if generation <= self.upstream_gen
            || self.upstream.is_some()
            || self.running_op().is_some()
            || self.snap.transition.is_some()
            || self.snap.state != TunnelState::Connected
            || self.snap.mode != Some(evidence.mode())
        {
            return Err(Invalid);
        }
        self.upstream_gen = generation;
        self.upstream = Some((generation, evidence));
        self.commit(e, |s| {
            s.transition = Some(Transition::Reconnecting);
            s.cleanup_required = true;
        });
        Ok(())
    }

    /// The pending upstream switch finished. Confirms only if it was verified and the very same
    /// engine run survived it with the same proofs (the Soft tweaks included).
    pub fn upstream_finished(
        &mut self,
        generation: u64,
        verified: bool,
        e: Option<Evidence>,
    ) -> Result<(), Invalid> {
        let Some((pending_gen, before)) = self.upstream else {
            return Err(Invalid);
        };
        if pending_gen != generation
            || self.running_op().is_some()
            || self.snap.transition != Some(Transition::Reconnecting)
        {
            return Err(Invalid);
        }
        self.upstream = None;
        let retained = e == Some(before);
        let confirmed = verified && retained && !self.fault;
        self.commit(e, |s| {
            s.state = if confirmed {
                TunnelState::Connected
            } else {
                TunnelState::Unknown
            };
            s.transition = None;
            s.mode = confirmed.then_some(before.mode());
            s.proxy_status = if confirmed {
                ProxyStatus::Running
            } else {
                ProxyStatus::ProxyDown
            };
            s.cleanup_required = true;
        });
        Ok(())
    }

    /// The runtime finished a stop outside the lane. The only way from a fault back to
    /// "disconnected" without the user: a full stop of the current generation whose receipt
    /// confirms every rollback step, with no operation running and nothing of ours left.
    pub fn native_stop_finished(
        &mut self,
        generation: u64,
        preserved: bool,
        receipt: &StopReceipt,
        e: Option<Evidence>,
    ) -> Result<(), Invalid> {
        if generation != self.native_gen
            || preserved
            || self.running_op().is_some()
            || !self.can_confirm_stop(e)
            || !receipt.confirms_cleanup()
        {
            return Err(Invalid);
        }
        self.reconnect_eligible = false;
        self.expected_native_gen = None;
        self.fault = false;
        self.commit(e, |s| {
            s.state = TunnelState::Disconnected;
            s.transition = None;
            s.mode = None;
            s.proxy_status = ProxyStatus::Stopped;
            s.cleanup_required = false;
        });
        Ok(())
    }
}
