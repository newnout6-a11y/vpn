//! The lease book (spec 3.3–3.5): which automation client holds which slot until when, plus the
//! owner memory that hands a client its previous route back. Pure: the caller passes `now` and
//! the current statuses (readiness derived at `now`) and owns the expiry timer
//! ([`LeaseBook::next_expiry`]). Leases are never persisted: they guard live children of this
//! process, and a restored lease would block a slot while protecting nothing.
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::IpAddr;

use vpnte_base::types::UnixMs;

use crate::model::{InstanceStatus, ProxyError, Released, Reservation, ReserveRequest};
use crate::slot::Slot;

/// Lease length when the client names none.
pub const DEFAULT_TTL_SECS: u32 = 120;
/// Longest lease a client may ask for.
pub const MAX_TTL_SECS: u32 = 3600;
/// Owners remembered for sticky routes; the oldest is forgotten first.
const OWNER_MEMORY: usize = 1024;

/// One active lease.
#[derive(Clone, PartialEq, Eq)]
pub struct Lease {
    pub slot: Slot,
    token: String,
    pub owner: String,
    pub expires_at: UnixMs,
}

impl fmt::Debug for Lease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lease")
            .field("slot", &self.slot)
            .field("owner", &self.owner)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// An operation a live lease blocks (each has its own wire message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guarded {
    Stop,
    /// `start` of a configured slot whose engine is not running.
    Restart,
    /// Any start, rotate or connect that would replace the slot's route.
    ChangeRoute,
}

/// Where an owner's last lease exited.
#[derive(Debug, Clone, Copy)]
struct Sticky {
    slot: Slot,
    egress_ip: IpAddr,
    generation: u64,
    seq: u64,
}

/// Active leases by slot (at most one per slot and one per owner) and the owners' last routes.
#[derive(Debug, Default)]
pub struct LeaseBook {
    leases: BTreeMap<Slot, Lease>,
    owners: HashMap<String, Sticky>,
    seq: u64,
}

impl LeaseBook {
    /// Drops the leases that expired by `now` and returns their slots.
    pub fn sweep(&mut self, now: UnixMs) -> Vec<Slot> {
        let expired: Vec<Slot> = self
            .leases
            .values()
            .filter(|l| l.expires_at <= now)
            .map(|l| l.slot)
            .collect();
        for slot in &expired {
            if let Some(lease) = self.leases.remove(slot) {
                tracing::info!(slot = %slot, owner = %lease.owner, "expired proxy lease released");
            }
        }
        expired
    }

    /// The live lease of `slot`.
    pub fn lease(&self, slot: Slot, now: UnixMs) -> Option<&Lease> {
        self.leases.get(&slot).filter(|l| l.expires_at > now)
    }

    /// Live leases, in slot order.
    pub fn active(&self, now: UnixMs) -> impl Iterator<Item = &Lease> {
        self.leases.values().filter(move |l| l.expires_at > now)
    }

    /// When the caller's timer should sweep next.
    pub fn next_expiry(&self) -> Option<UnixMs> {
        self.leases.values().map(|l| l.expires_at).min()
    }

    /// 409 when a live lease on `slot` forbids `op`.
    pub fn guard(&self, slot: Slot, op: Guarded, now: UnixMs) -> Result<(), ProxyError> {
        if self.lease(slot, now).is_none() {
            return Ok(());
        }
        let what = match op {
            Guarded::Stop => "stop",
            Guarded::Restart => "restart",
            Guarded::ChangeRoute => "change route",
        };
        Err(ProxyError::Conflict(format!(
            "Slot {slot} cannot {what} while a Buyer Search lease is active"
        )))
    }

    /// Forgets `slot` after it stopped: its lease and every owner memory pointing at it.
    pub fn forget_slot(&mut self, slot: Slot) -> Option<Lease> {
        self.owners.retain(|_, sticky| sticky.slot != slot);
        self.leases.remove(&slot)
    }

    /// Drops every lease and owner memory (app exit).
    pub fn clear(&mut self) {
        self.leases.clear();
        self.owners.clear();
    }

    /// Leases a ready route. `routes` are the current statuses with readiness derived at `now`.
    /// Selection order (old API, kept for its clients): the strict `slot` (a leased one is
    /// always 409; a not-ready one is 409 only without fallback), the owner's previous route if
    /// it still has the same generation and egress IP, the preferred egress IP, the preferred
    /// slot, then (with fallback) the first ready slot. Steps 2 and 3 run even without fallback.
    pub fn reserve(
        &mut self,
        req: &ReserveRequest,
        routes: &[InstanceStatus],
        now: UnixMs,
    ) -> Result<Reservation, ProxyError> {
        let owner = req.owner.trim();
        if owner.is_empty() {
            return Err(ProxyError::BadRequest("owner is required".into()));
        }
        let ttl = ttl_secs(req.ttl_secs)?;
        self.sweep(now);
        if let Some(held) = self.leases.values().find(|l| l.owner == owner) {
            return Err(ProxyError::Conflict(format!(
                "Owner already has an active lease for slot {}",
                held.slot
            )));
        }
        let mut sorted: Vec<&InstanceStatus> = routes.iter().collect();
        sorted.sort_by_key(|r| r.slot);
        let route = |slot: Slot| sorted.iter().copied().find(|r| r.slot == slot);
        let free = |r: &&InstanceStatus| r.ready && !self.leases.contains_key(&r.slot);

        let mut chosen = None;
        if let Some(slot) = req.slot {
            if self.leases.contains_key(&slot) {
                return Err(already_leased(slot));
            }
            chosen = route(slot).filter(|r| r.ready);
            if chosen.is_none() && !req.allow_fallback {
                return Err(ProxyError::Conflict(format!(
                    "Slot {slot} is not a healthy ready route"
                )));
            }
        }
        if chosen.is_none()
            && let Some(sticky) = self.owners.get(owner)
        {
            chosen = route(sticky.slot)
                .filter(|r| r.generation == sticky.generation)
                .filter(|r| r.egress_ip == Some(sticky.egress_ip))
                .filter(free);
        }
        if chosen.is_none()
            && let Some(ip) = req.preferred_egress_ip
        {
            chosen = sorted
                .iter()
                .copied()
                .filter(|r| r.egress_ip == Some(ip))
                .find(free);
        }
        if chosen.is_none()
            && let Some(slot) = req.preferred_slot
        {
            if self.leases.contains_key(&slot) && !req.allow_fallback {
                return Err(already_leased(slot));
            }
            chosen = route(slot).filter(free);
        }
        if chosen.is_none() && req.allow_fallback {
            chosen = sorted.iter().copied().find(free);
        }
        let Some(route) = chosen else {
            return Err(ProxyError::Unavailable(
                "No free healthy route with a fresh unique egress IP is available".into(),
            ));
        };

        let lease = Lease {
            slot: route.slot,
            token: new_token()?,
            owner: owner.to_owned(),
            expires_at: now + i64::from(ttl) * 1000,
        };
        self.remember(owner, route);
        tracing::info!(slot = %route.slot, owner, egress_ip = ?route.egress_ip,
            generation = route.generation, "proxy route reserved");
        let reservation = reservation(&lease, route);
        self.leases.insert(lease.slot, lease);
        Ok(reservation)
    }

    /// Extends a lease to `now + ttl` (`None` = the default TTL, not the previous one). A lease
    /// whose route has no running engine is dropped with a 409 so the client reserves anew
    /// instead of keeping a dead route blocked (B-31).
    pub fn renew(
        &mut self,
        token: &str,
        ttl: Option<f64>,
        routes: &[InstanceStatus],
        now: UnixMs,
    ) -> Result<Reservation, ProxyError> {
        let slot = self.find(token, now)?;
        let ttl = ttl_secs(ttl)?;
        let Some(route) = routes.iter().find(|r| r.slot == slot && r.process_running) else {
            if let Some(lease) = self.leases.remove(&slot) {
                tracing::info!(slot = %slot, owner = %lease.owner, "proxy lease dropped: route is down");
            }
            return Err(ProxyError::Conflict("Leased route is down".into()));
        };
        let lease = self.leases.get_mut(&slot).ok_or_else(unknown_token)?;
        lease.expires_at = now + i64::from(ttl) * 1000;
        Ok(reservation(lease, route))
    }

    /// Ends a lease.
    pub fn release(&mut self, token: &str, now: UnixMs) -> Result<Released, ProxyError> {
        let slot = self.find(token, now)?;
        if let Some(lease) = self.leases.remove(&slot) {
            tracing::info!(slot = %slot, owner = %lease.owner, "proxy route released");
        }
        Ok(Released {
            released: true,
            slot,
        })
    }

    /// Slot of the live lease holding `token`; tokens are compared in constant time.
    fn find(&mut self, token: &str, now: UnixMs) -> Result<Slot, ProxyError> {
        self.sweep(now);
        let token = token.trim();
        self.leases
            .values()
            .find(|l| crate::token::matches(&l.token, token))
            .map(|l| l.slot)
            .ok_or_else(unknown_token)
    }

    fn remember(&mut self, owner: &str, route: &InstanceStatus) {
        let Some(egress_ip) = route.egress_ip else {
            return;
        };
        if !self.owners.contains_key(owner) && self.owners.len() >= OWNER_MEMORY {
            let oldest = self
                .owners
                .iter()
                .min_by_key(|(_, s)| s.seq)
                .map(|(o, _)| o.clone());
            if let Some(oldest) = oldest {
                self.owners.remove(&oldest);
            }
        }
        self.seq += 1;
        let sticky = Sticky {
            slot: route.slot,
            egress_ip,
            generation: route.generation,
            seq: self.seq,
        };
        self.owners.insert(owner.to_owned(), sticky);
    }
}

/// Validates a lease length as the client sent it: 1..=3600 s, fractions floored.
pub fn ttl_secs(raw: Option<f64>) -> Result<u32, ProxyError> {
    match raw {
        None => Ok(DEFAULT_TTL_SECS),
        Some(v) if v.is_finite() && (1.0..=f64::from(MAX_TTL_SECS)).contains(&v) => {
            Ok(v.floor() as u32)
        }
        Some(_) => Err(ProxyError::BadRequest(format!(
            "ttlSeconds must be between 1 and {MAX_TTL_SECS}"
        ))),
    }
}

fn reservation(lease: &Lease, route: &InstanceStatus) -> Reservation {
    Reservation {
        lease_token: lease.token.clone(),
        owner: lease.owner.clone(),
        expires_at: lease.expires_at,
        slot: route.slot,
        proxy_url: route.proxy_url.clone(),
        egress_ip: route.egress_ip,
        generation: route.generation,
        instance: route.clone(),
    }
}

fn already_leased(slot: Slot) -> ProxyError {
    ProxyError::Conflict(format!("Slot {slot} is already leased"))
}

fn unknown_token() -> ProxyError {
    ProxyError::Forbidden("Unknown or expired lease token".into())
}

fn new_token() -> Result<String, ProxyError> {
    crate::token::generate()
        .map_err(|e| ProxyError::Engine(format!("cannot generate a lease token: {e}")))
}

#[cfg(test)]
mod tests;
