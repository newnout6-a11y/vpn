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
        let token = token.trim().as_bytes();
        self.leases
            .values()
            .find(|l| constant_time_eq(l.token.as_bytes(), token))
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

/// 32 random bytes as 64 lower-case hex chars.
fn new_token() -> Result<String, ProxyError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| ProxyError::Engine(format!("cannot generate a lease token: {e}")))?;
    Ok(hex::encode(bytes))
}

/// Equal-length byte strings compared without an early exit (the length is public: 64).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && std::hint::black_box(a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y))) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{derive_readiness, healthy_instance};

    const NOW: UnixMs = 1_762_800_000_000;

    fn routes(ips: &[&str]) -> Vec<InstanceStatus> {
        let mut list: Vec<_> = ips
            .iter()
            .zip(1..)
            .map(|(ip, n)| healthy_instance(n, ip, NOW))
            .collect();
        derive_readiness(&mut list, NOW);
        list
    }

    fn ask(owner: &str) -> ReserveRequest {
        ReserveRequest {
            ttl_secs: Some(120.0),
            ..ReserveRequest::new(owner)
        }
    }

    fn slot(n: u64) -> Slot {
        Slot::new(n).unwrap()
    }

    /// Spec external-proxy §7.8: a client falls back from an occupied egress IP, tokens are
    /// enforced, renew keeps the token and a returning owner gets its route back.
    #[test]
    fn falls_back_from_an_occupied_ip_and_enforces_tokens() {
        let routes = routes(&["198.51.100.1", "198.51.100.2", "198.51.100.3"]);
        let mut book = LeaseBook::default();
        let first = book
            .reserve(
                &ReserveRequest {
                    preferred_egress_ip: Some("198.51.100.2".parse().unwrap()),
                    ..ask("buyer-worker-1")
                },
                &routes,
                NOW,
            )
            .unwrap();
        assert_eq!(
            first.instance.egress_ip,
            Some("198.51.100.2".parse().unwrap())
        );
        assert_eq!((first.slot, first.lease_token.len()), (slot(2), 64));
        assert!(
            first
                .lease_token
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_eq!(first.expires_at, NOW + 120_000);
        let err = book.guard(slot(2), Guarded::ChangeRoute, NOW).unwrap_err();
        assert_eq!(err.http_status(), 409);
        assert_eq!(
            err.detail(),
            "Slot 2 cannot change route while a Buyer Search lease is active"
        );

        let second = book
            .reserve(
                &ReserveRequest {
                    preferred_egress_ip: first.egress_ip,
                    preferred_slot: Some(slot(2)),
                    ..ask("buyer-worker-2")
                },
                &routes,
                NOW,
            )
            .unwrap();
        assert_ne!(second.slot, first.slot);
        assert_ne!(second.egress_ip, first.egress_ip);

        let strict = ReserveRequest {
            slot: Some(slot(2)),
            allow_fallback: false,
            ..ask("buyer-worker-3")
        };
        let err = book.reserve(&strict, &routes, NOW).unwrap_err();
        assert_eq!(
            (err.http_status(), err.detail()),
            (409, "Slot 2 is already leased")
        );

        let err = book.release("wrong-token", NOW).unwrap_err();
        assert_eq!(
            (err.http_status(), err.detail()),
            (403, "Unknown or expired lease token")
        );
        let renewed = book
            .renew(&first.lease_token, Some(120.0), &routes, NOW + 5)
            .unwrap();
        assert_eq!(renewed.lease_token, first.lease_token);
        assert_eq!(renewed.expires_at, NOW + 5 + 120_000);

        let released = book
            .release(&format!(" {} ", first.lease_token), NOW)
            .unwrap();
        assert_eq!(
            released,
            Released {
                released: true,
                slot: slot(2)
            }
        );
        book.release(&second.lease_token, NOW).unwrap();
        // Slot 1 is free and first in order, yet the owner's previous route wins.
        let again = book.reserve(&ask("buyer-worker-1"), &routes, NOW).unwrap();
        assert_eq!(
            (again.slot, again.generation),
            (first.slot, first.generation)
        );
    }

    /// Spec external-proxy §3.4: owner memory only counts while the slot keeps its generation
    /// and egress IP; an owner holds one lease at a time.
    #[test]
    fn owner_memory_needs_the_same_route() {
        let mut routes = routes(&["198.51.100.1", "198.51.100.2"]);
        let mut book = LeaseBook::default();
        let pick_two = ReserveRequest {
            slot: Some(slot(2)),
            ..ask("o")
        };
        let first = book.reserve(&pick_two, &routes, NOW).unwrap();
        let err = book.reserve(&ask("o"), &routes, NOW).unwrap_err();
        assert_eq!(err.detail(), "Owner already has an active lease for slot 2");
        book.release(&first.lease_token, NOW).unwrap();
        routes[1].generation += 1; // rotated since
        assert_eq!(book.reserve(&ask("o"), &routes, NOW).unwrap().slot, slot(1));
    }

    /// Spec external-proxy §7.8: an expired lease is freed before the next reservation.
    #[test]
    fn expired_lease_is_freed_before_the_next_reservation() {
        let routes = routes(&["198.51.100.50"]);
        let mut book = LeaseBook::default();
        let strict = |owner: &str, ttl| ReserveRequest {
            slot: Some(slot(1)),
            ttl_secs: Some(ttl),
            allow_fallback: false,
            ..ReserveRequest::new(owner)
        };
        book.reserve(&strict("expiry-owner", 1.0), &routes, NOW)
            .unwrap();
        assert_eq!(book.next_expiry(), Some(NOW + 1000));
        assert!(book.guard(slot(1), Guarded::Stop, NOW).is_err());
        assert!(book.guard(slot(1), Guarded::Stop, NOW + 1000).is_ok());
        let next = book
            .reserve(&strict("next-owner", 120.0), &routes, NOW + 1001)
            .unwrap();
        assert_eq!(next.slot, slot(1));
        assert_eq!(book.active(NOW + 1001).count(), 1);
    }

    /// Spec external-proxy §3.3–3.5: input validation and the "nothing ready" answer.
    #[test]
    fn validates_owner_and_ttl() {
        let routes = routes(&["198.51.100.1"]);
        let mut book = LeaseBook::default();
        let err = book.reserve(&ask("   "), &routes, NOW).unwrap_err();
        assert_eq!(
            (err.http_status(), err.detail()),
            (400, "owner is required")
        );
        for bad in [0.0, 0.5, 3600.5, -1.0, f64::NAN, f64::INFINITY] {
            let req = ReserveRequest {
                ttl_secs: Some(bad),
                ..ask("o")
            };
            let err = book.reserve(&req, &routes, NOW).unwrap_err();
            assert_eq!(
                err.detail(),
                "ttlSeconds must be between 1 and 3600",
                "{bad}"
            );
        }
        assert_eq!(ttl_secs(None).unwrap(), 120);
        assert_eq!(ttl_secs(Some(1.9)).unwrap(), 1);
        assert_eq!(ttl_secs(Some(3600.0)).unwrap(), 3600);
        let mut not_ready = routes.clone();
        not_ready[0].ready = false;
        let err = book.reserve(&ask("o"), &not_ready, NOW).unwrap_err();
        assert_eq!(err.http_status(), 503);
        assert_eq!(
            err.detail(),
            "No free healthy route with a fresh unique egress IP is available"
        );
        let lease = book
            .reserve(&ReserveRequest::new(" o "), &routes, NOW)
            .unwrap();
        assert_eq!(
            (lease.owner.as_str(), lease.expires_at),
            ("o", NOW + 120_000)
        );
        let err = book
            .renew(&lease.lease_token, Some(0.0), &routes, NOW)
            .unwrap_err();
        assert_eq!(err.http_status(), 400);
        assert!(
            book.lease(slot(1), NOW).is_some(),
            "a bad renew keeps the lease"
        );
    }

    /// Spec external-proxy §3.4 (confirmed quirk): a strict slot that is not ready falls back
    /// unless fallback is off; a leased strict slot is a 409 even with fallback; a leased
    /// preferred slot is a 409 only without fallback.
    #[test]
    fn strict_and_preferred_slots() {
        let mut routes = routes(&["198.51.100.1", "198.51.100.2"]);
        routes[1].ready = false;
        let mut book = LeaseBook::default();
        let strict = ReserveRequest {
            slot: Some(slot(2)),
            ..ask("a")
        };
        assert_eq!(book.reserve(&strict, &routes, NOW).unwrap().slot, slot(1));
        let no_fallback = ReserveRequest {
            slot: Some(slot(2)),
            allow_fallback: false,
            ..ask("b")
        };
        let err = book.reserve(&no_fallback, &routes, NOW).unwrap_err();
        assert_eq!(err.detail(), "Slot 2 is not a healthy ready route");
        let leased = ReserveRequest {
            slot: Some(slot(1)),
            ..ask("c")
        };
        assert_eq!(
            book.reserve(&leased, &routes, NOW).unwrap_err().detail(),
            "Slot 1 is already leased"
        );
        let preferred = ReserveRequest {
            preferred_slot: Some(slot(1)),
            allow_fallback: false,
            ..ask("d")
        };
        assert_eq!(
            book.reserve(&preferred, &routes, NOW).unwrap_err().detail(),
            "Slot 1 is already leased"
        );
        let preferred = ReserveRequest {
            preferred_slot: Some(slot(1)),
            ..ask("d")
        };
        assert_eq!(
            book.reserve(&preferred, &routes, NOW)
                .unwrap_err()
                .http_status(),
            503
        );
    }

    /// B-31: a lease on a route whose engine died is dropped on renew, unblocking the slot.
    #[test]
    fn renew_drops_a_lease_whose_route_is_down() {
        let mut routes = routes(&["198.51.100.1"]);
        let mut book = LeaseBook::default();
        let lease = book.reserve(&ask("o"), &routes, NOW).unwrap();
        routes[0].process_running = false;
        let err = book
            .renew(&lease.lease_token, None, &routes, NOW)
            .unwrap_err();
        assert_eq!(
            (err.http_status(), err.detail()),
            (409, "Leased route is down")
        );
        assert!(book.guard(slot(1), Guarded::Restart, NOW).is_ok());
        assert_eq!(
            book.renew(&lease.lease_token, None, &routes, NOW)
                .unwrap_err()
                .http_status(),
            403
        );
    }

    /// Spec external-proxy §7.7: 30 clients get 30 distinct slots and tokens; §7.2: a new book
    /// (an app restart) holds no lease, nothing is read back.
    #[test]
    fn thirty_clients_get_distinct_routes() {
        let ips: Vec<String> = (1..=30).map(|n| format!("198.51.100.{n}")).collect();
        let ips: Vec<&str> = ips.iter().map(String::as_str).collect();
        let routes = routes(&ips);
        let mut book = LeaseBook::default();
        let leases: Vec<Reservation> = (0..30)
            .map(|i| {
                book.reserve(&ask(&format!("buyer-worker-{i}")), &routes, NOW)
                    .unwrap()
            })
            .collect();
        let slots: std::collections::HashSet<Slot> = leases.iter().map(|l| l.slot).collect();
        let tokens: std::collections::HashSet<&str> =
            leases.iter().map(|l| l.lease_token.as_str()).collect();
        assert_eq!((slots.len(), tokens.len()), (30, 30));
        assert_eq!(
            book.reserve(&ask("late"), &routes, NOW)
                .unwrap_err()
                .http_status(),
            503
        );
        for l in &leases {
            book.release(&l.lease_token, NOW).unwrap();
        }
        assert_eq!(book.active(NOW).count(), 0);
        let fresh = LeaseBook::default();
        assert_eq!((fresh.active(NOW).count(), fresh.next_expiry()), (0, None));
    }

    #[test]
    fn tokens_never_show_in_debug_and_stopped_slots_are_forgotten() {
        let routes = routes(&["198.51.100.1", "198.51.100.2"]);
        let mut book = LeaseBook::default();
        let lease = book
            .reserve(
                &ReserveRequest {
                    slot: Some(slot(2)),
                    ..ask("o")
                },
                &routes,
                NOW,
            )
            .unwrap();
        assert!(!format!("{lease:?}").contains(&lease.lease_token));
        assert!(!format!("{book:?}").contains(&lease.lease_token));
        assert_eq!(book.forget_slot(slot(2)).map(|l| l.slot), Some(slot(2)));
        // The owner memory went with the slot: plain fallback order now.
        assert_eq!(book.reserve(&ask("o"), &routes, NOW).unwrap().slot, slot(1));
        book.clear();
        assert_eq!(book.active(NOW).count(), 0);
        assert!(constant_time_eq(b"abc123", b"abc123"));
        assert!(!constant_time_eq(b"abc123", b"abc124"));
        assert!(!constant_time_eq(b"abc123", b""));
    }
}
