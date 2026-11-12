use super::*;
use crate::model::derive_readiness;
use crate::test_support::healthy_instance;

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

/// Leases still live at `now`.
fn active(book: &LeaseBook, now: UnixMs) -> usize {
    book.leases.values().filter(|l| l.expires_at > now).count()
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
    assert_eq!(active(&book, NOW + 1001), 1);
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
    assert_eq!(active(&book, NOW), 0);
    let fresh = LeaseBook::default();
    assert_eq!((active(&fresh, NOW), fresh.next_expiry()), (0, None));
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
    assert_eq!(active(&book, NOW), 0);
}
