use std::net::IpAddr;

use super::*;
use crate::resolve::tests::{answer, ip};

#[test]
fn query_bytes() {
    let q = query(0x1234, "ex.com", Record::A).unwrap();
    let mut expected = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    expected.extend_from_slice(b"\x02ex\x03com\x00\x00\x01\x00\x01");
    assert_eq!(q, expected);
    let q = query(7, "a.b", Record::Aaaa).unwrap();
    assert_eq!(&q[q.len() - 4..], &[0, 28, 0, 1]);
}

#[test]
fn query_refuses_bad_labels() {
    assert_eq!(query(1, "a..b", Record::A), None);
    assert_eq!(query(1, &"x".repeat(64), Record::A), None);
    let long = ["a".repeat(63).as_str(); 4].join(".");
    assert_eq!(
        query(1, &long, Record::A),
        None,
        "{} octets",
        long.len() + 2
    );
    assert!(query(1, &"x".repeat(63), Record::A).is_some());
}

#[test]
fn parse_reads_flags_and_addresses() {
    let q = query(0xbeef, "example.com", Record::A).unwrap();
    let reply = answer(
        &q,
        NOERROR,
        false,
        &[ip("203.0.113.1"), ip("2001:db8::1"), ip("198.51.100.2")],
    );
    let parsed = parse(&reply, &q, Record::A).unwrap();
    assert_eq!(
        parsed,
        Reply {
            rcode: NOERROR,
            authoritative: false,
            addrs: vec![ip("203.0.113.1"), ip("198.51.100.2")]
        }
    );
    let forged = answer(&q, NXDOMAIN, true, &[]);
    let parsed = parse(&forged, &q, Record::A).unwrap();
    assert_eq!(
        (parsed.rcode, parsed.authoritative, parsed.addrs.len()),
        (NXDOMAIN, true, 0)
    );
    let q6 = query(9, "example.com", Record::Aaaa).unwrap();
    let parsed = parse(
        &answer(&q6, NOERROR, false, &[ip("2001:db8::7")]),
        &q6,
        Record::Aaaa,
    )
    .unwrap();
    assert_eq!(parsed.addrs, vec![ip("2001:db8::7")]);
}

/// A CNAME step, a record of another class and an A record of the wrong size are skipped;
/// the A after them (owner name compressed) is read.
#[test]
fn parse_skips_other_records() {
    let q = query(5, "www.example.com", Record::A).unwrap();
    let mut reply = answer(&q, NOERROR, false, &[]);
    reply[7] = 4;
    let cname: &[u8] = b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x05\x02cd\xc0\x10";
    let chaos: &[u8] = b"\xc0\x0c\x00\x01\x00\x03\x00\x00\x00\x3c\x00\x04\x0a\x00\x00\x01";
    let short: &[u8] = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x03\x0a\x00\x00";
    let a: &[u8] = b"\x02cd\xc0\x10\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xcb\x00\x71\x09";
    for record in [cname, chaos, short, a] {
        reply.extend_from_slice(record);
    }
    let parsed = parse(&reply, &q, Record::A).unwrap();
    assert_eq!(parsed.addrs, vec![IpAddr::from([203, 0, 113, 9])]);
}

#[test]
fn parse_refuses_what_is_not_our_answer() {
    let q = query(0x0102, "example.com", Record::A).unwrap();
    let good = answer(&q, NOERROR, false, &[ip("203.0.113.1")]);
    let mut other_id = good.clone();
    other_id[1] ^= 1;
    let mut not_a_reply = good.clone();
    not_a_reply[2] &= 0x7f;
    let other_name = answer(
        &query(0x0102, "example.org", Record::A).unwrap(),
        NOERROR,
        false,
        &[],
    );
    let mut cut = good.clone();
    cut.pop();
    for (what, bytes) in [
        ("id", other_id),
        ("QR", not_a_reply),
        ("question", other_name),
        ("cut", cut),
    ] {
        assert_eq!(parse(&bytes, &q, Record::A), None, "{what}");
    }
    assert_eq!(parse(b"<html>blocked</html>", &q, Record::A), None);
    assert_eq!(parse(&[], &q, Record::A), None);
    // 0x20 case mixing in the echoed question is fine.
    let mut mixed = good.clone();
    mixed[13] = b'E';
    assert!(parse(&mixed, &q, Record::A).is_some());
}
