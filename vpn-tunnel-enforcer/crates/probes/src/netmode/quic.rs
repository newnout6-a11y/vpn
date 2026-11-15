//! The QUIC probe: a datagram that every QUIC server must answer without any crypto. A long
//! header carrying a reserved ("greased") version, padded to 1200 bytes, makes the server reply
//! with a Version Negotiation packet that echoes our connection ids (RFC 9000 §6.1, §17.2.1). An
//! answer proves UDP 443 to a foreign host passes. Silence alone is not a UDP block: a QUIC or
//! port-443 filter looks the same, so the classifier also asks the STUN probe.
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::{Outcome, udp};

/// Smallest datagram a server answers (RFC 9000 §14.1: smaller Initials are discarded).
pub(crate) const PROBE_LEN: usize = 1200;
/// A reserved version of the `0x?a?a?a?a` pattern: never supported, so always negotiated.
const GREASE_VERSION: [u8; 4] = [0x1a, 0x2a, 0x3a, 0x4a];

/// The probe datagram with destination id `dcid` and source id `scid`.
pub(crate) fn probe_packet(dcid: [u8; 8], scid: [u8; 8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(PROBE_LEN);
    // Long header, fixed bit, type Initial.
    p.push(0xc0);
    p.extend_from_slice(&GREASE_VERSION);
    p.push(8);
    p.extend_from_slice(&dcid);
    p.push(8);
    p.extend_from_slice(&scid);
    p.resize(PROBE_LEN, 0);
    p
}

/// `reply` is a Version Negotiation packet answering a probe whose source id was `scid`: long
/// header, version 0, and our source id back as its destination id.
pub(crate) fn is_negotiation(reply: &[u8], scid: &[u8; 8]) -> bool {
    let long = reply.first().is_some_and(|b| b & 0x80 != 0);
    let version_zero = reply.get(1..5) == Some(&[0, 0, 0, 0][..]);
    let echoed = reply.get(5) == Some(&8) && reply.get(6..14) == Some(&scid[..]);
    long && version_zero && echoed
}

/// One probe of `dst` within `limit` per attempt, from the uplink address `source` (the
/// datagram then bypasses any TUN; none: not run).
pub(crate) async fn probe(dst: SocketAddr, source: Option<IpAddr>, limit: Duration) -> Outcome {
    let (dcid, scid) = (
        fastrand::u64(..).to_be_bytes(),
        fastrand::u64(..).to_be_bytes(),
    );
    let packet = probe_packet(dcid, scid);
    udp::exchange(dst, source, limit, &packet, |reply| {
        is_negotiation(reply, &scid)
    })
    .await
}
