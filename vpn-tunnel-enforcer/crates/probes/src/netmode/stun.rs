//! The plain UDP probe: a STUN Binding Request (RFC 8489 §5, §6) to a public STUN server on its
//! own port (not 443). Any STUN server answers it without credentials, so an answer proves UDP to
//! foreign hosts passes on other ports than QUIC's. Silence here AND from the QUIC probes is what
//! "this network drops UDP" means; QUIC silence with a STUN answer is a QUIC / port-443 filter.
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::{Outcome, udp};

/// The fixed cookie of every RFC 5389+ message.
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

/// A Binding Request with transaction id `txid` and no attributes.
pub(crate) fn request(txid: [u8; 12]) -> [u8; 20] {
    let mut p = [0u8; 20];
    // Message type Binding (0x0001), length 0 (no attributes).
    p[1] = 0x01;
    p[4..8].copy_from_slice(&MAGIC_COOKIE);
    p[8..20].copy_from_slice(&txid);
    p
}

/// `reply` answers the request `txid`: a Binding success (0x0101) or error (0x0111) response
/// (either one proves the server got our datagram), our cookie and transaction id.
pub(crate) fn is_response(reply: &[u8], txid: &[u8; 12]) -> bool {
    let binding_response = matches!(reply.get(0..2), Some([0x01, 0x01] | [0x01, 0x11]));
    binding_response
        && reply.get(4..8) == Some(&MAGIC_COOKIE[..])
        && reply.get(8..20) == Some(&txid[..])
}

/// One probe of `dst` within `limit` per attempt, from the uplink address `source` (none: not
/// run).
pub(crate) async fn probe(dst: SocketAddr, source: Option<IpAddr>, limit: Duration) -> Outcome {
    let mut txid = [0u8; 12];
    txid.iter_mut().for_each(|b| *b = fastrand::u8(..));
    let packet = request(txid);
    udp::exchange(dst, source, limit, &packet, |reply| {
        is_response(reply, &txid)
    })
    .await
}
