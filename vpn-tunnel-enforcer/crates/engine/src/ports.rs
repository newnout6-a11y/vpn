//! Loopback listener ports and per-run secrets for everything the engines listen on (Clash API,
//! `mixed-direct-in`, `live-check-in`, `dns-bootstrap-in`, Xray slots).
//!
//! WHY [20000, 45000): outgoing loopback sockets (sing-box <-> Xray traffic itself) draw their
//! source ports from Windows' dynamic range 49152-65535, so a port picked there can be taken
//! before the engine binds it; Hyper-V / WSL "excluded port ranges" are caught by the bind test
//! (binding into one fails with WSAEACCES, which used to kill sing-box at start).
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::ops::{Range, RangeInclusive};

use vpnte_base::types::Creds;
use vpnte_base::{AppError, ErrorKind, Msg};

/// Ports handed out by [`alloc_listeners`] / [`alloc_port`].
pub const PORT_RANGE: Range<u16> = 20000..45000;
/// The External Proxy API range: never handed to an engine listener.
pub const RESERVED: RangeInclusive<u16> = 17990..=17999;
/// Random picks per port before giving up.
pub const TRIES: usize = 16;

/// No free loopback port was found within [`TRIES`] random picks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("no free loopback port in 20000..45000 after 16 tries")]
pub struct PortsExhausted;

impl From<PortsExhausted> for AppError {
    fn from(err: PortsExhausted) -> Self {
        AppError::msg(ErrorKind::Network, Msg::new("engine.ports.exhausted")).with_source(err)
    }
}

/// `tcp` ports that bind on TCP, then `tcp_udp` ports that bind on TCP and UDP (DNS listeners);
/// all distinct, in that order.
pub fn alloc_listeners(tcp: usize, tcp_udp: usize) -> Result<Vec<u16>, PortsExhausted> {
    let mut ports = Vec::with_capacity(tcp + tcp_udp);
    for i in 0..tcp + tcp_udp {
        let port = alloc_port(i >= tcp, &ports)?;
        ports.push(port);
    }
    Ok(ports)
}

/// One random port of [`PORT_RANGE`] that is not in `taken` and binds on `127.0.0.1` right now
/// (also on UDP when `udp`). The test socket is closed again: the engine binds it moments later.
pub fn alloc_port(udp: bool, taken: &[u16]) -> Result<u16, PortsExhausted> {
    let span = u32::from(PORT_RANGE.end - PORT_RANGE.start);
    for _ in 0..TRIES {
        let Ok(r) = getrandom::u32() else {
            return Err(PortsExhausted);
        };
        let port = PORT_RANGE.start + (r % span) as u16;
        if taken.contains(&port) || RESERVED.contains(&port) {
            continue;
        }
        if binds(port, udp) {
            return Ok(port);
        }
    }
    Err(PortsExhausted)
}

fn binds(port: u16, udp: bool) -> bool {
    let tcp_ok = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok();
    tcp_ok && (!udp || UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok())
}

/// 16 bytes from the OS CSPRNG as 32 lowercase hex chars. Never persisted, logged or shown.
pub fn secret() -> String {
    let mut bytes = [0u8; 16];
    // WHY panic: there is no safe fallback for a secret, and `ProcessPrng` does not fail on
    // supported Windows versions (std's `HashMap` seeding makes the same assumption).
    if let Err(err) = getrandom::fill(&mut bytes) {
        panic!("OS random generator failed: {err}");
    }
    hex::encode(bytes)
}

/// A fresh user/password pair for an app-owned loopback listener.
pub fn creds() -> Creds {
    Creds {
        user: secret(),
        pass: secret(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_secret(s: &str) -> bool {
        s.len() == 32
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    /// AT-02-005 (tunnel-core 7.2): every port in [20000,45000), distinct, none in 17990..17999.
    #[test]
    fn listeners_are_distinct_and_in_range() {
        for _ in 0..20 {
            let ports = alloc_listeners(5, 1).unwrap();
            assert_eq!(ports.len(), 6);
            for (i, p) in ports.iter().enumerate() {
                assert!(PORT_RANGE.contains(p), "{p}");
                assert!(!RESERVED.contains(p));
                assert!(!ports[..i].contains(p), "duplicate {p}");
            }
        }
    }

    /// A port in `taken` is never handed out again, even when the range is nearly all taken.
    #[test]
    fn taken_ports_are_skipped() {
        let first = alloc_port(false, &[]).unwrap();
        for _ in 0..50 {
            assert_ne!(alloc_port(false, &[first]).unwrap(), first);
        }
    }

    /// A port that is already bound fails the test, so the result is bindable right now.
    #[test]
    fn allocated_port_binds() {
        let port = alloc_port(true, &[]).unwrap();
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
        assert!(UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
        let held = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        assert!(!binds(held.local_addr().unwrap().port(), false));
    }

    /// AT-02-005 (tunnel-core 7.2): secrets match `^[a-f0-9]{32}$` and differ per call.
    #[test]
    fn secrets_are_32_lowercase_hex() {
        let (a, b) = (secret(), secret());
        assert!(is_secret(&a) && is_secret(&b));
        assert_ne!(a, b);
        let c = creds();
        assert!(is_secret(&c.user) && is_secret(&c.pass));
        assert_ne!(c.user, c.pass);
    }

    #[test]
    fn exhaustion_maps_to_a_message() {
        let err = AppError::from(PortsExhausted);
        assert_eq!(err.kind, ErrorKind::Network);
        assert_eq!(err.user_msg().key, "engine.ports.exhausted");
    }
}
