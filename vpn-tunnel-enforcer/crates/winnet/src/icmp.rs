//! ICMP echo for ping, traceroute fan-out and PMTU ladders: `IcmpSendEcho2Ex` (IPv4) and
//! `Icmp6SendEcho2` (IPv6), one blocking-pool thread per probe. Needs no admin rights and no raw
//! sockets; the reply status comes from the OS stack, so no console-tool output is parsed.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use vpnte_base::{AppError, ErrorKind, Msg};
use windows::Win32::Foundation::{GetLastError, HANDLE, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{
    ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY_LH, IP_BAD_DESTINATION, IP_DEST_HOST_UNREACHABLE,
    IP_DEST_NET_UNREACHABLE, IP_DEST_PORT_UNREACHABLE, IP_DEST_PROT_UNREACHABLE,
    IP_DEST_SCOPE_MISMATCH, IP_DEST_UNREACHABLE, IP_FLAG_DF, IP_OPTION_INFORMATION,
    IP_PACKET_TOO_BIG, IP_REQ_TIMED_OUT, IP_STATUS_BASE, IP_SUCCESS, IP_TIME_EXCEEDED,
    IP_TTL_EXPIRED_TRANSIT, Icmp6CreateFile, Icmp6SendEcho2, IcmpCloseHandle, IcmpCreateFile,
    IcmpSendEcho2Ex,
};
use windows::Win32::Networking::WinSock::{AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6};

/// Largest payload accepted (ping.exe's limit; the IPv4 maximum is 65507).
pub const MAX_PAYLOAD: u16 = 65_500;
/// Longest accepted timeout.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(30);

/// One echo request. Start from [`EchoRequest::new`] and override fields:
/// `EchoRequest { ttl: 3, ..EchoRequest::new(dst) }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoRequest {
    pub dst: IpAddr,
    /// Address to send from (pins the interface, e.g. the physical one); `None` = OS route.
    pub src: Option<IpAddr>,
    /// TTL (IPv4) or hop limit (IPv6), at least 1.
    pub ttl: u8,
    /// Don't fragment (the IPv4 DF bit; IPv6 routers never fragment): an oversized probe comes
    /// back as [`EchoStatus::PacketTooBig`].
    pub df: bool,
    /// ICMP payload bytes; the packet adds 28 (IPv4) or 48 (IPv6) bytes of headers.
    pub payload: u16,
    /// Reply deadline, 1 ms ..= [`MAX_TIMEOUT`] (whole milliseconds are used).
    pub timeout: Duration,
}

impl EchoRequest {
    /// TTL 128, no DF and a 32-byte payload like ping.exe; 1 s timeout (ping.exe waits 4 s, the
    /// live probes wait at most 1 s).
    pub fn new(dst: IpAddr) -> Self {
        Self {
            dst,
            src: None,
            ttl: 128,
            df: false,
            payload: 32,
            timeout: Duration::from_secs(1),
        }
    }
}

/// What came back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoStatus {
    /// Echo reply (from the destination itself).
    Success,
    /// TTL / hop limit expired in transit; the reply comes from that hop.
    TtlExpired,
    /// DF set and the packet exceeds the MTU of a hop or of the local interface.
    PacketTooBig,
    /// No reply within the timeout.
    TimedOut,
    /// Destination network, host, protocol or port unreachable, or administratively prohibited.
    Unreachable,
    /// Any other `IP_*` status (raw code, for logs).
    Other(u32),
}

/// Result of one echo request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoReply {
    pub status: EchoStatus,
    /// Who answered: the destination, the hop whose TTL ran out, or the reporting router.
    pub from: Option<IpAddr>,
    /// Round-trip time reported by the stack, whole milliseconds; `None` without a reply.
    pub rtt_ms: Option<u32>,
}

/// Why no answer could be obtained at all (a timeout is an answer, not an error).
#[derive(Debug, thiserror::Error)]
pub enum IcmpError {
    #[error("invalid echo request: {0}")]
    Invalid(&'static str),
    #[error(transparent)]
    Os(#[from] windows::core::Error),
    #[error("echo task did not complete")]
    Join,
}

impl From<IcmpError> for AppError {
    fn from(err: IcmpError) -> Self {
        let (kind, key) = match &err {
            IcmpError::Invalid(_) => (ErrorKind::Validation, "winnet.icmp.invalid"),
            IcmpError::Os(_) => (ErrorKind::Network, "winnet.icmp.failed"),
            IcmpError::Join => (ErrorKind::Internal, "winnet.icmp.failed"),
        };
        AppError::msg(kind, Msg::new(key)).with_source(err)
    }
}

/// Sends one echo request and waits for the reply or the timeout on a blocking-pool thread.
/// Fan-outs (traceroute TTLs, PMTU ladders) simply run several of these concurrently.
pub async fn echo(req: EchoRequest) -> Result<EchoReply, IcmpError> {
    validate(&req)?;
    tokio::task::spawn_blocking(move || echo_blocking(&req))
        .await
        .map_err(|_| IcmpError::Join)?
}

fn validate(req: &EchoRequest) -> Result<(), IcmpError> {
    if req.ttl == 0 {
        return Err(IcmpError::Invalid("ttl must be at least 1"));
    }
    if req.payload > MAX_PAYLOAD {
        return Err(IcmpError::Invalid("payload too large"));
    }
    if req.timeout < Duration::from_millis(1) || req.timeout > MAX_TIMEOUT {
        return Err(IcmpError::Invalid("timeout out of range"));
    }
    if req
        .src
        .is_some_and(|src| src.is_ipv4() != req.dst.is_ipv4())
    {
        return Err(IcmpError::Invalid("source and destination families differ"));
    }
    Ok(())
}

/// An ICMP handle, closed on drop.
struct IcmpHandle(HANDLE);

impl Drop for IcmpHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from Icmp(6)CreateFile and is closed exactly once.
        let _ = unsafe { IcmpCloseHandle(self.0) };
    }
}

fn echo_blocking(req: &EchoRequest) -> Result<EchoReply, IcmpError> {
    // ping.exe's payload pattern, so filters treat our probes like the system tool's.
    let payload: Vec<u8> = (0..req.payload).map(|i| b'a' + (i % 23) as u8).collect();
    // MSDN mentions 32-bit layouts (IP_OPTION_INFORMATION32 / ICMP_ECHO_REPLY32) on 64-bit
    // Windows: only the leading fields are used here (TTL/flags in, address/status/RTT out),
    // and they sit at the same offsets in both layouts; no options data is sent.
    let options = IP_OPTION_INFORMATION {
        Ttl: req.ttl,
        Flags: if req.df { IP_FLAG_DF as u8 } else { 0 },
        ..Default::default()
    };
    let timeout = req.timeout.as_millis() as u32; // validated: at most 30 s
    // One reply + echoed payload + 8 bytes of ICMP error data + an IO_STATUS_BLOCK (MSDN), with
    // slack; u64 storage keeps the reply structure aligned.
    let reply_len = |head: usize| (head + payload.len() + 8 + 16 + 64).div_ceil(8);
    match (req.dst, req.src) {
        (IpAddr::V4(dst), src) => {
            let src = match src {
                Some(IpAddr::V4(src)) => src,
                _ => Ipv4Addr::UNSPECIFIED,
            };
            // SAFETY: plain call; the handle is owned by `IcmpHandle` right away.
            let handle = IcmpHandle(unsafe { IcmpCreateFile()? });
            let mut buf = vec![0u64; reply_len(size_of::<ICMP_ECHO_REPLY>())];
            // SAFETY: synchronous call (no event, no APC); every pointer is valid for the call
            // and the reply buffer length is given in bytes.
            let replies = unsafe {
                IcmpSendEcho2Ex(
                    handle.0,
                    None,
                    None,
                    None,
                    u32::from_ne_bytes(src.octets()),
                    u32::from_ne_bytes(dst.octets()),
                    payload.as_ptr().cast(),
                    req.payload,
                    Some(&raw const options),
                    buf.as_mut_ptr().cast(),
                    (buf.len() * 8) as u32,
                    timeout,
                )
            };
            if replies == 0 {
                // SAFETY: read right after the failing call on the same thread.
                return no_reply(unsafe { GetLastError() });
            }
            // SAFETY: at least one ICMP_ECHO_REPLY was written at the start of the aligned buffer.
            let reply = unsafe { buf.as_ptr().cast::<ICMP_ECHO_REPLY>().read() };
            let from = IpAddr::V4(Ipv4Addr::from(reply.Address.to_ne_bytes()));
            Ok(reply_of(reply.Status, from, reply.RoundTripTime))
        }
        (IpAddr::V6(dst), src) => {
            let src = match src {
                Some(IpAddr::V6(src)) => src,
                _ => Ipv6Addr::UNSPECIFIED,
            };
            // SAFETY: plain call; the handle is owned by `IcmpHandle` right away.
            let handle = IcmpHandle(unsafe { Icmp6CreateFile()? });
            let mut buf = vec![0u64; reply_len(size_of::<ICMPV6_ECHO_REPLY_LH>())];
            let (src, dst) = (sockaddr6(src), sockaddr6(dst));
            // SAFETY: as for IPv4; the socket addresses live on this stack frame.
            let replies = unsafe {
                Icmp6SendEcho2(
                    handle.0,
                    None,
                    None,
                    None,
                    &raw const src,
                    &raw const dst,
                    payload.as_ptr().cast(),
                    req.payload,
                    Some(&raw const options),
                    buf.as_mut_ptr().cast(),
                    (buf.len() * 8) as u32,
                    timeout,
                )
            };
            if replies == 0 {
                // SAFETY: read right after the failing call on the same thread.
                return no_reply(unsafe { GetLastError() });
            }
            // SAFETY: at least one ICMPV6_ECHO_REPLY was written at the start of the buffer.
            let reply = unsafe { buf.as_ptr().cast::<ICMPV6_ECHO_REPLY_LH>().read() };
            let words = reply.Address.sin6_addr;
            Ok(reply_of(
                reply.Status,
                IpAddr::V6(ipv6_from_words(words)),
                reply.RoundTripTime,
            ))
        }
    }
}

fn sockaddr6(ip: Ipv6Addr) -> SOCKADDR_IN6 {
    SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 { Byte: ip.octets() },
        },
        ..Default::default()
    }
}

/// `IPV6_ADDRESS_EX.sin6_addr` holds the address as eight words whose bytes are in network
/// order in memory.
fn ipv6_from_words(words: [u16; 8]) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    for (pair, word) in octets.as_chunks_mut::<2>().0.iter_mut().zip(words) {
        *pair = word.to_ne_bytes();
    }
    Ipv6Addr::from(octets)
}

/// A reply that names a sender carries a round-trip time.
fn reply_of(status: u32, from: IpAddr, rtt_ms: u32) -> EchoReply {
    let from = (!from.is_unspecified()).then_some(from);
    EchoReply {
        status: status_of(status),
        from,
        rtt_ms: from.map(|_| rtt_ms),
    }
}

/// With zero replies the outcome is in GetLastError: an `IP_*` status (timeout, too big,
/// unreachable) is an answer; any other code is an OS failure.
fn no_reply(code: WIN32_ERROR) -> Result<EchoReply, IcmpError> {
    if (IP_STATUS_BASE..=IP_STATUS_BASE + 255).contains(&code.0) {
        Ok(EchoReply {
            status: status_of(code.0),
            from: None,
            rtt_ms: None,
        })
    } else {
        Err(IcmpError::Os(code.into()))
    }
}

fn status_of(code: u32) -> EchoStatus {
    match code {
        IP_SUCCESS => EchoStatus::Success,
        // 11013 is also IP_HOP_LIMIT_EXCEEDED (IPv6).
        IP_TTL_EXPIRED_TRANSIT | IP_TIME_EXCEEDED => EchoStatus::TtlExpired,
        IP_PACKET_TOO_BIG => EchoStatus::PacketTooBig,
        IP_REQ_TIMED_OUT => EchoStatus::TimedOut,
        // Equal values: NET = NO_ROUTE, HOST = ADDR, PROT = PROHIBITED.
        IP_DEST_NET_UNREACHABLE
        | IP_DEST_HOST_UNREACHABLE
        | IP_DEST_PROT_UNREACHABLE
        | IP_DEST_PORT_UNREACHABLE
        | IP_DEST_UNREACHABLE
        | IP_DEST_SCOPE_MISMATCH
        | IP_BAD_DESTINATION => EchoStatus::Unreachable,
        other => EchoStatus::Other(other),
    }
}

#[cfg(test)]
mod tests {
    use windows::Win32::Foundation::ERROR_INVALID_PARAMETER;

    use super::*;

    const V4_LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    #[test]
    fn requests_are_validated_before_sending() {
        let base = EchoRequest::new(V4_LOOPBACK);
        let invalid = |r: EchoRequest| matches!(validate(&r), Err(IcmpError::Invalid(_)));
        assert!(validate(&base).is_ok());
        assert!(invalid(EchoRequest { ttl: 0, ..base }));
        assert!(invalid(EchoRequest {
            payload: MAX_PAYLOAD + 1,
            ..base
        }));
        assert!(invalid(EchoRequest {
            timeout: Duration::from_micros(999),
            ..base
        }));
        assert!(invalid(EchoRequest {
            timeout: MAX_TIMEOUT + Duration::from_millis(1),
            ..base
        }));
        assert!(invalid(EchoRequest {
            src: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ..base
        }));
    }

    #[test]
    fn statuses_map_to_outcomes() {
        assert_eq!(status_of(0), EchoStatus::Success);
        assert_eq!(status_of(11013), EchoStatus::TtlExpired);
        assert_eq!(status_of(11009), EchoStatus::PacketTooBig);
        assert_eq!(status_of(11010), EchoStatus::TimedOut);
        assert_eq!(status_of(11003), EchoStatus::Unreachable);
        assert_eq!(status_of(11050), EchoStatus::Other(11050));
        let timed_out = no_reply(WIN32_ERROR(11010)).unwrap();
        assert_eq!(
            (timed_out.status, timed_out.from, timed_out.rtt_ms),
            (EchoStatus::TimedOut, None, None)
        );
        assert!(matches!(
            no_reply(ERROR_INVALID_PARAMETER),
            Err(IcmpError::Os(_))
        ));
        let hop = reply_of(11013, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 7);
        assert_eq!((hop.status, hop.rtt_ms), (EchoStatus::TtlExpired, Some(7)));
        assert_eq!(
            reply_of(11010, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).from,
            None
        );
    }

    #[test]
    fn ipv6_reply_words_keep_network_order() {
        // In memory, 2001:db8::1 is the byte sequence 20 01 0d b8 00 .. 00 01.
        let word = |hi: u8, lo: u8| u16::from_ne_bytes([hi, lo]);
        let words = [
            word(0x20, 0x01),
            word(0x0d, 0xb8),
            0,
            0,
            0,
            0,
            0,
            word(0, 1),
        ];
        let expect: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(ipv6_from_words(words), expect);
    }

    #[tokio::test]
    async fn loopback_echo_succeeds() {
        let reply = echo(EchoRequest::new(V4_LOOPBACK)).await.unwrap();
        assert_eq!(reply.status, EchoStatus::Success);
        assert_eq!(reply.from, Some(V4_LOOPBACK));
        assert!(reply.rtt_ms.is_some());
        // A full-size DF probe with a pinned source: the loopback MTU is far above 1500.
        let big = EchoRequest {
            df: true,
            payload: 1472,
            src: Some(V4_LOOPBACK),
            ttl: 64,
            ..EchoRequest::new(V4_LOOPBACK)
        };
        assert_eq!(echo(big).await.unwrap().status, EchoStatus::Success);
        let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let reply = echo(EchoRequest::new(v6)).await.unwrap();
        assert_eq!((reply.status, reply.from), (EchoStatus::Success, Some(v6)));
    }

    /// Traceroute building block: TTL 1 to a public address expires at the first hop. A VPN TUN
    /// may answer echo requests itself; `VPNTE_TEST_ICMP_SRC=<physical IPv4>` pins the probe to
    /// the physical interface, as live checks do. Opt-in with `VPNTE_ICMP_TESTS=1`: GitHub-hosted
    /// runners (Azure) drop ICMP to the internet, so the elevated CI job cannot prove it.
    #[tokio::test]
    #[ignore = "needs internet that answers ICMP (VPNTE_ICMP_TESTS=1)"]
    async fn ttl_one_expires_at_the_first_hop() {
        if std::env::var_os("VPNTE_ICMP_TESTS").is_none() {
            eprintln!("skipped: set VPNTE_ICMP_TESTS=1 on a network that answers ICMP");
            return;
        }
        let src = std::env::var("VPNTE_TEST_ICMP_SRC")
            .ok()
            .map(|s| s.parse().unwrap());
        let dst = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let req = EchoRequest {
            ttl: 1,
            src,
            ..EchoRequest::new(dst)
        };
        let reply = echo(req).await.unwrap();
        assert_eq!(reply.status, EchoStatus::TtlExpired, "{reply:?}");
        assert!(reply.from.is_some_and(|from| from != dst));
    }
}
