//! Owners of local TCP/UDP sockets (`GetExtendedTcpTable` / `GetExtendedUdpTable`, IPv4 + IPv6).
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::PathBuf;

use serde::Serialize;
use windows::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA, NO_ERROR, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use super::image::image_path;

/// Transport of a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

/// TCP connection state (`MIB_TCP_STATE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown,
}

impl TcpState {
    fn from_raw(state: u32) -> Self {
        use TcpState::*;
        match state {
            1 => Closed,
            2 => Listen,
            3 => SynSent,
            4 => SynReceived,
            5 => Established,
            6 => FinWait1,
            7 => FinWait2,
            8 => CloseWait,
            9 => Closing,
            10 => LastAck,
            11 => TimeWait,
            12 => DeleteTcb,
            _ => Unknown,
        }
    }
}

/// One socket with its owning process. UDP rows have neither a remote end nor a state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SocketRow {
    pub transport: Transport,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub state: Option<TcpState>,
    pub pid: u32,
}

/// The process behind a local listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerOwner {
    pub pid: u32,
    /// The address the listener is bound to (the matching entry of `hosts`).
    pub local: SocketAddr,
    /// `None` when unreadable: protected or System process, or exited since the table was read.
    pub image: Option<PathBuf>,
}

/// Every TCP socket (all states) and every bound UDP socket, IPv4 then IPv6, with owner PIDs.
pub fn socket_table() -> windows::core::Result<Vec<SocketRow>> {
    let mut rows = table(Transport::Tcp)?;
    rows.extend(table(Transport::Udp)?);
    Ok(rows)
}

/// The process listening on `port` at the first entry of `hosts` that has a listener. List the
/// exact address first and the wildcards after it, as Windows prefers the more specific bind;
/// a dual-stack socket bound to `::` also accepts IPv4 connections, so include `::` for those.
/// TCP considers LISTEN sockets only, UDP every bound socket.
pub fn listener_owner(
    transport: Transport,
    port: u16,
    hosts: &[IpAddr],
) -> windows::core::Result<Option<ListenerOwner>> {
    let rows = table(transport)?;
    Ok(
        pick_listener(&rows, transport, port, hosts).map(|row| ListenerOwner {
            pid: row.pid,
            local: row.local,
            image: image_path(row.pid).ok(),
        }),
    )
}

fn pick_listener<'a>(
    rows: &'a [SocketRow],
    transport: Transport,
    port: u16,
    hosts: &[IpAddr],
) -> Option<&'a SocketRow> {
    hosts.iter().find_map(|host| {
        rows.iter().find(|r| {
            r.transport == transport
                && r.local.port() == port
                && r.local.ip() == *host
                && (transport == Transport::Udp || r.state == Some(TcpState::Listen))
        })
    })
}

fn table(transport: Transport) -> windows::core::Result<Vec<SocketRow>> {
    let (v4, v6) = (u32::from(AF_INET.0), u32::from(AF_INET6.0));
    let mut rows: Vec<SocketRow> = Vec::new();
    match transport {
        Transport::Tcp => {
            // SAFETY (all four calls): `buf` is None (size query) or a writable buffer of `*size`
            // bytes, `size` is a valid pointer; the table class matches the row type parsed.
            let t4 = fetch::<MIB_TCPROW_OWNER_PID>(|buf, size| unsafe {
                GetExtendedTcpTable(buf, size, false, v4, TCP_TABLE_OWNER_PID_ALL, 0)
            })?;
            let t6 = fetch::<MIB_TCP6ROW_OWNER_PID>(|buf, size| unsafe {
                GetExtendedTcpTable(buf, size, false, v6, TCP_TABLE_OWNER_PID_ALL, 0)
            })?;
            rows.extend(t4.iter().map(tcp4_row));
            rows.extend(t6.iter().map(tcp6_row));
        }
        Transport::Udp => {
            let u4 = fetch::<MIB_UDPROW_OWNER_PID>(|buf, size| unsafe {
                GetExtendedUdpTable(buf, size, false, v4, UDP_TABLE_OWNER_PID, 0)
            })?;
            let u6 = fetch::<MIB_UDP6ROW_OWNER_PID>(|buf, size| unsafe {
                GetExtendedUdpTable(buf, size, false, v6, UDP_TABLE_OWNER_PID, 0)
            })?;
            rows.extend(
                u4.iter()
                    .map(|r| udp_row(sock4(r.dwLocalAddr, r.dwLocalPort), r.dwOwningPid)),
            );
            rows.extend(u6.iter().map(|r| {
                udp_row(
                    sock6(r.ucLocalAddr, r.dwLocalPort, r.dwLocalScopeId),
                    r.dwOwningPid,
                )
            }));
        }
    }
    Ok(rows)
}

/// IP Helper owner-table rows: plain data, every bit pattern is a valid value.
///
/// # Safety
/// Implement only for `repr(C)` structs made of integers and integer arrays.
unsafe trait PlainRow: Copy {}
// SAFETY: all four are repr(C) structs of u32 and [u8; 16] fields.
unsafe impl PlainRow for MIB_TCPROW_OWNER_PID {}
// SAFETY: as above.
unsafe impl PlainRow for MIB_TCP6ROW_OWNER_PID {}
// SAFETY: as above.
unsafe impl PlainRow for MIB_UDPROW_OWNER_PID {}
// SAFETY: as above.
unsafe impl PlainRow for MIB_UDP6ROW_OWNER_PID {}

/// Size query, then fill. The table can grow between the calls (new connections), hence the
/// slack and the bounded retry.
fn fetch<R: PlainRow>(
    call: impl Fn(Option<*mut c_void>, *mut u32) -> u32,
) -> windows::core::Result<Vec<R>> {
    let mut buf: Vec<u64> = Vec::new(); // u64 storage keeps the rows aligned
    for _ in 0..4 {
        let mut size = (buf.len() * 8) as u32;
        let ptr = (!buf.is_empty()).then(|| buf.as_mut_ptr().cast::<c_void>());
        match WIN32_ERROR(call(ptr, &mut size)) {
            NO_ERROR if !buf.is_empty() => {
                // SAFETY: viewing the initialised u64 buffer as bytes; the length is in bytes.
                let bytes =
                    unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len() * 8) };
                return parse_rows(bytes).ok_or_else(|| ERROR_INVALID_DATA.into());
            }
            NO_ERROR | ERROR_INSUFFICIENT_BUFFER => {
                buf = vec![0u64; (size as usize + 4096).div_ceil(8)];
            }
            err => return Err(err.into()),
        }
    }
    Err(ERROR_INSUFFICIENT_BUFFER.into())
}

/// `dwNumEntries` followed by the row array; `None` when the count does not fit the buffer.
fn parse_rows<R: PlainRow>(bytes: &[u8]) -> Option<Vec<R>> {
    let count = u32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    let offset = size_of::<u32>().next_multiple_of(align_of::<R>());
    let end = count.checked_mul(size_of::<R>())?.checked_add(offset)?;
    let rows = bytes.get(offset..end)?;
    let read = |chunk: &[u8]| {
        // SAFETY: `chunk` holds exactly one `R` (PlainRow: any bit pattern is valid).
        unsafe { chunk.as_ptr().cast::<R>().read_unaligned() }
    };
    Some(rows.chunks_exact(size_of::<R>()).map(read).collect())
}

/// Ports sit in the low 16 bits in network byte order, i.e. in the first two bytes in memory.
fn port(raw: u32) -> u16 {
    let b = raw.to_ne_bytes();
    u16::from_be_bytes([b[0], b[1]])
}

/// IPv4 addresses are stored in network byte order (memory order = octet order).
fn sock4(addr: u32, raw_port: u32) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::from(addr.to_ne_bytes())),
        port(raw_port),
    )
}

/// Scope ids are in host order although MSDN says "network byte order": a socket bound to
/// `fe80::…%25` is listed with 25 (measured on Windows 11).
fn sock6(addr: [u8; 16], raw_port: u32, scope: u32) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(addr),
        port(raw_port),
        0,
        scope,
    ))
}

fn tcp4_row(r: &MIB_TCPROW_OWNER_PID) -> SocketRow {
    SocketRow {
        transport: Transport::Tcp,
        local: sock4(r.dwLocalAddr, r.dwLocalPort),
        remote: Some(sock4(r.dwRemoteAddr, r.dwRemotePort)),
        state: Some(TcpState::from_raw(r.dwState)),
        pid: r.dwOwningPid,
    }
}

fn tcp6_row(r: &MIB_TCP6ROW_OWNER_PID) -> SocketRow {
    SocketRow {
        transport: Transport::Tcp,
        local: sock6(r.ucLocalAddr, r.dwLocalPort, r.dwLocalScopeId),
        remote: Some(sock6(r.ucRemoteAddr, r.dwRemotePort, r.dwRemoteScopeId)),
        state: Some(TcpState::from_raw(r.dwState)),
        pid: r.dwOwningPid,
    }
}

fn udp_row(local: SocketAddr, pid: u32) -> SocketRow {
    SocketRow {
        transport: Transport::Udp,
        local,
        remote: None,
        state: None,
        pid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const ANY4: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

    #[test]
    fn row_fields_are_decoded_from_network_order() {
        // Port 10808 = 0x2A38 lives in the first two bytes, high byte first; 127.0.0.1 as octets.
        let raw_port = u32::from_ne_bytes([0x2A, 0x38, 0, 0]);
        let raw_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        assert_eq!(
            sock4(raw_addr, raw_port),
            "127.0.0.1:10808".parse().unwrap()
        );
        let row = MIB_TCPROW_OWNER_PID {
            dwState: 2,
            dwLocalAddr: raw_addr,
            dwLocalPort: raw_port,
            dwRemoteAddr: 0,
            dwRemotePort: 0,
            dwOwningPid: 4242,
        };
        let r = tcp4_row(&row);
        assert_eq!(
            (r.state, r.pid, r.local.port()),
            (Some(TcpState::Listen), 4242, 10808)
        );
        let mut v6 = [0u8; 16];
        v6[15] = 1;
        assert_eq!(sock6(v6, raw_port, 0), "[::1]:10808".parse().unwrap());
    }

    #[test]
    fn rows_are_parsed_only_when_the_count_fits() {
        let row = MIB_UDPROW_OWNER_PID {
            dwLocalAddr: 1,
            dwLocalPort: 2,
            dwOwningPid: 3,
        };
        let mut bytes = 2u32.to_ne_bytes().to_vec();
        for _ in 0..2 {
            // SAFETY (test): viewing a plain repr(C) row as bytes.
            let raw = unsafe {
                std::slice::from_raw_parts((&raw const row).cast::<u8>(), size_of_val(&row))
            };
            bytes.extend_from_slice(raw);
        }
        let rows: Vec<MIB_UDPROW_OWNER_PID> = parse_rows(&bytes).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].dwOwningPid, 3);
        assert!(parse_rows::<MIB_UDPROW_OWNER_PID>(&bytes[..bytes.len() - 1]).is_none());
        assert!(parse_rows::<MIB_UDPROW_OWNER_PID>(&[1, 0]).is_none());
    }

    fn row(transport: Transport, local: &str, state: Option<TcpState>, pid: u32) -> SocketRow {
        SocketRow {
            transport,
            local: local.parse().unwrap(),
            remote: None,
            state,
            pid,
        }
    }

    #[test]
    fn listener_pick_follows_host_order_and_tcp_state() {
        let rows = [
            row(Transport::Tcp, "0.0.0.0:1080", Some(TcpState::Listen), 1),
            row(Transport::Tcp, "127.0.0.1:1080", Some(TcpState::Listen), 2),
            row(
                Transport::Tcp,
                "127.0.0.1:2080",
                Some(TcpState::Established),
                3,
            ),
            row(Transport::Udp, "127.0.0.1:2080", None, 4),
        ];
        let pid = |t, port, hosts: &[IpAddr]| pick_listener(&rows, t, port, hosts).map(|r| r.pid);
        assert_eq!(pid(Transport::Tcp, 1080, &[LOCALHOST, ANY4]), Some(2));
        assert_eq!(pid(Transport::Tcp, 1080, &[ANY4, LOCALHOST]), Some(1));
        assert_eq!(pid(Transport::Tcp, 2080, &[LOCALHOST]), None);
        assert_eq!(pid(Transport::Udp, 2080, &[LOCALHOST]), Some(4));
        assert_eq!(pid(Transport::Udp, 1080, &[LOCALHOST, ANY4]), None);
    }

    fn assert_owned_by_us(owner: Option<ListenerOwner>) {
        let owner = owner.expect("our own listener must be found");
        assert_eq!(owner.pid, std::process::id());
        let image = owner.image.expect("own image path is readable");
        assert_eq!(
            image.file_name().map(|n| n.to_ascii_lowercase()),
            std::env::current_exe()
                .unwrap()
                .file_name()
                .map(|n| n.to_ascii_lowercase())
        );
    }

    /// B-36 (tunnel-core): the owner of a loopback listener is read from the socket tables.
    #[test]
    fn finds_our_own_tcp_and_udp_listeners() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tcp_port = tcp.local_addr().unwrap().port();
        assert_owned_by_us(listener_owner(Transport::Tcp, tcp_port, &[LOCALHOST, ANY4]).unwrap());

        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = udp.local_addr().unwrap().port();
        assert_owned_by_us(listener_owner(Transport::Udp, port, &[LOCALHOST]).unwrap());

        if let Ok(tcp6) = std::net::TcpListener::bind("[::1]:0") {
            let port = tcp6.local_addr().unwrap().port();
            let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
            assert_owned_by_us(listener_owner(Transport::Tcp, port, &[v6]).unwrap());
        }

        let all = socket_table().unwrap();
        assert!(all.iter().any(|r| r.transport == Transport::Tcp
            && r.local == SocketAddr::new(LOCALHOST, tcp_port)
            && r.state == Some(TcpState::Listen)
            && r.pid == std::process::id()));
    }
}
