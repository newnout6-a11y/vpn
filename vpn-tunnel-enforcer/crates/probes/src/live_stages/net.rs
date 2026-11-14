//! TCP connects to the probed server, pinned to the physical uplink while our tunnel is up.
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream};

use super::ProbePath;

/// Connects within `limit`. Errors are the Node errno names the old rows (and the port-state
/// classification) use: `ETIMEDOUT`, `ECONNREFUSED`, … or the OS text for anything else.
pub(crate) async fn connect(
    addr: SocketAddr,
    path: &ProbePath,
    limit: Duration,
) -> Result<TcpStream, String> {
    let attempt = async {
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        if let Some(if_index) = path.if_index() {
            bind_to_interface(&socket, if_index, addr.is_ipv6())?;
        }
        socket.connect(addr).await
    };
    match tokio::time::timeout(limit, attempt).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(err)) => Err(errno_name(&err)),
        Err(_) => Err("ETIMEDOUT".into()),
    }
}

/// Node-style error code of a socket error.
pub(crate) fn errno_name(err: &io::Error) -> String {
    use io::ErrorKind as K;
    let code = match err.kind() {
        K::ConnectionRefused => "ECONNREFUSED",
        K::ConnectionReset => "ECONNRESET",
        K::ConnectionAborted => "ECONNABORTED",
        K::TimedOut => "ETIMEDOUT",
        K::NetworkUnreachable => "ENETUNREACH",
        K::HostUnreachable => "EHOSTUNREACH",
        K::AddrNotAvailable => "EADDRNOTAVAIL",
        K::PermissionDenied => "EACCES",
        _ => return err.to_string(),
    };
    code.to_owned()
}

/// `IP_UNICAST_IF` / `IPV6_UNICAST_IF`: the socket leaves through this interface whatever the
/// routing table says (how sing-box's own `bind_interface` works on Windows).
fn bind_to_interface(socket: &TcpSocket, if_index: u32, v6: bool) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Networking::WinSock::{
        IP_UNICAST_IF, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, SOCKET, SOCKET_ERROR,
        WSAGetLastError, setsockopt,
    };
    // Winsock quirk: the IPv4 option takes the index in network byte order, the IPv6 one in host order.
    let (level, name, value) = if v6 {
        (IPPROTO_IPV6.0, IPV6_UNICAST_IF, if_index)
    } else {
        (IPPROTO_IP.0, IP_UNICAST_IF, if_index.to_be())
    };
    let raw = SOCKET(socket.as_raw_socket() as usize);
    // SAFETY: `raw` is the live socket owned by `socket`; the option value is a 4-byte DWORD.
    let rc = unsafe { setsockopt(raw, level, name, Some(&value.to_ne_bytes())) };
    if rc == SOCKET_ERROR {
        // SAFETY: reads the calling thread's last Winsock error, no preconditions.
        let code = unsafe { WSAGetLastError() };
        return Err(io::Error::from_raw_os_error(code.0));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_names() {
        let e = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(errno_name(&e), "ECONNREFUSED");
        let e = io::Error::other("weird");
        assert_eq!(errno_name(&e), "weird");
    }

    /// Binding to the loopback interface index still connects to a loopback listener.
    #[tokio::test]
    async fn bound_connect_reaches_loopback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let free = connect(addr, &ProbePath::Os, Duration::from_secs(2)).await;
        assert!(free.is_ok());
        // Loopback Pseudo-Interface 1 is index 1 on every Windows installation.
        let path = ProbePath::Physical {
            if_index: 1,
            luid: 0,
            src_v4: None,
            src_v6: None,
        };
        let bound = connect(addr, &path, Duration::from_secs(2)).await;
        assert!(bound.is_ok(), "{bound:?}");
    }

    #[tokio::test]
    async fn refused_port_reports_econnrefused() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        // Windows re-sends the SYN twice after a RST before it reports the refusal (about 2 s).
        let err = connect(addr, &ProbePath::Os, Duration::from_secs(6))
            .await
            .unwrap_err();
        assert_eq!(err, "ECONNREFUSED");
    }
}
