//! SOCKS CONNECT latency against a scripted loopback SOCKS5 server (AT-07-003;
//! socksPing.test.ts).
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use vpnte_base::types::{Creds, Loopback};

use super::*;

fn creds() -> Creds {
    Creds {
        user: "probe-user".into(),
        pass: "fake-pass-123".into(),
    }
}

/// Behaviour of the fake server: the method it selects (0x02 user/password, 0x00 no-auth), the
/// credentials it accepts and its CONNECT reply code (0 = success).
#[derive(Clone)]
struct Script {
    method: u8,
    creds: Option<Creds>,
    rep: u8,
}

/// What clients sent, for assertions.
#[derive(Default)]
struct Seen {
    greetings: AtomicUsize,
    connects: Mutex<Vec<Vec<u8>>>,
    auth: Mutex<Vec<Vec<u8>>>,
}

fn no_auth(rep: u8) -> Script {
    Script {
        method: 0,
        creds: None,
        rep,
    }
}

async fn serve(script: Script) -> (u16, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Seen::default());
    let out = seen.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(session(stream, script.clone(), seen.clone()));
        }
    });
    (port, out)
}

async fn session(mut s: TcpStream, script: Script, seen: Arc<Seen>) -> std::io::Result<()> {
    let mut head = [0; 2];
    s.read_exact(&mut head).await?;
    let mut methods = vec![0; head[1] as usize];
    s.read_exact(&mut methods).await?;
    seen.greetings.fetch_add(1, Ordering::SeqCst);
    // Fragmented on purpose: the client must reassemble the method reply.
    s.write_all(&[5]).await?;
    s.flush().await?;
    tokio::time::sleep(Duration::from_millis(5)).await;
    s.write_all(&[script.method]).await?;
    if script.method == 2 {
        let mut auth = vec![0; 2];
        s.read_exact(&mut auth).await?;
        let mut user = vec![0; auth[1] as usize];
        s.read_exact(&mut user).await?;
        let mut plen = [0; 1];
        s.read_exact(&mut plen).await?;
        let mut pass = vec![0; plen[0] as usize];
        s.read_exact(&mut pass).await?;
        let ok = script
            .creds
            .as_ref()
            .is_some_and(|c| c.user.as_bytes() == user && c.pass.as_bytes() == pass);
        let sent = [auth, user, plen.to_vec(), pass].concat();
        seen.auth.lock().push(sent);
        s.write_all(&[1, if ok { 0 } else { 1 }]).await?;
        if !ok {
            return Ok(());
        }
    }
    let request = read_connect(&mut s).await?;
    seen.connects.lock().push(request);
    s.write_all(&[5, script.rep, 0, 1, 127, 0, 0, 1, 0, 80])
        .await?;
    // Hold the connection like a proxy that dialled the target.
    tokio::time::sleep(Duration::from_secs(5)).await;
    Ok(())
}

/// Reads `05 01 00 ATYP ADDR PORT` and returns it raw.
async fn read_connect(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut head = [0; 4];
    s.read_exact(&mut head).await?;
    let addr_len = match head[3] {
        1 => 4,
        4 => 16,
        _ => {
            let mut len = [0; 1];
            s.read_exact(&mut len).await?;
            return read_rest(s, [&head[..], &len].concat(), len[0] as usize).await;
        }
    };
    read_rest(s, head.to_vec(), addr_len).await
}

/// Appends the address of `addr_len` bytes and the port to `request`.
async fn read_rest(
    s: &mut TcpStream,
    mut request: Vec<u8>,
    addr_len: usize,
) -> std::io::Result<Vec<u8>> {
    let mut rest = vec![0; addr_len + 2];
    s.read_exact(&mut rest).await?;
    request.extend_from_slice(&rest);
    Ok(request)
}

/// `05 00` then a success reply → a latency; reply code 5 → `None` (socksPing.test.ts).
#[tokio::test]
async fn socks_latency_reads_the_connect_reply() {
    let (port, seen) = serve(no_auth(0)).await;
    let proxy = Loopback { port, creds: None };
    let ms = socks_connect_latency(&proxy, "example.com", 443, Duration::from_secs(2)).await;
    assert!(ms.is_some_and(|ms| ms >= 1));
    assert_eq!(
        seen.connects.lock()[0],
        [&[5u8, 1, 0, 3, 11][..], b"example.com", &[1, 187]].concat()
    );
    let (port, _) = serve(no_auth(5)).await;
    let refused = Loopback { port, creds: None };
    assert_eq!(
        socks_connect_latency(&refused, "example.com", 443, Duration::from_secs(2)).await,
        None
    );
}

/// Invalid input is `None` without any I/O.
#[tokio::test]
async fn socks_latency_refuses_invalid_input() {
    let (port, seen) = serve(no_auth(0)).await;
    let proxy = Loopback { port, creds: None };
    let limit = Duration::from_secs(1);
    assert_eq!(
        socks_connect_latency(&proxy, "example.com", 0, limit).await,
        None
    );
    assert_eq!(socks_connect_latency(&proxy, "", 443, limit).await, None);
    assert_eq!(
        socks_connect_latency(&proxy, "example.com", 443, Duration::ZERO).await,
        None
    );
    let zero = Loopback {
        port: 0,
        creds: None,
    };
    assert_eq!(
        socks_connect_latency(&zero, "example.com", 443, limit).await,
        None
    );
    assert_eq!(seen.greetings.load(Ordering::SeqCst), 0);
}

/// IPv6 targets use ATYP 4; with credentials only user/password is offered, and a server that
/// answers no-auth is refused.
#[tokio::test]
async fn socks_latency_encodings_and_auth() {
    let (port, seen) = serve(no_auth(0)).await;
    let proxy = Loopback { port, creds: None };
    assert!(
        socks_connect_latency(&proxy, "2001:db8::1", 8443, Duration::from_secs(2))
            .await
            .is_some()
    );
    let mut expected = vec![5u8, 1, 0, 4];
    expected.extend_from_slice(
        &"2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    expected.extend_from_slice(&8443u16.to_be_bytes());
    assert_eq!(seen.connects.lock()[0], expected);

    let authed_server = Script {
        method: 2,
        creds: Some(creds()),
        rep: 0,
    };
    let (port, seen) = serve(authed_server).await;
    let authed = Loopback {
        port,
        creds: Some(creds()),
    };
    assert!(
        socks_connect_latency(&authed, "1.2.3.4", 443, Duration::from_secs(2))
            .await
            .is_some()
    );
    assert_eq!(
        seen.auth.lock()[0],
        [&[1u8, 10][..], b"probe-user", &[13], b"fake-pass-123"].concat()
    );
    assert_eq!(
        seen.connects.lock()[0],
        vec![5, 1, 0, 1, 1, 2, 3, 4, 1, 187]
    );

    let (port, _) = serve(no_auth(0)).await;
    let wants_auth = Loopback {
        port,
        creds: Some(creds()),
    };
    assert_eq!(
        socks_connect_latency(&wants_auth, "1.2.3.4", 443, Duration::from_secs(2)).await,
        None
    );
}

/// Three parallel samples reduce to the median; all failing → `None`.
#[tokio::test]
async fn reliable_latency_takes_the_median() {
    let (port, seen) = serve(no_auth(0)).await;
    let proxy = Loopback { port, creds: None };
    assert!(
        reliable_socks_latency(&proxy, "example.com", 443, Duration::from_secs(2), 3)
            .await
            .is_some()
    );
    assert_eq!(seen.greetings.load(Ordering::SeqCst), 3);
    let (port, _) = serve(no_auth(1)).await;
    let failing = Loopback { port, creds: None };
    assert_eq!(
        reliable_socks_latency(&failing, "example.com", 443, Duration::from_secs(2), 3).await,
        None
    );
}
