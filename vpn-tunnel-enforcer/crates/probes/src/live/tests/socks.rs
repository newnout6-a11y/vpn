//! A scripted SOCKS5 server on loopback standing in for the probe inbound and the far side of
//! the tunnel (the engine stage runs over plain TCP in tests: `Wire::plain`).
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use vpnte_base::types::{Creds, Loopback};

/// What the server does after reading a CONNECT to a host.
#[derive(Clone)]
pub(crate) enum Reply {
    /// Accept, read the HTTP request, answer with these bytes and close.
    Http(Vec<u8>),
    /// Accept, then close without answering (no status line ever arrives).
    Close,
    /// Refuse with this SOCKS reply code.
    Refuse(u8),
    /// Accept and never answer.
    Hang,
}

/// A running fake; dropping it stops the listener.
pub(crate) struct FakeSocks {
    pub inbound: Loopback,
    /// CONNECT targets (`host:port`) in arrival order.
    pub targets: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl Drop for FakeSocks {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) fn creds() -> Creds {
    Creds {
        user: "probe-user".into(),
        pass: "fake-pass-123".into(),
    }
}

/// HTTP/1.1 response with a Content-Length body.
pub(crate) fn http(status: &str, body: &[u8]) -> Reply {
    let mut out = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    Reply::Http(out)
}

/// Starts a fake inbound (user / password auth) answering per CONNECT host.
pub(crate) async fn fake_socks(
    script: impl Fn(&str) -> Reply + Send + Sync + 'static,
) -> FakeSocks {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let targets = Arc::new(Mutex::new(Vec::new()));
    let seen = targets.clone();
    let script = Arc::new(script);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (seen, script) = (seen.clone(), script.clone());
            tokio::spawn(async move {
                let _ = serve(stream, &*script, &seen).await;
            });
        }
    });
    FakeSocks {
        inbound: Loopback {
            port,
            creds: Some(creds()),
        },
        targets,
        task,
    }
}

async fn serve(
    mut s: TcpStream,
    script: &(dyn Fn(&str) -> Reply + Send + Sync),
    seen: &Mutex<Vec<String>>,
) -> std::io::Result<()> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    let mut methods = vec![0u8; usize::from(head[1])];
    s.read_exact(&mut methods).await?;
    s.write_all(&[5, 2]).await?;
    let mut ver_len = [0u8; 2];
    s.read_exact(&mut ver_len).await?;
    let mut user = vec![0u8; usize::from(ver_len[1])];
    s.read_exact(&mut user).await?;
    let plen = s.read_u8().await?;
    let mut pass = vec![0u8; usize::from(plen)];
    s.read_exact(&mut pass).await?;
    let ok = user == creds().user.as_bytes() && pass == creds().pass.as_bytes();
    s.write_all(&[1, u8::from(!ok)]).await?;
    if !ok {
        return Ok(());
    }
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        4 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => {
            let len = s.read_u8().await?;
            let mut name = vec![0u8; usize::from(len)];
            s.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
    };
    let port = s.read_u16().await?;
    seen.lock().push(format!("{host}:{port}"));
    let reply = script(&host);
    let code = match reply {
        Reply::Refuse(code) => code,
        _ => 0,
    };
    s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    match reply {
        Reply::Http(bytes) => {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut chunk).await?;
                if n == 0 {
                    return Ok(());
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            s.write_all(&bytes).await?;
            s.shutdown().await
        }
        Reply::Hang => {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(())
        }
        Reply::Close | Reply::Refuse(_) => Ok(()),
    }
}
