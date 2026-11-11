//! A scripted SOCKS5 inbound on loopback (no authentication) standing in for a proxy and the
//! far side of the tunnel: plain HTTP after the CONNECT (`Wire::plain`), one answer per request,
//! a freeze is "send, then stay silent with the connection open". Tests only.
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use vpnte_base::types::Loopback;

/// What the far side does for one request.
#[derive(Debug, Clone)]
pub(crate) enum Answer {
    /// Write these bytes and wait for the next request.
    Send(Vec<u8>),
    /// Write these bytes, then go silent with the connection open (a freeze: no FIN, no RST).
    SendThenHang(Vec<u8>),
    /// Write these bytes and close.
    SendThenClose(Vec<u8>),
    /// Never answer.
    Hang,
}

/// A trace body with a public exit address and a country.
pub(crate) const TRACE: &[u8] = b"fl=1\nh=speed.cloudflare.com\nip=185.220.101.5\nts=1\nloc=NL\n";

pub(crate) fn head(status: &str, len: usize) -> Vec<u8> {
    format!("HTTP/1.1 {status}\r\nContent-Length: {len}\r\n\r\n").into_bytes()
}

/// A 64 KiB download whose body stops after `sent` bytes.
pub(crate) fn download(sent: usize) -> Vec<u8> {
    let mut out = head("200 OK", 64 * 1024);
    out.resize(out.len() + sent, b'x');
    out
}

pub(crate) fn trace() -> Answer {
    let mut out = head("200 OK", TRACE.len());
    out.extend_from_slice(TRACE);
    Answer::Send(out)
}

/// Starts the inbound; every connection gets the same script. Abort the task when done.
pub(crate) async fn far_side(answers: Vec<Answer>) -> (Loopback, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let answers = answers.clone();
            tokio::spawn(async move {
                let _ = serve(stream, answers).await;
            });
        }
    });
    (Loopback { port, creds: None }, task)
}

async fn serve(mut s: TcpStream, answers: Vec<Answer>) -> std::io::Result<()> {
    let mut greeting = [0u8; 2];
    s.read_exact(&mut greeting).await?;
    let mut methods = vec![0u8; usize::from(greeting[1])];
    s.read_exact(&mut methods).await?;
    s.write_all(&[5, 0]).await?;
    let mut request = [0u8; 4];
    s.read_exact(&mut request).await?;
    let addr_len = match request[3] {
        1 => 4,
        4 => 16,
        _ => usize::from(s.read_u8().await?),
    };
    let mut rest = vec![0u8; addr_len + 2];
    s.read_exact(&mut rest).await?;
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    for answer in answers {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = s.read(&mut chunk).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        match answer {
            Answer::Send(bytes) => s.write_all(&bytes).await?,
            Answer::SendThenClose(bytes) => {
                s.write_all(&bytes).await?;
                return s.shutdown().await;
            }
            Answer::SendThenHang(bytes) => {
                s.write_all(&bytes).await?;
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
            Answer::Hang => tokio::time::sleep(Duration::from_secs(30)).await,
        }
    }
    Ok(())
}
