//! How an app-originated HTTP request leaves the machine: straight out or through a proxy.
//! Built on [`vpnte_base::http::client_builder`], so the system proxy is never used implicitly.
use std::fmt;
use std::time::Duration;

use url::{Position, Url};
use vpnte_base::types::{Creds, ProxyKind};
use vpnte_base::{AppError, AppResult, http};

use super::HostPort;

/// Egress of an app request.
#[derive(Clone, PartialEq, Eq)]
pub enum Route {
    /// No proxy (with the tunnel up, "direct" already rides the TUN).
    Direct,
    /// Through a proxy: `socks5h://` (the proxy resolves names) or `http://`; credentials, if
    /// any, sit percent-encoded in the userinfo.
    Proxy { url: Url },
}

impl Route {
    /// Route through the proxy at `addr`. SOCKS uses `socks5h` so no name is resolved locally.
    pub fn proxy(kind: ProxyKind, addr: &HostPort, creds: Option<&Creds>) -> Route {
        let scheme = match kind {
            ProxyKind::Socks5 => "socks5h",
            ProxyKind::Http => "http",
        };
        // A validated host:port always forms a URL with an authority, which accepts userinfo
        // (`Host::parse` already ran the URL host parser on names).
        let mut url = Url::parse(&format!("{scheme}://{addr}")).expect("validated host:port");
        if let Some(creds) = creds {
            // The URL standard leaves `%` as is in userinfo while proxy clients percent-decode
            // it, so a password like `ab%41` would arrive as `abA` unless `%` is escaped first.
            let escape = |s: &str| s.replace('%', "%25");
            let set = url.set_username(&escape(&creds.user)).is_ok()
                && url.set_password(Some(&escape(&creds.pass))).is_ok();
            debug_assert!(set, "a URL with a host accepts userinfo");
        }
        Route::Proxy { url }
    }

    /// Log-safe label: `direct` or `scheme://host:port` (never the credentials).
    pub fn label(&self) -> String {
        match self {
            Route::Direct => "direct".to_owned(),
            Route::Proxy { url } => format!(
                "{}://{}",
                url.scheme(),
                &url[Position::BeforeHost..Position::AfterPort]
            ),
        }
    }
}

impl fmt::Debug for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Route({})", self.label())
    }
}

/// Client builder with the app defaults (no implicit proxy, no redirects, `timeout`) bound to
/// `route`; callers may still add headers or pinned addresses (`resolve_to_addrs`).
pub fn builder_for(route: &Route, timeout: Duration) -> AppResult<reqwest::ClientBuilder> {
    let builder = http::client_builder(timeout);
    match route {
        Route::Direct => Ok(builder),
        Route::Proxy { url } => {
            let proxy = reqwest::Proxy::all(url.clone())
                .map_err(|err| AppError::internal(err.without_url()))?;
            Ok(builder.proxy(proxy))
        }
    }
}

/// Ready client for `route` with the app defaults.
pub fn client_for(route: &Route, timeout: Duration) -> AppResult<reqwest::Client> {
    builder_for(route, timeout)?
        .build()
        .map_err(|err| AppError::internal(err.without_url()))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    const OK: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";

    fn creds(user: &str, pass: &str) -> Creds {
        Creds {
            user: user.into(),
            pass: pass.into(),
        }
    }

    async fn listener() -> (TcpListener, HostPort) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = HostPort::try_from(listener.local_addr().unwrap()).unwrap();
        (listener, addr)
    }

    async fn read_head(stream: &mut TcpStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).await.unwrap() == 1 {
            head.push(byte[0]);
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    async fn read_vec(stream: &mut TcpStream, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await.unwrap();
        buf
    }

    #[test]
    fn labels_never_show_credentials() {
        let addr = HostPort::parse("[::1]:1080").unwrap();
        let route = Route::proxy(
            ProxyKind::Socks5,
            &addr,
            Some(&creds("us er", "p@ss:w%41rd")),
        );
        let Route::Proxy { url } = &route else {
            panic!("proxy route expected")
        };
        assert_eq!(
            url.as_str(),
            "socks5h://us%20er:p%40ss%3Aw%2541rd@[::1]:1080"
        );
        assert_eq!(route.label(), "socks5h://[::1]:1080");
        assert_eq!(format!("{route:?}"), "Route(socks5h://[::1]:1080)");
        let http = Route::proxy(
            ProxyKind::Http,
            &HostPort::parse("127.0.0.1:10809").unwrap(),
            None,
        );
        assert_eq!(http.label(), "http://127.0.0.1:10809");
        assert_eq!(Route::Direct.label(), "direct");
        assert!(client_for(&Route::Direct, Duration::from_secs(5)).is_ok());
    }

    /// Every name `HostPort` accepts forms a proxy URL (an undecodable `xn--` label used to
    /// panic `Route::proxy` for HTTP: the URL parser runs IDNA on special schemes only).
    #[test]
    fn accepted_names_form_proxy_urls() {
        for s in ["xn--d1acufc.xn--p1ai:1080", "a_b.example:8080"] {
            let addr = HostPort::parse(s).unwrap();
            for kind in [ProxyKind::Socks5, ProxyKind::Http] {
                let label = Route::proxy(kind, &addr, None).label();
                assert!(label.ends_with(s), "{label}");
            }
        }
    }

    /// The SOCKS route authenticates with the decoded credentials and lets the proxy resolve.
    #[tokio::test]
    async fn socks_route_end_to_end() {
        let (listener, addr) = listener().await;
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let head = read_vec(&mut s, 2).await;
            let methods = read_vec(&mut s, head[1] as usize).await;
            assert!(methods.contains(&2));
            s.write_all(&[5, 2]).await.unwrap();
            let ver_ulen = read_vec(&mut s, 2).await;
            let user = read_vec(&mut s, ver_ulen[1] as usize).await;
            let plen = read_vec(&mut s, 1).await;
            let pass = read_vec(&mut s, plen[0] as usize).await;
            s.write_all(&[1, 0]).await.unwrap();
            let request = read_vec(&mut s, 5).await;
            assert_eq!(&request[..4], &[5, 1, 0, 3], "CONNECT by name (socks5h)");
            let target = read_vec(&mut s, request[4] as usize + 2).await;
            s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            let http_head = read_head(&mut s).await;
            s.write_all(OK).await.unwrap();
            (user, pass, target, http_head)
        });
        let route = Route::proxy(
            ProxyKind::Socks5,
            &addr,
            Some(&creds("us er", "p@ss:w%41rd")),
        );
        let client = client_for(&route, Duration::from_secs(5)).unwrap();
        let body = client.get("http://example.test/").send().await.unwrap();
        assert_eq!(body.text().await.unwrap(), "ok");
        let (user, pass, target, http_head) = server.await.unwrap();
        assert_eq!(user, b"us er");
        assert_eq!(pass, b"p@ss:w%41rd");
        assert_eq!(target, b"example.test\x00\x50");
        assert!(http_head.starts_with("GET / HTTP/1.1"), "{http_head}");
    }

    #[tokio::test]
    async fn http_route_sends_proxy_authorization() {
        let (listener, addr) = listener().await;
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let head = read_head(&mut s).await;
            s.write_all(OK).await.unwrap();
            head.to_ascii_lowercase()
        });
        let route = Route::proxy(ProxyKind::Http, &addr, Some(&creds("u", "p@ss")));
        let client = client_for(&route, Duration::from_secs(5)).unwrap();
        let body = client.get("http://example.test/").send().await.unwrap();
        assert_eq!(body.text().await.unwrap(), "ok");
        let head = server.await.unwrap();
        assert!(
            head.starts_with("get http://example.test/ http/1.1"),
            "{head}"
        );
        // base64("u:p@ss")
        assert!(
            head.contains("proxy-authorization: basic dtpwqhnz"),
            "{head}"
        );
    }
}
