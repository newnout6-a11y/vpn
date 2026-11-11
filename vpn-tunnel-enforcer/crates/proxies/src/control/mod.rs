//! Local control API of the external proxies: a small HTTP/1.1 server on `127.0.0.1:17873`
//! (exclusive bind, ephemeral fallback) that serves the old wire-compatible endpoints over
//! [`ProxyOps`], guarded by a per-start bearer token. The token file and the endpoint file are
//! written to the data root, where the `vpnte_proxy` CLI and automation clients find them.
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt as _;
use serde_json::Map;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use vpnte_base::{AppError, ErrorKind, Msg};

use crate::model::{ControlError, ProxyOps};
use crate::slot::{CONTROL_HOST, CONTROL_PORT, loopback_url};

pub mod client;
mod files;
mod http;
mod router;
#[cfg(test)]
mod tests;

pub use files::{ControlToken, ENDPOINT_FILE, Endpoint, TOKEN_FILE, read_token};
pub use router::{TOKEN_HEADER, is_mutation_path, is_trusted_host};

use http::{Conn, ReadError, Response};
use router::{Gate, Shared};

/// Server-side override of the control port. When set, a busy port is fatal (no fallback).
pub const ENV_CONTROL_PORT: &str = "VPNTE_CONTROL_PORT";
/// Connections served at the same time; more wait in the accept queue.
const MAX_CONNECTIONS: usize = 64;
/// Time a client gets to send its request (head and body).
const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Time a client gets to take the answer.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Where and how the control server listens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlConfig {
    /// Directory of the token and endpoint files (the data root).
    pub dir: PathBuf,
    /// Preferred port.
    pub port: u16,
    /// Bind an ephemeral port when `port` is busy (only when the port was not chosen explicitly).
    pub fallback: bool,
}

impl ControlConfig {
    /// Port 17873 with the ephemeral fallback, unless `VPNTE_CONTROL_PORT` names a port.
    pub fn from_env(dir: impl Into<PathBuf>) -> Self {
        Self::with_override(dir.into(), std::env::var(ENV_CONTROL_PORT).ok().as_deref())
    }

    fn with_override(dir: PathBuf, raw: Option<&str>) -> Self {
        let raw = raw.map(str::trim).filter(|r| !r.is_empty());
        match raw.map(|r| r.parse::<u16>()) {
            Some(Ok(port)) if port != 0 => Self {
                dir,
                port,
                fallback: false,
            },
            other => {
                // The old app bound 17873 without a fallback here; an unusable override is
                // treated as unset instead, so the API still comes up.
                if other.is_some() {
                    tracing::warn!(
                        value = raw,
                        "invalid {ENV_CONTROL_PORT}, using {CONTROL_PORT}"
                    );
                }
                Self {
                    dir,
                    port: CONTROL_PORT,
                    fallback: true,
                }
            }
        }
    }
}

/// Why the control server did not start (the app logs it and runs without the API).
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("control token write failed: {0}")]
    Token(#[source] io::Error),
    #[error("control listener bind failed on port {port}: {source}")]
    Bind {
        port: u16,
        #[source]
        source: io::Error,
    },
}

impl From<ServeError> for AppError {
    fn from(err: ServeError) -> Self {
        let msg = match &err {
            ServeError::Token(_) => Msg::new("proxies.control.tokenFailed"),
            ServeError::Bind { port, .. } => {
                Msg::new("proxies.control.bindFailed").arg("port", port)
            }
        };
        AppError::msg(ErrorKind::Internal, msg).with_source(err)
    }
}

/// A running control server. It serves until `cancel` (given to [`ControlServer::start`]) fires.
#[derive(Debug)]
pub struct ControlServer {
    port: u16,
    token_file: PathBuf,
    endpoint_file: Option<PathBuf>,
    task: tokio::task::JoinHandle<()>,
}

impl ControlServer {
    /// Writes a fresh token file, binds the listener (exclusively; an ephemeral port when the
    /// preferred one is busy and the fallback is allowed), reports the bound port to `ops`,
    /// writes the endpoint file and starts serving.
    pub async fn start(
        ops: Arc<dyn ProxyOps>,
        config: ControlConfig,
        cancel: CancellationToken,
    ) -> Result<Self, ServeError> {
        let token = ControlToken::generate().map_err(ServeError::Token)?;
        let token_file = files::write_token(&config.dir, &token).map_err(|e| {
            tracing::warn!(error = %e, "control token write failed");
            ServeError::Token(e)
        })?;
        let listener = bind(&config).map_err(|e| {
            tracing::warn!(port = config.port, error = %e, "control listener bind failed");
            e
        })?;
        let port = listener
            .local_addr()
            .map_err(|source| ServeError::Bind {
                port: config.port,
                source,
            })?
            .port();
        ops.set_control_port(port);
        let endpoint_file = files::write_endpoint(&config.dir, &Endpoint::new(&config.dir, port))
            .inspect_err(|e| tracing::warn!(error = %e, "failed to write control endpoint file"))
            .ok();
        tracing::info!(
            host = CONTROL_HOST,
            port,
            token_file = %token_file.display(),
            endpoint_file = ?endpoint_file.as_deref().map(Path::display),
            "control server listening"
        );
        let shared = Arc::new(Shared::new(ops, token, port));
        let task = tokio::spawn(serve(listener, shared, cancel));
        Ok(Self {
            port,
            token_file,
            endpoint_file,
            task,
        })
    }

    /// The port actually bound.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// `http://127.0.0.1:<port>`.
    pub fn url(&self) -> String {
        loopback_url(self.port)
    }

    /// The token file written at start.
    pub fn token_file(&self) -> &Path {
        &self.token_file
    }

    /// The endpoint file, unless writing it failed (the server serves anyway).
    pub fn endpoint_file(&self) -> Option<&Path> {
        self.endpoint_file.as_deref()
    }

    /// Waits until the accept loop has stopped (after the cancellation token fired).
    pub async fn join(self) {
        let _ = self.task.await;
    }
}

/// Exclusive bind of the preferred port, else (when allowed) of an ephemeral one.
fn bind(config: &ControlConfig) -> Result<TcpListener, ServeError> {
    let fail = |port, source| ServeError::Bind { port, source };
    match bind_exclusive(config.port) {
        Ok(listener) => Ok(listener),
        // WSAEACCES also means "taken": an exclusive holder or a reserved port range.
        Err(e)
            if config.fallback
                && matches!(
                    e.kind(),
                    io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                ) =>
        {
            tracing::warn!(
                host = CONTROL_HOST,
                port = config.port,
                "control port is busy, falling back to an ephemeral port"
            );
            bind_exclusive(0).map_err(|e| fail(config.port, e))
        }
        Err(e) => Err(fail(config.port, e)),
    }
}

/// `SO_EXCLUSIVEADDRUSE` keeps another process from co-binding the port with `SO_REUSEADDR`
/// and taking over the API (B-23).
fn bind_exclusive(port: u16) -> io::Result<TcpListener> {
    use std::os::windows::io::AsRawSocket as _;
    use windows::Win32::Networking::WinSock::{
        SO_EXCLUSIVEADDRUSE, SOCKET, SOL_SOCKET, setsockopt,
    };

    let socket = TcpSocket::new_v4()?;
    let on = 1i32.to_ne_bytes();
    // SAFETY: the raw socket stays valid while `socket` lives; the option value is a BOOL.
    let rc = unsafe {
        setsockopt(
            SOCKET(socket.as_raw_socket() as usize),
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            Some(&on),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    socket.bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    socket.listen(128)
}

/// Accept loop: one task per connection, at most [`MAX_CONNECTIONS`] at a time.
async fn serve(listener: TcpListener, shared: Arc<Shared>, cancel: CancellationToken) {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let permit = tokio::select! {
            () = cancel.cancelled() => break,
            permit = permits.clone().acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => break,
            },
        };
        let stream = tokio::select! {
            () = cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => stream,
                Err(e) => {
                    // Typically a client that reset before the accept; keep serving.
                    tracing::debug!(error = %e, "control accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
        };
        let shared = shared.clone();
        tokio::spawn(async move {
            connection(stream, &shared).await;
            drop(permit);
        });
    }
    tracing::info!(port = shared.port, "control server stopped");
}

/// One request and its answer. Reading is bounded by [`READ_TIMEOUT`]; the operation itself
/// is not (a rotate or a prewarm legitimately takes many seconds).
async fn connection(stream: TcpStream, shared: &Shared) {
    let mut conn = Conn::new(stream);
    let head = match tokio::time::timeout(READ_TIMEOUT, conn.read_head()).await {
        Ok(Ok(head)) => head,
        Ok(Err(ReadError::Malformed)) => {
            let _ = conn.respond(&Response::json(400, &bad_request())).await;
            return;
        }
        _ => return,
    };
    let response = match router::gate(shared, &head) {
        Gate::Respond(response) => response,
        Gate::Proceed(route) => {
            match tokio::time::timeout(READ_TIMEOUT, conn.read_body(&head)).await {
                Ok(Ok(raw)) => {
                    let body = if route.post {
                        router::parse_body(&raw)
                    } else {
                        Ok(Map::new())
                    };
                    match body {
                        Ok(body) => run(shared, &route, &body).await,
                        Err(err) => router::error_response(&route.path, &err, route.text),
                    }
                }
                Ok(Err(ReadError::TooLarge)) => too_large(route.text),
                Ok(Err(ReadError::Malformed)) => Response::json(400, &bad_request()),
                _ => return,
            }
        }
    };
    let _ = tokio::time::timeout(WRITE_TIMEOUT, conn.respond(&response)).await;
}

/// Runs the endpoint; a panic in an operation becomes a 500 instead of a dropped connection.
async fn run(
    shared: &Shared,
    route: &router::Route,
    body: &Map<String, serde_json::Value>,
) -> Response {
    match AssertUnwindSafe(router::dispatch(shared, route, body))
        .catch_unwind()
        .await
    {
        Ok(response) => response,
        Err(_) => {
            tracing::error!(path = %route.path, "control request panicked");
            Response::json(
                500,
                &ControlError::new("external-proxy-error", "internal error"),
            )
        }
    }
}

fn bad_request() -> ControlError {
    ControlError::new("bad-request", "malformed HTTP request")
}

/// Body over 64 KiB (the old server cut the socket and could leave the request hanging, B-13).
fn too_large(text: bool) -> Response {
    let detail = "request body exceeds 64 KiB";
    if text {
        Response::text(413, detail)
    } else {
        Response::json(413, &ControlError::new("payload-too-large", detail))
    }
}
