//! One pipe connection: `Hello` first, then (for the controlling client) concurrent requests,
//! pushed events, and the clean stop when the client goes away.
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use tokio::io::{AsyncReadExt, AsyncWrite};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::sync::{OwnedSemaphorePermit, broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use vpnte_base::ErrorKind;

use super::{HELLO_TIMEOUT, Host};
use crate::pipe::{ClientInfo, ident};
use crate::proto::frame::{self, FrameError};
use crate::proto::{
    ClientFrame, ErrorCode, Event, ExitWire, PROTOCOL, Reply, Request, ServerFrame, StatusWire,
    TunnelEventWire, WireError, negotiate,
};

type Pending = Pin<Box<dyn Future<Output = (u64, Result<Reply, WireError>)> + Send>>;

/// What the reader task hands over.
enum Incoming {
    Frame(ClientFrame),
    /// Undecodable; `Some(id)` when the id could still be read.
    Bad(Option<u64>),
}

/// Requests of the controlling client in flight at once; with more, its frames are not read until
/// one finishes (review service-a4).
pub(super) const MAX_PENDING: usize = 32;

pub(super) async fn run(
    host: Arc<Host>,
    id: u64,
    mut pipe: NamedPipeServer,
    unidentified: OwnedSemaphorePermit,
    cancel: CancellationToken,
) {
    let first = frame::read_frame_max(&mut pipe, frame::FIRST_FRAME_MAX);
    let body = match tokio::time::timeout(HELLO_TIMEOUT, first).await {
        Ok(Ok(body)) => body,
        Ok(Err(err)) => return tracing::debug!(error = %err, "connection closed before hello"),
        Err(_) => return tracing::debug!("no hello in time"),
    };
    let hello = match frame::decode::<ClientFrame>(&body) {
        Ok(ClientFrame {
            id: fid,
            request: Request::Hello(hello),
        }) => (fid, hello),
        Ok(ClientFrame {
            id: fid,
            request: Request::ForgetMe,
        }) => return forget(&host, pipe, fid).await,
        Ok(other) => return refuse(pipe, other.id, ErrorCode::HelloFirst).await,
        Err(_) => match frame::request_id(&body) {
            Some(fid) => return refuse(pipe, fid, ErrorCode::BadRequest).await,
            None => return,
        },
    };
    let (fid, hello) = hello;
    // The version string only reaches the log, but bounded like every other text.
    if crate::validate::text(&hello.app_version, "appVersion").is_err() {
        return refuse(pipe, fid, ErrorCode::BadRequest).await;
    }
    let client = match ident::client(&pipe) {
        Ok(client) => client,
        Err(err) => return tracing::warn!(error = %err, "client not identifiable; dropped"),
    };
    tracing::info!(pid = client.pid, session = client.session, image = ?client.image, app = %hello.app_version, "client connected");
    if !(host.deps.check)(&client) {
        return refuse(pipe, fid, ErrorCode::Refused).await;
    }
    let Some(protocol) = negotiate(hello.protocol, PROTOCOL) else {
        return refuse(pipe, fid, ErrorCode::Version).await;
    };
    if let Err(same_user) = host.claim(id, &client.user) {
        // The user's own app reconnecting while its last connection still stops is told so,
        // not that another Windows user has Tunnel mode (review service-b7).
        let key = if same_user {
            "service.pipe.busySelf"
        } else {
            "service.pipe.busy"
        };
        return refuse_with(pipe, fid, ErrorCode::Busy, key).await;
    }
    drop(unidentified);
    host.admit(&client.user).await;
    if let Err(err) = host.deps.users.add(&client.user) {
        tracing::warn!(error = %err, "users list not saved");
    }
    let welcome = ServerFrame::Reply {
        id: fid,
        reply: Box::new(Reply::Welcome {
            protocol,
            service_version: host.deps.service_version.clone(),
        }),
    };
    let (reader, mut writer) = tokio::io::split(pipe);
    if frame::write_frame(&mut writer, &welcome).await.is_ok() {
        serve(&host, &client, reader, writer, cancel.clone()).await;
    }
    // Gone without a stop (Quit and Disconnect send one): a start or switch in flight is
    // cancelled, kill-switch changes already asked for finish, and a running session stays for
    // its user's app to take over at its next start (owner question 23).
    cancel.cancel();
    drop(host.settled().await);
    let running = host.deps.runtime.status().borrow().running;
    tracing::info!(running, "client gone; the session stays as it is");
    host.release(id);
}

/// Answers the first request with `code`, then waits briefly for the client to read it and close
/// (closing at once could drop the answer before the client read it).
async fn refuse(pipe: NamedPipeServer, id: u64, code: ErrorCode) {
    let key = match code {
        ErrorCode::Busy => "service.pipe.busy",
        ErrorCode::Version => "service.pipe.version",
        ErrorCode::HelloFirst => "service.pipe.helloFirst",
        _ => "service.pipe.badRequest",
    };
    refuse_with(pipe, id, code, key).await;
}

async fn refuse_with(pipe: NamedPipeServer, id: u64, code: ErrorCode, key: &'static str) {
    let kind = match code {
        ErrorCode::Busy => ErrorKind::Conflict,
        _ => ErrorKind::Validation,
    };
    let failed = ServerFrame::Failed {
        id,
        error: WireError::new(code, kind, key),
    };
    answer_and_close(pipe, &failed).await;
}

async fn answer_and_close(mut pipe: NamedPipeServer, frame: &ServerFrame) {
    if frame::write_frame(&mut pipe, frame).await.is_ok() {
        let mut byte = [0u8; 1];
        let _ = tokio::time::timeout(Duration::from_secs(2), pipe.read(&mut byte)).await;
    }
}

/// `ForgetMe` as the first request: answered for any user without the controller slot (it does
/// not touch the session), so an uninstaller is never turned away (review service-a7).
async fn forget(host: &Arc<Host>, pipe: NamedPipeServer, id: u64) {
    let client = match ident::client(&pipe) {
        Ok(client) => client,
        Err(err) => return tracing::warn!(error = %err, "client not identifiable; dropped"),
    };
    if !(host.deps.check)(&client) {
        return refuse(pipe, id, ErrorCode::Refused).await;
    }
    let (frame, removing) = match host.forget(&client).await {
        Ok(reply) => {
            let removing = reply == Reply::Done { removing: true };
            let reply = Box::new(reply);
            (ServerFrame::Reply { id, reply }, removing)
        }
        Err(error) => (ServerFrame::Failed { id, error }, false),
    };
    answer_and_close(pipe, &frame).await;
    if removing {
        (host.deps.on_last_user)();
    }
}

/// Reads frames on its own task (a partial read must never be lost to a `select!`).
fn spawn_reader(mut reader: tokio::io::ReadHalf<NamedPipeServer>) -> mpsc::Receiver<Incoming> {
    let (tx, rx) = mpsc::channel(16);
    tokio::spawn(async move {
        loop {
            let incoming = match frame::read_frame(&mut reader).await {
                Ok(body) => match frame::decode(&body) {
                    Ok(frame) => Incoming::Frame(frame),
                    Err(_) => Incoming::Bad(frame::request_id(&body)),
                },
                Err(FrameError::Closed) => break,
                Err(err) => {
                    tracing::debug!(error = %err, "client read failed");
                    break;
                }
            };
            if tx.send(incoming).await.is_err() {
                break;
            }
        }
    });
    rx
}

async fn send<W: AsyncWrite + Unpin>(w: &mut W, frame: &ServerFrame) -> bool {
    frame::write_frame(w, frame).await.is_ok()
}

fn event(event: Event) -> ServerFrame {
    ServerFrame::Event {
        event: Box::new(event),
    }
}

/// Pushes the status watch's current value (marks it seen).
async fn push_status<W: AsyncWrite + Unpin>(w: &mut W, status: &mut Status) -> bool {
    let wire = status.take();
    send(w, &event(Event::Status(Box::new(wire)))).await
}

/// Pushes a changed status first: the runtime updates its watch before the matching event.
async fn push_event<W: AsyncWrite + Unpin>(
    w: &mut W,
    status: &mut Status,
    e: &vpnte_tunnel::api::TunnelEvent,
) -> bool {
    if status.has_changed().unwrap_or(false) && !push_status(w, status).await {
        return false;
    }
    send(w, &event(Event::Tunnel(TunnelEventWire::from(e)))).await
}

/// Sends every event already queued (an operation's events come before its reply).
async fn drain<W: AsyncWrite + Unpin>(
    w: &mut W,
    status: &mut Status,
    events: &mut broadcast::Receiver<vpnte_tunnel::api::TunnelEvent>,
) -> bool {
    loop {
        match events.try_recv() {
            Ok(e) => {
                if !push_event(w, status, &e).await {
                    return false;
                }
            }
            Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
            Err(_) => break,
        }
    }
    !status.has_changed().unwrap_or(false) || push_status(w, status).await
}

/// The runtime's status as this connection pushes it: with the last exit and fault when the
/// session is this client's (review service-b2), so the app reads them with the status of a crash.
struct Status {
    rx: tokio::sync::watch::Receiver<vpnte_tunnel::api::TunStatus>,
    host: Arc<Host>,
    user: String,
}

impl Status {
    fn has_changed(&self) -> Result<bool, tokio::sync::watch::error::RecvError> {
        self.rx.has_changed()
    }

    async fn changed(&mut self) -> Result<(), tokio::sync::watch::error::RecvError> {
        self.rx.changed().await
    }

    fn take(&mut self) -> StatusWire {
        let mut wire = StatusWire::from(&*self.rx.borrow_and_update());
        if self.host.session_user.lock().as_deref() == Some(self.user.as_str()) {
            let runtime = &self.host.deps.runtime;
            wire.last_exit = runtime.last_exit().as_ref().map(ExitWire::from);
            wire.recent_fault = runtime.recent_fault();
        }
        wire
    }
}

/// The controlling client's loop: requests run concurrently (a stop may cancel a start in
/// flight), replies and events share this one writer.
async fn serve<W: AsyncWrite + Unpin>(
    host: &Arc<Host>,
    client: &ClientInfo,
    reader: tokio::io::ReadHalf<NamedPipeServer>,
    mut writer: W,
    cancel: CancellationToken,
) {
    let runtime = host.deps.runtime.clone();
    let mut status = Status {
        rx: runtime.status(),
        host: host.clone(),
        user: client.user.clone(),
    };
    let mut events = runtime.subscribe();
    let mut notices = host.deps.kill_switch.notices();
    let (mut status_open, mut events_open, mut notices_open) = (true, true, true);
    let mut incoming = spawn_reader(reader);
    let mut pending: FuturesUnordered<Pending> = FuturesUnordered::new();
    // Start-like requests run under the token of the stops sent so far: a `Stop` cancels every
    // one sent before it, also one still applying its kill-switch settings (review service-a2).
    let mut starts = cancel.child_token();
    if !push_status(&mut writer, &mut status).await {
        return;
    }
    loop {
        let ok = tokio::select! {
            () = cancel.cancelled() => false,
            msg = incoming.recv(), if pending.len() < MAX_PENDING => match msg {
                Some(Incoming::Frame(f)) => {
                    if matches!(f.request, Request::Stop(_)) {
                        starts.cancel();
                        starts = cancel.child_token();
                    }
                    let (host, client, token) = (host.clone(), client.clone(), starts.clone());
                    pending.push(Box::pin(async move {
                        (f.id, host.handle(&client, f.request, &token).await)
                    }));
                    true
                }
                Some(Incoming::Bad(Some(id))) => {
                    let error = WireError::new(
                        ErrorCode::BadRequest,
                        ErrorKind::Validation,
                        "service.pipe.badRequest",
                    );
                    send(&mut writer, &ServerFrame::Failed { id, error }).await
                }
                // Not even an id: not our protocol.
                Some(Incoming::Bad(None)) | None => false,
            },
            Some((id, result)) = pending.next(), if !pending.is_empty() => {
                let removing = matches!(result, Ok(Reply::Done { removing: true }));
                let frame = match result {
                    Ok(reply) => ServerFrame::Reply { id, reply: Box::new(reply) },
                    Err(error) => ServerFrame::Failed { id, error },
                };
                let sent = drain(&mut writer, &mut status, &mut events).await
                    && send(&mut writer, &frame).await;
                if removing {
                    (host.deps.on_last_user)();
                }
                sent
            }
            changed = status.changed(), if status_open => match changed {
                Ok(()) => push_status(&mut writer, &mut status).await,
                Err(_) => {
                    status_open = false;
                    true
                }
            },
            e = events.recv(), if events_open => match e {
                Ok(e) => push_event(&mut writer, &mut status, &e).await,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(missed = n, "event stream lagged; status resent");
                    push_status(&mut writer, &mut status).await
                }
                Err(broadcast::error::RecvError::Closed) => {
                    events_open = false;
                    true
                }
            },
            n = notices.recv(), if notices_open => match n {
                Ok(n) => send(&mut writer, &event(Event::Notice(n))).await,
                Err(broadcast::error::RecvError::Lagged(_)) => true,
                Err(broadcast::error::RecvError::Closed) => {
                    notices_open = false;
                    true
                }
            },
        };
        if !ok {
            break;
        }
    }
}
