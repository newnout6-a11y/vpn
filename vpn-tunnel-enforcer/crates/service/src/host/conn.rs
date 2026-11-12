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
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use vpnte_base::ErrorKind;
use vpnte_base::types::KillSwitchLevel;
use vpnte_tunnel::api::StopOptions;

use super::{HELLO_TIMEOUT, Host};
use crate::pipe::{ClientInfo, ident};
use crate::proto::frame::{self, FrameError};
use crate::proto::{
    ClientFrame, ErrorCode, Event, PROTOCOL, Reply, Request, ServerFrame, StatusWire,
    TunnelEventWire, WireError, negotiate,
};

type Pending = Pin<Box<dyn Future<Output = (u64, Result<Reply, WireError>)> + Send>>;

/// What the reader task hands over.
enum Incoming {
    Frame(ClientFrame),
    /// Undecodable; `Some(id)` when the id could still be read.
    Bad(Option<u64>),
}

pub(super) async fn run(
    host: Arc<Host>,
    id: u64,
    mut pipe: NamedPipeServer,
    cancel: CancellationToken,
) {
    let body = match tokio::time::timeout(HELLO_TIMEOUT, frame::read_frame(&mut pipe)).await {
        Ok(Ok(body)) => body,
        Ok(Err(err)) => return tracing::debug!(error = %err, "connection closed before hello"),
        Err(_) => return tracing::debug!("no hello in time"),
    };
    let hello = match frame::decode::<ClientFrame>(&body) {
        Ok(ClientFrame {
            id: fid,
            request: Request::Hello(hello),
        }) => (fid, hello),
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
    if !host.claim(id) {
        return refuse(pipe, fid, ErrorCode::Busy).await;
    }
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
    // The session belongs to this connection: in-flight work is cancelled, then the tunnel stops.
    cancel.cancel();
    let keep_block = host.deps.kill_switch.level() == KillSwitchLevel::Strict;
    let receipt = host
        .deps
        .runtime
        .stop(StopOptions {
            preserve_protection: keep_block,
            preserve_last: false,
        })
        .await;
    tracing::info!(ok = receipt.ok, keep_block, "client gone; session stopped");
    host.release(id);
}

/// Answers the first request with `code`, then waits briefly for the client to read it and close
/// (closing at once could drop the answer before the client read it).
async fn refuse(mut pipe: NamedPipeServer, id: u64, code: ErrorCode) {
    let (kind, key) = match code {
        ErrorCode::Busy => (ErrorKind::Conflict, "service.pipe.busy"),
        ErrorCode::Version => (ErrorKind::Validation, "service.pipe.version"),
        ErrorCode::HelloFirst => (ErrorKind::Validation, "service.pipe.helloFirst"),
        _ => (ErrorKind::Validation, "service.pipe.badRequest"),
    };
    let failed = ServerFrame::Failed {
        id,
        error: WireError::new(code, kind, key),
    };
    if frame::write_frame(&mut pipe, &failed).await.is_ok() {
        let mut byte = [0u8; 1];
        let _ = tokio::time::timeout(Duration::from_secs(2), pipe.read(&mut byte)).await;
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
    let wire = StatusWire::from(&*status.borrow_and_update());
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

type Status = tokio::sync::watch::Receiver<vpnte_tunnel::api::TunStatus>;

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
    let mut status = runtime.status();
    let mut events = runtime.subscribe();
    let mut notices = host.deps.kill_switch.notices();
    let (mut status_open, mut events_open, mut notices_open) = (true, true, true);
    let mut incoming = spawn_reader(reader);
    let mut pending: FuturesUnordered<Pending> = FuturesUnordered::new();
    if !push_status(&mut writer, &mut status).await {
        return;
    }
    loop {
        let ok = tokio::select! {
            () = cancel.cancelled() => false,
            msg = incoming.recv() => match msg {
                Some(Incoming::Frame(f)) => {
                    let (host, client, cancel) = (host.clone(), client.clone(), cancel.clone());
                    pending.push(Box::pin(async move {
                        (f.id, host.handle(&client, f.request, &cancel).await)
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
