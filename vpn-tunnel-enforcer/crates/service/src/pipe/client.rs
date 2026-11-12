//! The app's end of the pipe: connect, verify who serves it, request / reply, pushed events.
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use vpnte_base::{AppError, ErrorKind, Msg};

use crate::proto::frame::{self, FrameError};
use crate::proto::{ClientFrame, Event, Hello, PROTOCOL, Reply, Request, ServerFrame, WireError};

/// `ERROR_ACCESS_DENIED`: the pipe's DACL does not admit this account.
const ERROR_ACCESS_DENIED: i32 = 5;
/// `ERROR_PIPE_BUSY`: every instance is taken for a moment; retry.
const ERROR_PIPE_BUSY: i32 = 231;

/// Who must serve the pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerCheck {
    /// The server process runs this image (the installed service exe from the SCM).
    Image(PathBuf),
    /// No check: a private test pipe.
    Any,
}

/// A failed call.
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    /// The pipe broke or carried something undecodable.
    #[error("pipe: {0}")]
    Pipe(AppError),
    /// The service refused or failed the request.
    #[error("service: {:?}", .0.code)]
    Service(WireError),
}

/// A connected client. Cancel-safe: a `call` or `next_event` dropped half-way (raced in a
/// `select!`, or a call abandoned for a `Stop`) loses nothing, because the bytes read so far and
/// the rest of a request being written stay here; the abandoned reply is dropped when it comes
/// (review service-a12).
pub struct Client {
    reader: ReadHalf<NamedPipeClient>,
    writer: WriteHalf<NamedPipeClient>,
    next_id: u64,
    events: VecDeque<Event>,
    /// Read, not yet a whole frame.
    inbox: Vec<u8>,
    /// Not yet written: the rest of a request whose call was dropped goes out before the next.
    outbox: Vec<u8>,
}

fn failure(key: &'static str, err: impl std::fmt::Display) -> AppError {
    tracing::debug!(error = %err, key, "service pipe failed");
    AppError::msg(ErrorKind::Network, Msg::new(key))
}

/// Why opening the pipe failed: no service, not for this account, or no answer in time.
fn open_failed(err: &std::io::Error) -> AppError {
    let key = match err.raw_os_error() {
        Some(ERROR_ACCESS_DENIED) => "service.pipe.denied",
        Some(ERROR_PIPE_BUSY) => "service.pipe.noAnswer",
        _ => "service.pipe.unavailable",
    };
    failure(key, err)
}

/// A broken connection, or a frame from the service this build cannot read (review service-b7).
fn read_failed(err: FrameError) -> CallError {
    let key = match err {
        FrameError::Closed | FrameError::Io(_) => "service.pipe.lost",
        FrameError::Length(_) | FrameError::Json(_) => "service.pipe.badReply",
    };
    CallError::Pipe(failure(key, err))
}

impl Client {
    /// Opens `name` (retrying a busy pipe until `timeout`) and checks the server process.
    pub async fn connect(
        name: &str,
        check: &ServerCheck,
        timeout: Duration,
    ) -> Result<Self, AppError> {
        let deadline = Instant::now() + timeout;
        let pipe = loop {
            match ClientOptions::new().open(name) {
                Ok(pipe) => break pipe,
                Err(e)
                    if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => return Err(open_failed(&e)),
            }
        };
        if let ServerCheck::Image(expected) = check {
            verify_server(&pipe, expected)?;
        }
        let (reader, writer) = tokio::io::split(pipe);
        Ok(Self {
            reader,
            writer,
            next_id: 1,
            events: VecDeque::new(),
            inbox: Vec::new(),
            outbox: Vec::new(),
        })
    }

    /// `Hello` with this build's version; returns the negotiated version and the service's.
    pub async fn hello(&mut self, app_version: &str) -> Result<(u32, String), CallError> {
        let hello = Request::Hello(Hello {
            protocol: PROTOCOL,
            app_version: app_version.to_owned(),
        });
        match self.call(hello).await? {
            Reply::Welcome {
                protocol,
                service_version,
            } => Ok((protocol, service_version)),
            other => Err(CallError::Pipe(unexpected(&other))),
        }
    }

    /// Sends `request` and waits for its answer; events arriving meanwhile are queued.
    pub async fn call(&mut self, request: Request) -> Result<Reply, CallError> {
        let id = self.next_id;
        self.next_id += 1;
        let bytes = frame::encode(&ClientFrame { id, request })
            .map_err(|e| CallError::Pipe(failure("service.pipe.tooLarge", e)))?;
        self.outbox.extend_from_slice(&bytes);
        self.send().await?;
        loop {
            match self.read().await? {
                ServerFrame::Reply { id: got, reply } if got == id => return Ok(*reply),
                ServerFrame::Failed { id: got, error } if got == id => {
                    return Err(CallError::Service(error));
                }
                ServerFrame::Event { event } => self.events.push_back(*event),
                other => tracing::warn!(?other, "answer to another request; dropped"),
            }
        }
    }

    /// The next pushed event (queued ones first).
    pub async fn next_event(&mut self) -> Result<Event, CallError> {
        if let Some(event) = self.events.pop_front() {
            return Ok(event);
        }
        loop {
            if let ServerFrame::Event { event } = self.read().await? {
                return Ok(*event);
            }
        }
    }

    /// Writes the outbox; each `write` is cancel-safe, and what it wrote leaves the outbox.
    async fn send(&mut self) -> Result<(), CallError> {
        while !self.outbox.is_empty() {
            match self.writer.write(&self.outbox).await {
                Ok(0) => return Err(read_failed(FrameError::Closed)),
                Ok(n) => drop(self.outbox.drain(..n)),
                Err(e) => return Err(read_failed(FrameError::Io(e))),
            }
        }
        Ok(())
    }

    /// The next frame; each `read` is cancel-safe, and what it read stays in the inbox.
    async fn read(&mut self) -> Result<ServerFrame, CallError> {
        let mut chunk = [0u8; 8192];
        loop {
            if let Some(body) = frame::take_frame(&mut self.inbox).map_err(read_failed)? {
                return frame::decode(&body).map_err(read_failed);
            }
            match self.reader.read(&mut chunk).await {
                Ok(0) => return Err(read_failed(FrameError::Closed)),
                Ok(n) => self.inbox.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(read_failed(FrameError::Io(e))),
            }
        }
    }
}

fn unexpected(reply: &Reply) -> AppError {
    tracing::warn!(?reply, "unexpected reply");
    AppError::msg(ErrorKind::Internal, Msg::new("service.pipe.badRequest"))
}

/// The server end belongs to a process running `expected` (Windows-style case-insensitive path
/// comparison): a pipe someone else created under our name is refused before anything is sent.
fn verify_server(pipe: &NamedPipeClient, expected: &Path) -> Result<(), AppError> {
    let image = super::ident::server_pid(pipe)
        .ok()
        .and_then(|pid| vpnte_winnet::process::image_path(pid).ok());
    let same = image.as_deref().is_some_and(|got| {
        got.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&expected.as_os_str().to_string_lossy())
    });
    if same {
        Ok(())
    } else {
        tracing::warn!(?image, "the pipe's server is not the installed service");
        Err(AppError::msg(
            ErrorKind::Permission,
            Msg::new("service.pipe.notOurs"),
        ))
    }
}
