//! The app's end of the pipe: connect, verify who serves it, request / reply, pushed events.
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use vpnte_base::{AppError, ErrorKind, Msg};

use crate::proto::frame::{self, FrameError};
use crate::proto::{ClientFrame, Event, Hello, PROTOCOL, Reply, Request, ServerFrame, WireError};

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

/// A connected client.
pub struct Client {
    reader: ReadHalf<NamedPipeClient>,
    writer: WriteHalf<NamedPipeClient>,
    next_id: u64,
    events: VecDeque<Event>,
}

fn unavailable(err: impl std::fmt::Display) -> AppError {
    tracing::debug!(error = %err, "service pipe unavailable");
    AppError::msg(ErrorKind::Network, Msg::new("service.pipe.unavailable"))
}

fn pipe_error(err: FrameError) -> CallError {
    CallError::Pipe(unavailable(err))
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
                Err(e) => return Err(unavailable(e)),
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
        frame::write_frame(&mut self.writer, &ClientFrame { id, request })
            .await
            .map_err(pipe_error)?;
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

    async fn read(&mut self) -> Result<ServerFrame, CallError> {
        let body = frame::read_frame(&mut self.reader)
            .await
            .map_err(pipe_error)?;
        frame::decode(&body).map_err(pipe_error)
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
