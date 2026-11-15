//! A connected client split in two for a long-lived controller (the app's remote runtime): many
//! requests in flight at once (a `Stop` overtakes a start, as the service expects) and one ordered
//! stream of what the service sends, so the events of an operation are handled before its reply.
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::windows::named_pipe::NamedPipeClient;

use super::{CallError, Client, failure, read_failed, read_from};
use crate::proto::frame::{self, FrameError};
use crate::proto::{ClientFrame, Event, Reply, Request, ServerFrame, WireError};

/// One frame from the service, in arrival order.
#[derive(Debug)]
pub enum Incoming {
    Event(Event),
    /// The answer to request `id`.
    Answer {
        id: u64,
        result: Result<Reply, WireError>,
    },
}

/// The writing half: shared, each request goes out whole.
#[derive(Clone)]
pub struct Requests {
    writer: Arc<tokio::sync::Mutex<WriteHalf<NamedPipeClient>>>,
    next_id: Arc<AtomicU64>,
    /// The negotiated version.
    protocol: u32,
}

impl Requests {
    /// A fresh request id: register where its answer goes before sending (it may come at once).
    pub fn id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Sends `request` under `id`. The write runs on a task of its own: a caller that gives up
    /// never leaves half a frame on the pipe.
    pub async fn send(&self, id: u64, request: Request) -> Result<(), CallError> {
        let request = request.speak(self.protocol);
        let bytes = frame::encode(&ClientFrame { id, request })
            .map_err(|e| CallError::Pipe(failure("service.pipe.tooLarge", e)))?;
        let writer = self.writer.clone();
        let written = tokio::spawn(async move { writer.lock().await.write_all(&bytes).await });
        match written.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(read_failed(FrameError::Io(e))),
            Err(e) => Err(CallError::Pipe(failure("service.pipe.lost", e))),
        }
    }
}

/// The reading half: events queued before the split first, then every frame as it comes.
pub struct Frames {
    reader: ReadHalf<NamedPipeClient>,
    inbox: Vec<u8>,
    events: VecDeque<Event>,
}

impl Frames {
    /// The next frame (cancel-safe: what was read so far stays here).
    pub async fn next(&mut self) -> Result<Incoming, CallError> {
        if let Some(event) = self.events.pop_front() {
            return Ok(Incoming::Event(event));
        }
        Ok(match read_from(&mut self.reader, &mut self.inbox).await? {
            ServerFrame::Event { event } => Incoming::Event(*event),
            ServerFrame::Reply { id, reply } => Incoming::Answer {
                id,
                result: Ok(*reply),
            },
            ServerFrame::Failed { id, error } => Incoming::Answer {
                id,
                result: Err(error),
            },
        })
    }
}

impl Client {
    /// Splits a client (after its `Hello`) into the two halves; a request still half written
    /// goes out first.
    pub async fn split(mut self) -> Result<(Requests, Frames), CallError> {
        self.send().await?;
        let requests = Requests {
            writer: Arc::new(tokio::sync::Mutex::new(self.writer)),
            next_id: Arc::new(AtomicU64::new(self.next_id)),
            protocol: self.protocol,
        };
        let frames = Frames {
            reader: self.reader,
            inbox: self.inbox,
            events: self.events,
        };
        Ok((requests, frames))
    }
}
