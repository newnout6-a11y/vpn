//! Length-prefixed JSON frames: 4 bytes little-endian length, then the JSON (at most
//! [`MAX_FRAME`] bytes, never empty).
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest frame either side accepts: a start request with a provider Xray graph and a long
/// domain-rule list stays far below it; anything bigger is refused before it is read.
pub const MAX_FRAME: usize = 4 << 20;

/// A frame that could not be read, decoded or written.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The peer closed the pipe between frames.
    #[error("the peer closed the connection")]
    Closed,
    /// The length prefix is 0 or over [`MAX_FRAME`].
    #[error("frame length {0} is outside 1..={MAX_FRAME}")]
    Length(usize),
    #[error("pipe I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame is not valid protocol JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Reads one frame's JSON bytes.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>, FrameError> {
    let mut len = [0u8; 4];
    // A clean close shows up as EOF before the first byte of a frame.
    let first = r.read(&mut len).await?;
    if first == 0 {
        return Err(FrameError::Closed);
    }
    r.read_exact(&mut len[first..]).await?;
    let len = u32::from_le_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(FrameError::Length(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(body)
}

/// Decodes a frame's JSON.
pub fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, FrameError> {
    Ok(serde_json::from_slice(body)?)
}

/// The length prefix and JSON of `msg`.
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, FrameError> {
    let json = serde_json::to_vec(msg)?;
    if json.is_empty() || json.len() > MAX_FRAME {
        return Err(FrameError::Length(json.len()));
    }
    let len = u32::try_from(json.len()).map_err(|_| FrameError::Length(json.len()))?;
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

/// Writes `msg` as one frame (one write call, so frames never interleave on a shared writer
/// that is held across the call).
pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    w: &mut W,
    msg: &T,
) -> Result<(), FrameError> {
    let bytes = encode(msg)?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

/// The id of a request that does not decode as a known [`super::ClientFrame`] (a newer
/// client's request, or a bad one): lets the service answer `BadRequest` instead of dropping
/// the connection.
pub fn request_id(body: &[u8]) -> Option<u64> {
    #[derive(serde::Deserialize)]
    struct IdOnly {
        id: u64,
    }
    serde_json::from_slice::<IdOnly>(body).ok().map(|f| f.id)
}
