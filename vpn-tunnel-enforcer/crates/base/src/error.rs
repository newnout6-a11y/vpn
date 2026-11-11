//! App-wide error: a small category the UI and callers branch on, an optional user-facing
//! message (i18n key + arguments) and the technical cause for the log.
//!
//! Rule: the user never sees `source` text (it can carry paths, hosts or OS strings); the UI
//! renders `msg` or, when absent, the canonical message of `kind`.
use std::fmt;

use crate::msg::Msg;

/// What went wrong, coarse enough to drive UI and retry decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ErrorKind {
    /// Bad input or parameters.
    Validation,
    /// Needs administrator rights or the OS refused access.
    Permission,
    /// A network operation failed.
    Network,
    /// Not possible in the current state (busy, already running, pre-empted).
    Conflict,
    /// Anything unexpected.
    Internal,
    /// Cancelled by the user or by a higher-priority operation.
    Cancelled,
    /// A deadline passed.
    Timeout,
}

impl ErrorKind {
    /// Key of the canonical user-facing sentence for this category (`errors.<kind>`).
    pub fn i18n_key(self) -> &'static str {
        match self {
            ErrorKind::Validation => "errors.validation",
            ErrorKind::Permission => "errors.permission",
            ErrorKind::Network => "errors.network",
            ErrorKind::Conflict => "errors.conflict",
            ErrorKind::Internal => "errors.internal",
            ErrorKind::Cancelled => "errors.cancelled",
            ErrorKind::Timeout => "errors.timeout",
        }
    }
}

/// The error type crossing crate boundaries.
#[derive(Debug)]
pub struct AppError {
    pub kind: ErrorKind,
    /// User-facing explanation; `None` means "show the canonical message of `kind`".
    pub msg: Option<Msg>,
    /// Technical cause, for logs only.
    pub source: Option<anyhow::Error>,
}

pub type AppResult<T> = Result<T, AppError>;

impl AppError {
    pub fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            msg: None,
            source: None,
        }
    }
    /// Error with a user-facing message.
    pub fn msg(kind: ErrorKind, msg: Msg) -> Self {
        Self {
            kind,
            msg: Some(msg),
            source: None,
        }
    }
    /// Attaches the technical cause.
    pub fn with_source(mut self, source: impl Into<anyhow::Error>) -> Self {
        self.source = Some(source.into());
        self
    }
    pub fn validation(msg: Msg) -> Self {
        Self::msg(ErrorKind::Validation, msg)
    }
    pub fn conflict(msg: Msg) -> Self {
        Self::msg(ErrorKind::Conflict, msg)
    }
    pub fn cancelled() -> Self {
        Self::new(ErrorKind::Cancelled)
    }
    pub fn timeout() -> Self {
        Self::new(ErrorKind::Timeout)
    }
    pub fn internal(source: impl Into<anyhow::Error>) -> Self {
        Self::new(ErrorKind::Internal).with_source(source)
    }
    /// The message to show: the specific one, or the canonical one for the category.
    pub fn user_msg(&self) -> Msg {
        self.msg
            .clone()
            .unwrap_or_else(|| Msg::new(self.kind.i18n_key()))
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.kind)?;
        if let Some(msg) = &self.msg {
            write!(f, " [{}]", msg.key)?;
        }
        if let Some(source) = &self.source {
            write!(f, ": {source:#}")?;
        }
        Ok(())
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|e| e as _)
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        use std::io::ErrorKind as Io;
        let kind = match err.kind() {
            Io::PermissionDenied => ErrorKind::Permission,
            Io::TimedOut => ErrorKind::Timeout,
            Io::ConnectionRefused
            | Io::ConnectionReset
            | Io::ConnectionAborted
            | Io::HostUnreachable
            | Io::NetworkUnreachable
            | Io::NotConnected
            | Io::AddrNotAvailable => ErrorKind::Network,
            _ => ErrorKind::Internal,
        };
        AppError::new(kind).with_source(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_errors_map_to_kinds() {
        let e: AppError = std::io::Error::from(std::io::ErrorKind::PermissionDenied).into();
        assert_eq!(e.kind, ErrorKind::Permission);
        let e: AppError = std::io::Error::from(std::io::ErrorKind::ConnectionRefused).into();
        assert_eq!(e.kind, ErrorKind::Network);
        let e: AppError = std::io::Error::other("boom").into();
        assert_eq!(e.kind, ErrorKind::Internal);
    }

    #[test]
    fn user_message_falls_back_to_the_kind() {
        assert_eq!(AppError::timeout().user_msg().key, "errors.timeout");
        let e = AppError::validation(Msg::new("servers.invalidKey"));
        assert_eq!(e.user_msg().key, "servers.invalidKey");
    }
}
