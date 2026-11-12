//! Process elevation: the token check, read once per process. The app never elevates itself
//! (NOADMIN §0): privileged features are available exactly when this says `true`.
use std::ffi::c_void;
use std::sync::OnceLock;

use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TokenElevation};

use crate::win;

/// `true` when the process token is elevated; read once per process (a token never changes).
pub fn is_elevated() -> bool {
    static ELEVATED: OnceLock<bool> = OnceLock::new();
    *ELEVATED.get_or_init(token_is_elevated)
}

fn token_is_elevated() -> bool {
    let Ok(token) = win::process_token() else {
        return false;
    };
    let mut elevation = TOKEN_ELEVATION::default();
    let mut len = 0u32;
    // SAFETY: the buffer is a TOKEN_ELEVATION of exactly the size passed; the token has TOKEN_QUERY.
    let read = unsafe {
        GetTokenInformation(
            *token,
            TokenElevation,
            Some((&raw mut elevation).cast::<c_void>()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    read.is_ok() && elevation.TokenIsElevated != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AT-00-004: the elevation check is performed once per process and agrees with the token.
    #[test]
    fn elevation_is_read_once_and_matches_the_token() {
        let first = is_elevated();
        assert_eq!(first, token_is_elevated());
        assert_eq!(first, is_elevated());
    }
}
