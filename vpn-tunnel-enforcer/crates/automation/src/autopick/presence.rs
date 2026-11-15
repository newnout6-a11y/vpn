//! Whether someone uses the PC (owner logs O-5, 15.11.2026): the warm-up checked a candidate
//! every two minutes all night. A locked session, a display turned off for idleness and a user
//! away all read the same here: no keyboard, mouse or touch input for a while.
use std::time::Duration;

use windows::Win32::System::SystemInformation::GetTickCount;
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

/// No input for this long: nobody is at the PC, and the next candidates can wait.
pub const AWAY: Duration = Duration::from_secs(5 * 60);

/// How long this Windows session has had no input; `None` when Windows does not say.
pub fn idle_for() -> Option<Duration> {
    let mut info = LASTINPUTINFO {
        cbSize: size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: `info` is a valid LASTINPUTINFO with its size set, as the call requires.
    if !unsafe { GetLastInputInfo(&mut info) }.as_bool() {
        return None;
    }
    // SAFETY: no arguments; both counters are milliseconds since boot and wrap together.
    let now = unsafe { GetTickCount() };
    Some(Duration::from_millis(u64::from(
        now.wrapping_sub(info.dwTime),
    )))
}

/// Someone is at the PC: input within [`AWAY`] (unknown counts as present, as before).
pub fn present(idle: Option<Duration>) -> bool {
    idle.is_none_or(|idle| idle < AWAY)
}
