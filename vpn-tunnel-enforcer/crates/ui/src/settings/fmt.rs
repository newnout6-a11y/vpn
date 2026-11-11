//! Text helpers of the Settings page. Unit words come from the catalog (the old page printed
//! English `h/m/s` in the Russian UI, U-14); the arithmetic is pure and tested.
use dioxus::prelude::*;
use vpnte_base::types::UnixMs;

use crate::lang::{LANG, Lang};
use crate::t;

/// Time left until the next rotation, in the old `formatCountdown` shape (§3.18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Countdown {
    /// No rotation planned («—»).
    None,
    HoursMinutes(u64, u64),
    MinutesSeconds(u64, u64),
    Seconds(u64),
}

/// `null`/`0` → none; minutes > 60 → hours + minutes; minutes > 0 → minutes + seconds; else
/// seconds (60 min exactly stays «60m 0s», as before).
pub fn countdown(next_at: Option<UnixMs>, now: UnixMs) -> Countdown {
    let Some(at) = next_at.filter(|&at| at != 0) else {
        return Countdown::None;
    };
    let left = u64::try_from(at.saturating_sub(now)).unwrap_or(0);
    let minutes = left / 60_000;
    let seconds = (left % 60_000) / 1000;
    if minutes > 60 {
        Countdown::HoursMinutes(minutes / 60, minutes % 60)
    } else if minutes > 0 {
        Countdown::MinutesSeconds(minutes, seconds)
    } else {
        Countdown::Seconds(seconds)
    }
}

/// [`Countdown`] in the current language.
pub fn countdown_text(value: Countdown) -> String {
    match value {
        Countdown::None => "—".to_owned(),
        Countdown::HoursMinutes(h, m) => t!("ui.settings.units.hoursMinutes", h = h, m = m),
        Countdown::MinutesSeconds(m, s) => t!("ui.settings.units.minutesSeconds", m = m, s = s),
        Countdown::Seconds(s) => t!("ui.settings.units.seconds", s = s),
    }
}

/// Disk size as «N МБ» below 1 GiB, else «N,N ГБ» (one decimal; comma in Russian).
pub fn size_text(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    if bytes < 1024 * MIB {
        let mb = bytes.div_ceil(MIB);
        return t!("ui.settings.units.mb", n = mb);
    }
    let tenths = (bytes * 10 + 512 * MIB) / (1024 * MIB);
    let text = format!("{}.{}", tenths / 10, tenths % 10);
    let text = if *LANG.read() == Lang::Ru {
        text.replace('.', ",")
    } else {
        text
    };
    t!("ui.settings.units.gb", n = text)
}

/// Local date and time of a timestamp («11.11.2026 14:05» / «Nov 11, 2026 14:05»).
pub fn datetime_text(at: UnixMs) -> String {
    let Ok(ts) = jiff::Timestamp::from_millisecond(at) else {
        return "—".to_owned();
    };
    let local = ts.to_zoned(jiff::tz::TimeZone::system());
    let pattern = match *LANG.read() {
        Lang::Ru => "%d.%m.%Y %H:%M",
        Lang::En => "%b %-d, %Y %H:%M",
    };
    local.strftime(pattern).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: UnixMs = 1_800_000_000_000;

    /// ui-pages §7.13 `formatCountdown`: null → «—»; 61 min → 1h 1m; 60 min → 60m 0s; 90 s → 1m 30s.
    #[test]
    fn countdown_follows_the_old_rules() {
        assert_eq!(countdown(None, NOW), Countdown::None);
        assert_eq!(countdown(Some(0), NOW), Countdown::None);
        assert_eq!(
            countdown(Some(NOW + 61 * 60_000), NOW),
            Countdown::HoursMinutes(1, 1)
        );
        assert_eq!(
            countdown(Some(NOW + 60 * 60_000), NOW),
            Countdown::MinutesSeconds(60, 0)
        );
        assert_eq!(
            countdown(Some(NOW + 90_000), NOW),
            Countdown::MinutesSeconds(1, 30)
        );
        assert_eq!(countdown(Some(NOW + 5_400), NOW), Countdown::Seconds(5));
        // overdue: the old `max(0, at − now)` → «0s»
        assert_eq!(countdown(Some(NOW - 10_000), NOW), Countdown::Seconds(0));
    }
}
