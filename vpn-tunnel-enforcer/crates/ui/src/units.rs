//! Display units shared by the pages.

/// A byte count for display, the same on every page: whole bytes below 1 KB, then one decimal
/// (halves round up) in KB, MB, GB or TB, base 1024, Latin unit symbols in both languages:
/// `1023 B`, `1.5 KB`, `4.8 MB`, `2.2 GB`, `1.5 TB`.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut unit = 0;
    let mut scale = 1u64;
    while unit < UNITS.len() - 1 && bytes / 1024 >= scale {
        scale *= 1024;
        unit += 1;
    }
    if unit == 0 {
        return format!("{bytes} B");
    }
    let tenths = (bytes as f64 / scale as f64 * 10.0).round() as u64;
    format!("{}.{} {}", tenths / 10, tenths % 10, UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::format_bytes;

    /// The vectors of the old Logs, Servers and Traffic formats, on the one shared format.
    #[test]
    fn byte_sizes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1000), "1000 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1280), "1.3 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(586 * 1024), "586.0 KB");
        assert_eq!(format_bytes(5_000_000), "4.8 MB");
        assert_eq!(format_bytes(15 * 1024 * 1024), "15.0 MB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
        assert_eq!(format_bytes(200 * 1024 * 1024 * 1024), "200.0 GB");
        assert_eq!(format_bytes(5 * 1024 * 1024 * 1024 * 1024), "5.0 TB");
        assert_eq!(format_bytes(u64::MAX), "16777216.0 TB");
    }
}
