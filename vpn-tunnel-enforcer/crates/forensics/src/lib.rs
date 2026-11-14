//! Traffic statistics, domain history, packet capture, ETW events and the diagnostics export.

pub mod capture;
pub mod connections;
pub mod domains;
pub mod enrichment;
pub mod etw;
pub mod export;
pub mod summary;
pub mod traffic;

#[cfg(test)]
mod test_support;

/// Locale fragments `(ru, en)`, one pair per file of `locales/` in file-name order; every key sits
/// under `forensics`. The app registers them at start.
pub const LOCALES: &[(&str, &str)] = &[
    (
        include_str!("../locales/forensics-capture.ru.json"),
        include_str!("../locales/forensics-capture.en.json"),
    ),
    (
        include_str!("../locales/forensics-export.ru.json"),
        include_str!("../locales/forensics-export.en.json"),
    ),
    (
        include_str!("../locales/forensics-traffic.ru.json"),
        include_str!("../locales/forensics-traffic.en.json"),
    ),
];

/// Pretty JSON plus a trailing newline: the on-disk form of every document this crate writes.
pub(crate) fn pretty_json<T: serde::Serialize + ?Sized>(value: &T) -> serde_json::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// `bytes` without a leading UTF-8 BOM (Windows PowerShell 5.1 and some tools write one, B-05).
pub(crate) fn strip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes)
}

#[cfg(test)]
mod locale_tests;
