//! TLS tricks a share link carries (item 18): `fragment=` and Hiddify's `fgsize` / `fgsleep`.
use super::parts::Params;
use crate::model::TlsTricks;

/// The link's own tricks; `Some(None)` when it names some that cannot be read (kept as a note).
///
/// `fragment=` is Xray's `packets,length,interval` (`tlshello,100-200,10-20`, `1-3,40-60,30-50`);
/// Hiddify also writes `size,sleep,tlshello` (ray2sing reads `size,sleep` whenever the first
/// item is not `tlshello`). A trailing `tlshello` therefore means Hiddify's order; three numbers
/// are Xray's (a packet range has to start at 1 to touch the ClientHello anyway).
pub(super) fn link_tricks(p: &Params) -> Option<Option<TlsTricks>> {
    if let Some(raw) = p.get(&["fragment"]) {
        let items: Vec<&str> = raw.split(',').map(str::trim).collect();
        let tricks = match items.as_slice() {
            [size, sleep, last] if last.eq_ignore_ascii_case("tlshello") => {
                TlsTricks::from_fragment(last, Some(size), Some(sleep))
            }
            [packets, length, interval] => {
                TlsTricks::from_fragment(packets, Some(length), Some(interval))
            }
            _ => None,
        };
        return Some(tricks);
    }
    let size = p.get(&["fgsize"])?;
    Some(TlsTricks::from_fragment(
        "1",
        Some(size),
        p.get(&["fgsleep"]),
    ))
}
