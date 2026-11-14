//! Pasted text and subscription bodies to `String`, bounded.
use std::io::Read;

use crate::model::TooLarge;

/// Pasted text ready for parsing: byte-order marks and surrounding whitespace removed (Rust's
/// `trim` keeps U+FEFF, JS `trim` did not), at most `max_bytes` long.
pub fn prepare(input: &str, max_bytes: usize) -> Result<&str, TooLarge> {
    let text = input.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    if text.len() > max_bytes {
        return Err(TooLarge);
    }
    Ok(text)
}

/// Subscription body bytes as text: gzip / zlib by their magic bytes, UTF-16 by BOM or NUL
/// density, UTF-8 otherwise, brotli only when the bytes are not text. Input and decompressed
/// output are both capped at `cap` bytes. A broken compressed stream is kept as raw bytes: a
/// truncated list must never pass for the whole list.
pub fn decode_body(raw: &[u8], cap: usize) -> Result<String, TooLarge> {
    if raw.len() > cap {
        return Err(TooLarge);
    }
    let inflated = if raw.starts_with(&GZIP_MAGIC) {
        gunzip(raw, cap)?
    } else if is_zlib_header(raw) {
        inflate(flate2::read::ZlibDecoder::new(raw), cap)?
    } else {
        None
    };
    let bytes = inflated.as_deref().unwrap_or(raw);
    if let Some(text) = to_text(bytes) {
        return Ok(text);
    }
    // Some panels serve brotli files without a Content-Encoding header; only bytes that are not
    // text at all are worth the attempt.
    if let Some(text) = inflate(brotli::Decompressor::new(bytes, 4096), cap)?
        .as_deref()
        .and_then(to_text)
        .filter(|t| !t.trim().is_empty())
    {
        return Ok(text);
    }
    Ok(String::from_utf8_lossy(bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes)).into_owned())
}

const UTF8_BOM: &[u8] = &[0xef, 0xbb, 0xbf];
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Every gzip member, one after another, as Node's `gunzipSync` read them: bytes after a whole
/// member that start no other member (a stray newline, NUL padding) are ignored. Each member is
/// checked against its CRC, so a cut one still fails the whole body.
fn gunzip(mut raw: &[u8], cap: usize) -> Result<Option<Vec<u8>>, TooLarge> {
    let mut out = Vec::new();
    while raw.starts_with(&GZIP_MAGIC) {
        let mut member = flate2::bufread::GzDecoder::new(raw);
        let Some(part) = inflate(&mut member, cap - out.len())? else {
            return Ok(None);
        };
        out.extend(part);
        raw = member.into_inner();
    }
    Ok(Some(out))
}

/// RFC 1950 header: deflate method with the check bits set (`0x78` alone matched plain text
/// starting with `x`).
fn is_zlib_header(raw: &[u8]) -> bool {
    match raw {
        [0x78, b1, ..] => ((0x78u16 << 8) | u16::from(*b1)).is_multiple_of(31),
        _ => false,
    }
}

/// Everything a decompressor yields, or `None` when the stream is not valid.
fn inflate(mut reader: impl Read, cap: usize) -> Result<Option<Vec<u8>>, TooLarge> {
    let mut out = Vec::new();
    match reader.by_ref().take(cap as u64 + 1).read_to_end(&mut out) {
        Ok(_) if out.len() > cap => Err(TooLarge),
        Ok(_) => Ok(Some(out)),
        Err(_) => Ok(None),
    }
}

/// Bytes as text without a byte-order mark when they are UTF-8 or UTF-16; `None` otherwise.
fn to_text(bytes: &[u8]) -> Option<String> {
    if let Some(rest) = bytes.strip_prefix(UTF8_BOM) {
        return std::str::from_utf8(rest).ok().map(str::to_owned);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xff, 0xfe]) {
        return Some(utf16(rest, u16::from_le_bytes));
    }
    if let Some(rest) = bytes.strip_prefix(&[0xfe, 0xff]) {
        return Some(utf16(rest, u16::from_be_bytes));
    }
    // Windows tools save "Unicode" text as BOM-less UTF-16: ASCII then shows up as every other
    // byte being NUL. Which half holds the NULs tells the byte order.
    let head = &bytes[..bytes.len().min(80)];
    let nul_even = head.iter().step_by(2).filter(|b| **b == 0).count();
    let nul_odd = head.iter().skip(1).step_by(2).filter(|b| **b == 0).count();
    if (nul_even + nul_odd) * 4 > head.len() {
        let unit = if nul_even > nul_odd {
            u16::from_be_bytes
        } else {
            u16::from_le_bytes
        };
        return Some(utf16(bytes, unit));
    }
    std::str::from_utf8(bytes).ok().map(str::to_owned)
}

fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> String {
    char::decode_utf16(bytes.as_chunks::<2>().0.iter().map(|pair| unit(*pair)))
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    const LIST: &str =
        "vless://00000000-0000-4000-8000-000000000000@one.example.com:443?security=tls#One\n";

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn brotli(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut enc = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
            enc.write_all(data).unwrap();
        }
        out
    }

    fn utf16le(text: &str, bom: bool) -> Vec<u8> {
        let mut out = if bom { vec![0xff, 0xfe] } else { Vec::new() };
        out.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        out
    }

    #[test]
    fn plain_utf8_passes_through_and_loses_the_bom() {
        assert_eq!(decode_body(LIST.as_bytes(), MAX).unwrap(), LIST);
        let with_bom = [&[0xef, 0xbb, 0xbf][..], LIST.as_bytes()].concat();
        assert_eq!(decode_body(&with_bom, MAX).unwrap(), LIST);
    }

    const MAX: usize = crate::text::MAX_BODY_BYTES;

    #[test]
    fn compressed_bodies_are_inflated() {
        assert_eq!(decode_body(&gzip(LIST.as_bytes()), MAX).unwrap(), LIST);
        assert_eq!(decode_body(&zlib(LIST.as_bytes()), MAX).unwrap(), LIST);
        assert_eq!(decode_body(&brotli(LIST.as_bytes()), MAX).unwrap(), LIST);
        // Compressed UTF-16 is decoded after inflating.
        assert_eq!(decode_body(&gzip(&utf16le(LIST, true)), MAX).unwrap(), LIST);
    }

    /// Concatenated gzip members all count; bytes after a whole member that start no other one
    /// are ignored, as Node's `gunzipSync` did; a cut member keeps the body raw.
    #[test]
    fn gzip_members_and_trailing_bytes() {
        let mut padded = gzip(LIST.as_bytes());
        padded.extend_from_slice(b"\n\0\0");
        assert_eq!(decode_body(&padded, MAX).unwrap(), LIST);
        let two = [gzip(b"vless://a@h:1#A\n"), gzip(b"vless://b@h:1#B\n")].concat();
        assert_eq!(
            decode_body(&two, MAX).unwrap(),
            "vless://a@h:1#A\nvless://b@h:1#B\n"
        );
        let mut cut = [gzip(b"x\n"), gzip(LIST.as_bytes())].concat();
        cut.truncate(cut.len() - 4);
        assert!(!decode_body(&cut, MAX).unwrap().contains("vless://"));
        // The cap holds across members.
        let big = gzip(&[b'A'; 3000]);
        assert_eq!(
            decode_body(&[big.clone(), big].concat(), 4096),
            Err(TooLarge)
        );
    }

    #[test]
    fn utf16_by_bom_or_nul_density() {
        assert_eq!(decode_body(&utf16le(LIST, true), MAX).unwrap(), LIST);
        assert_eq!(decode_body(&utf16le(LIST, false), MAX).unwrap(), LIST);
        let be: Vec<u8> = LIST.encode_utf16().flat_map(u16::to_be_bytes).collect();
        assert_eq!(decode_body(&be, MAX).unwrap(), LIST);
        assert_eq!(
            decode_body(&[[0xfe, 0xff].as_slice(), &be].concat(), MAX).unwrap(),
            LIST
        );
    }

    /// P-19: decompression is bounded; a bomb is refused instead of filling memory.
    #[test]
    fn caps_input_and_inflated_output() {
        assert_eq!(decode_body(&[b'a'; 11], 10), Err(TooLarge));
        let bomb = gzip(&vec![b'A'; 64 * 1024]);
        assert!(bomb.len() < 1024);
        assert_eq!(decode_body(&bomb, 4096), Err(TooLarge));
        assert_eq!(
            decode_body(&zlib(&vec![b'A'; 64 * 1024]), 4096),
            Err(TooLarge)
        );
        assert_eq!(
            decode_body(&brotli(&[0xffu8; 64 * 1024]), 4096),
            Err(TooLarge)
        );
    }

    /// A broken stream or text that merely starts with `x` stays as it was (no raw-deflate guessing).
    #[test]
    fn non_streams_are_kept_raw() {
        let mut broken = gzip(LIST.as_bytes());
        broken.truncate(broken.len() / 2);
        let text = decode_body(&broken, MAX).unwrap();
        assert!(!text.contains("vless://"));
        assert_eq!(decode_body(b"x^ not zlib", MAX).unwrap(), "x^ not zlib");
        assert_eq!(decode_body(b"xray config", MAX).unwrap(), "xray config");
        // Not UTF-8 and not brotli: lossy text, never an error (and still without the BOM).
        assert_eq!(decode_body(&[0xc3, 0x28, b'a'], MAX).unwrap(), "\u{fffd}(a");
        assert_eq!(
            decode_body(&[0xef, 0xbb, 0xbf, 0xc3, 0x28, b'a'], MAX).unwrap(),
            "\u{fffd}(a"
        );
    }

    #[test]
    fn prepare_strips_boms_and_whitespace_and_checks_the_size() {
        assert_eq!(
            prepare("\u{feff}  vless://x \n\u{feff}", 100),
            Ok("vless://x")
        );
        assert_eq!(prepare(" abc ", 3), Ok("abc"));
        assert_eq!(prepare("abcd", 3), Err(TooLarge));
    }
}
