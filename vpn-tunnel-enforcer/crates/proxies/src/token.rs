//! The bearer secret of the control API: 32 bytes from the OS random source as hex, compared
//! in constant time.

/// 32 random bytes as 64 lower-case hex characters.
pub(crate) fn generate() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(hex::encode(bytes))
}

/// Whether a token a client sent equals `expected`, without an early exit on the first
/// differing byte (the length is public: 64). An empty `expected` never matches.
pub(crate) fn matches(expected: &str, provided: &str) -> bool {
    let (a, b) = (expected.as_bytes(), provided.as_bytes());
    !a.is_empty()
        && a.len() == b.len()
        && std::hint::black_box(a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y))) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_fresh_hex_and_compare_exactly() {
        let (a, b) = (generate().unwrap(), generate().unwrap());
        assert_eq!(a.len(), 64);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        );
        assert_ne!(a, b);
        assert!(matches(&a, &a.clone()));
        assert!(!matches(&a, &b));
        assert!(!matches(&a, &a[..63]));
        assert!(!matches("", ""));
    }
}
