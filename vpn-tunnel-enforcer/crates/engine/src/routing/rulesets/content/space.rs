//! Address space of a network list as sorted, disjoint ranges per family: what a downloaded
//! set adds to or drops from the release's copy, counted exactly (overlaps once).
use std::net::IpAddr;

/// Sorted, disjoint, inclusive ranges of one family.
#[derive(Debug, Default, Clone, PartialEq)]
pub(super) struct Ranges(Vec<(u128, u128)>);

/// The IPv4 and IPv6 ranges of a network list.
#[derive(Debug, Default, Clone, PartialEq)]
pub(super) struct Space {
    pub v4: Ranges,
    pub v6: Ranges,
}

impl Space {
    /// `nets` as `(address, prefix length)`; a length is at most the family's width.
    pub(super) fn of(nets: &[(IpAddr, u8)]) -> Self {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for &(ip, len) in nets {
            match ip {
                IpAddr::V4(a) => v4.push(range(u128::from(u32::from(a)), 32 - len)),
                IpAddr::V6(a) => v6.push(range(u128::from(a), 128 - len)),
            }
        }
        Self {
            v4: Ranges::merged(v4),
            v6: Ranges::merged(v6),
        }
    }
}

/// The range of the network holding `start` with `host` host bits.
fn range(start: u128, host: u8) -> (u128, u128) {
    let span = u128::MAX.checked_shr(128 - u32::from(host)).unwrap_or(0);
    let base = start & !span;
    (base, base | span)
}

impl Ranges {
    fn merged(mut ranges: Vec<(u128, u128)>) -> Self {
        ranges.sort_unstable();
        let mut out: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            match out.last_mut() {
                Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
                _ => out.push((start, end)),
            }
        }
        Self(out)
    }

    /// Number of addresses (as a float: a whole IPv6 space overflows `u128`).
    pub(super) fn size(&self) -> f64 {
        self.0.iter().map(|(s, e)| (e - s) as f64 + 1.0).sum()
    }

    /// The addresses of `self` outside `other`.
    pub(super) fn minus(&self, other: &Ranges) -> Ranges {
        let mut out = Vec::new();
        let mut first = 0;
        for &(start, end) in &self.0 {
            while other.0.get(first).is_some_and(|c| c.1 < start) {
                first += 1;
            }
            let mut from = Some(start);
            for &(cut_start, cut_end) in &other.0[first..] {
                let Some(s) = from else { break };
                if cut_start > end {
                    break;
                }
                if cut_start > s {
                    out.push((s, cut_start - 1));
                }
                // `None` once a cut reaches the end of this range.
                from = cut_end.checked_add(1).filter(|next| *next <= end);
            }
            if let Some(s) = from {
                out.push((s, end));
            }
        }
        Ranges(out)
    }

    /// Whether any address lies in both.
    pub(super) fn overlaps(&self, other: &Ranges) -> bool {
        let (mut i, mut j) = (0, 0);
        while let (Some(a), Some(b)) = (self.0.get(i), other.0.get(j)) {
            if a.1 < b.0 {
                i += 1;
            } else if b.1 < a.0 {
                j += 1;
            } else {
                return true;
            }
        }
        false
    }
}
