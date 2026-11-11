//! The DNS wire format (RFC 1035 §4.1) shared by both transports of the chain, DoH (RFC 8484)
//! and DNS over TCP: one question out; the rcode, the AA flag and the A / AAAA records back.
use std::net::IpAddr;

/// RCODE of a successful answer.
pub(super) const NOERROR: u8 = 0;
/// RCODE "the name does not exist".
pub(super) const NXDOMAIN: u8 = 3;
const HEADER: usize = 12;
const CLASS_IN: u16 = 1;

/// The record type asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Record {
    A,
    Aaaa,
}

impl Record {
    pub(super) fn code(self) -> u16 {
        match self {
            Record::A => 1,
            Record::Aaaa => 28,
        }
    }

    /// The address in `data` when it has this record's size.
    fn address(self, data: &[u8]) -> Option<IpAddr> {
        match self {
            Record::A => <[u8; 4]>::try_from(data).ok().map(IpAddr::from),
            Record::Aaaa => <[u8; 16]>::try_from(data).ok().map(IpAddr::from),
        }
    }
}

/// What the chain judges in a reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Reply {
    pub rcode: u8,
    /// AA: a recursive resolver never sets it; the forged NXDOMAIN of the NSDI redirect does.
    pub authoritative: bool,
    /// The answer section's records of the asked type (CNAME steps skipped).
    pub addrs: Vec<IpAddr>,
}

/// A recursion-desired question for `name` (a valid host name, no trailing dot) with message
/// id `id`; `None` when a label is empty or too long.
pub(super) fn query(id: u16, name: &str, record: Record) -> Option<Vec<u8>> {
    let mut q = Vec::with_capacity(HEADER + name.len() + 6);
    q.extend_from_slice(&id.to_be_bytes());
    // Flags RD; one question, no other records.
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|n| (1..=63).contains(n))?;
        q.push(len);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    if q.len() - HEADER > 255 {
        return None;
    }
    q.extend_from_slice(&record.code().to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    Some(q)
}

/// The reply to `query` when it is one: same id, QR set, the same single question (letters in
/// any case: resolvers may echo 0x20-mixed names). `None` for anything else, also when a
/// record runs past the end.
pub(super) fn parse(reply: &[u8], query: &[u8], record: Record) -> Option<Reply> {
    let u16_at = |at: usize| Some(u16::from_be_bytes([*reply.get(at)?, *reply.get(at + 1)?]));
    let question = query.get(HEADER..)?;
    let flags = *reply.get(2)?;
    if reply.get(..2)? != query.get(..2)? || flags & 0x80 == 0 || u16_at(4)? != 1 {
        return None;
    }
    let echoed = reply.get(HEADER..HEADER + question.len())?;
    if !echoed.eq_ignore_ascii_case(question) {
        return None;
    }
    let mut at = HEADER + question.len();
    let mut addrs = Vec::new();
    for _ in 0..u16_at(6)? {
        at = skip_name(reply, at)?;
        let (rtype, class, len) = (u16_at(at)?, u16_at(at + 2)?, usize::from(u16_at(at + 8)?));
        let data = reply.get(at + 10..at + 10 + len)?;
        at += 10 + len;
        if rtype == record.code() && class == CLASS_IN {
            addrs.extend(record.address(data));
        }
    }
    Some(Reply {
        rcode: reply.get(3)? & 0x0f,
        authoritative: flags & 0x04 != 0,
        addrs,
    })
}

/// Past a (possibly compressed) name starting at `at`.
fn skip_name(msg: &[u8], mut at: usize) -> Option<usize> {
    loop {
        match *msg.get(at)? {
            0 => return Some(at + 1),
            len if len & 0xc0 == 0xc0 => return Some(at + 2),
            len if len & 0xc0 == 0 => at += 1 + usize::from(len),
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests;
