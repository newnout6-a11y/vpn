//! Dotted numeric versions (`1.14.5`, `26.11.20`, `2.0.1`) and the small range language of the
//! feed and of the compiled policy (`>=1.14.4 <1.15.0`). Engines and the app use three numbers;
//! a pre-release or build suffix is not part of anything we publish, so it is refused.
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// `major.minor.patch`, ordered numerically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub u16, pub u16, pub u16);

impl Version {
    /// The `(major, minor, patch)` triple the engine crate reports.
    pub fn from_triple((a, b, c): (u16, u16, u16)) -> Self {
        Self(a, b, c)
    }
}

impl FromStr for Version {
    type Err = BadVersion;

    fn from_str(s: &str) -> Result<Self, BadVersion> {
        let mut parts = s.trim().split('.');
        let mut next = || -> Result<u16, BadVersion> {
            let part = parts.next().ok_or(BadVersion)?;
            // "01" would compare equal to "1" but read as a different version in a file name.
            if part.is_empty() || (part.len() > 1 && part.starts_with('0')) {
                return Err(BadVersion);
            }
            part.parse().map_err(|_| BadVersion)
        };
        let version = Version(next()?, next()?, next()?);
        match parts.next() {
            None => Ok(version),
            Some(_) => Err(BadVersion),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

impl Serialize for Version {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Not `a.b.c` with plain decimal numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not a version (expected major.minor.patch)")]
pub struct BadVersion;

/// Comparators joined by AND: `>=1.14.4 <1.15.0`. Empty = any version.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Range(Vec<(Op, Version)>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Ge,
    Gt,
    Le,
    Lt,
    Eq,
}

impl Range {
    /// `true` when `v` satisfies every comparator.
    pub fn contains(&self, v: Version) -> bool {
        self.0.iter().all(|&(op, bound)| match op {
            Op::Ge => v >= bound,
            Op::Gt => v > bound,
            Op::Le => v <= bound,
            Op::Lt => v < bound,
            Op::Eq => v == bound,
        })
    }

    /// The lowest version the range names with `>=` / `=` (the compiled minimum), if any.
    pub fn minimum(&self) -> Option<Version> {
        self.0
            .iter()
            .filter(|(op, _)| matches!(op, Op::Ge | Op::Eq))
            .map(|&(_, v)| v)
            .max()
    }
}

impl FromStr for Range {
    type Err = BadVersion;

    fn from_str(s: &str) -> Result<Self, BadVersion> {
        let parse = |item: &str| -> Result<(Op, Version), BadVersion> {
            let (op, rest) = [
                (">=", Op::Ge),
                ("<=", Op::Le),
                (">", Op::Gt),
                ("<", Op::Lt),
                ("=", Op::Eq),
            ]
            .into_iter()
            .find_map(|(p, op)| item.strip_prefix(p).map(|rest| (op, rest)))
            .ok_or(BadVersion)?;
            Ok((op, rest.parse()?))
        };
        s.split_whitespace()
            .map(parse)
            .collect::<Result<_, _>>()
            .map(Range)
    }
}

impl fmt::Display for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (op, v)) in self.0.iter().enumerate() {
            let op = match op {
                Op::Ge => ">=",
                Op::Gt => ">",
                Op::Le => "<=",
                Op::Lt => "<",
                Op::Eq => "=",
            };
            write!(f, "{}{op}{v}", if i == 0 { "" } else { " " })?;
        }
        Ok(())
    }
}

impl Serialize for Range {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Range {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests;
