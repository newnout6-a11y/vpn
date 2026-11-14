//! Reading stored names a newer build may write (diag-a8). A build that adds an enum name keeps
//! the document's `VERSION`, so an older build must read such a name as a fallback instead of
//! failing the whole server list (the store would then open it read-only and empty). Each field
//! says what an unknown value reads as; a new group *kind* changes the document's shape and bumps
//! `VERSION` instead (the store keeps a newer document read-only, never rewriting it).
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};

/// An optional stored value; one this build cannot read is `None`.
pub(crate) fn option<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let value = Option::<serde_json::Value>::deserialize(d)?;
    Ok(value.and_then(|v| serde_json::from_value(v).ok()))
}

/// A stored value; one this build cannot read is the type's `Default` (each type documents why
/// its default is the safe reading).
pub(crate) fn or_default<'de, D, T>(d: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned + Default,
{
    let value = serde_json::Value::deserialize(d)?;
    Ok(serde_json::from_value(value).unwrap_or_default())
}
