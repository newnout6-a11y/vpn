//! Lenient reading of stored collections: an element that does not parse (a hand edit, a newer
//! variant) is dropped and logged instead of making the whole document unreadable, which would
//! lose everything else it holds (schedules, journal obligations, learned modes). Only counts are
//! logged: the dropped values may hold profile ids or proxy settings.
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// `deserialize_with` for a `Vec<T>`: the elements that parse, in order.
pub(crate) fn list<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let raw = Vec::<Value>::deserialize(d)?;
    let total = raw.len();
    let items: Vec<T> = raw
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect();
    report::<T>(total, items.len());
    Ok(items)
}

/// `deserialize_with` for a `BTreeMap<String, T>`: the entries whose value parses.
pub(crate) fn map<'de, D, T>(d: D) -> Result<std::collections::BTreeMap<String, T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let raw = std::collections::BTreeMap::<String, Value>::deserialize(d)?;
    let total = raw.len();
    let items: std::collections::BTreeMap<String, T> = raw
        .into_iter()
        .filter_map(|(k, v)| Some((k, serde_json::from_value(v).ok()?)))
        .collect();
    report::<T>(total, items.len());
    Ok(items)
}

fn report<T>(total: usize, kept: usize) {
    if kept != total {
        let kind = std::any::type_name::<T>();
        tracing::warn!(
            dropped = total - kept,
            kind,
            "unparseable stored entries dropped"
        );
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Doc {
        #[serde(default, deserialize_with = "super::list")]
        items: Vec<u8>,
    }

    /// One bad element is dropped alone; a non-array is still an error (the store moves it aside).
    #[test]
    fn bad_elements_are_dropped_alone() {
        let doc: Doc = serde_json::from_str(r#"{"items": [1, "x", 300, 2]}"#).unwrap();
        assert_eq!(doc.items, vec![1, 2]);
        assert!(serde_json::from_str::<Doc>(r#"{"items": 5}"#).is_err());
        assert_eq!(
            serde_json::from_str::<Doc>("{}").unwrap().items,
            Vec::<u8>::new()
        );
    }
}
