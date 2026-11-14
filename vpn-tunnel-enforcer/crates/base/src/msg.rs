//! A user-facing message that is not yet text: an i18n key plus arguments.
//!
//! Backend code never formats sentences for the user. It returns a [`Msg`]; the UI (or the
//! tray/toast code) renders it in the current language, so switching the language re-renders
//! everything, including errors and history headlines.
use std::borrow::Cow;

use crate::i18n::{self, Lang};

/// i18n key with interpolation arguments (`{{name}}` placeholders, `count` selects plurals).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Msg {
    pub key: Cow<'static, str>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<(Cow<'static, str>, String)>,
}

impl Msg {
    pub fn new(key: impl Into<Cow<'static, str>>) -> Self {
        Self {
            key: key.into(),
            args: Vec::new(),
        }
    }

    /// Adds an interpolation argument.
    #[must_use]
    pub fn arg(mut self, name: &'static str, value: impl ToString) -> Self {
        self.args.push((Cow::Borrowed(name), value.to_string()));
        self
    }

    /// Renders the message in `lang` (falls back to English, then to the key itself).
    pub fn render(&self, lang: Lang) -> String {
        let vars: Vec<(&str, String)> = self
            .args
            .iter()
            .map(|(k, v)| (k.as_ref(), v.clone()))
            .collect();
        i18n::lookup(lang, &self.key, &vars, None)
    }
}

impl From<&'static str> for Msg {
    fn from(key: &'static str) -> Self {
        Msg::new(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_key_renders_as_the_key() {
        assert_eq!(Msg::new("no.such.key").render(Lang::Ru), "no.such.key");
    }

    #[test]
    fn serializes_compactly() {
        let json = serde_json::to_string(&Msg::new("a.b")).unwrap();
        assert_eq!(json, r#"{"key":"a.b"}"#);
        let m: Msg = serde_json::from_str(r#"{"key":"a.b","args":[["n","3"]]}"#).unwrap();
        assert_eq!(m, Msg::new("a.b").arg("n", 3));
    }
}
