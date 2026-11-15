//! Status marks: [`Badge`], [`ProgressBar`], [`Spinner`].
use dioxus::prelude::*;
use vpnte_base::types::Verdict;

/// Meaning of a [`Badge`]. `Unknown` ("not checked") must never look like `Ok`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tone {
    /// Plain information: hairline frame, ink text.
    #[default]
    Neutral,
    /// Good / on / passed: ink fill.
    Ok,
    /// Needs attention: signal frame and text.
    Warn,
    /// Failed / leaking / off when it must be on: signal fill.
    Fail,
    /// Not checked / unknown: dashed frame, muted text.
    Unknown,
}

impl Tone {
    fn class(self) -> &'static str {
        match self {
            Tone::Neutral => "w-badge",
            Tone::Ok => "w-badge is-ok",
            Tone::Warn => "w-badge is-warn",
            Tone::Fail => "w-badge is-fail",
            Tone::Unknown => "w-badge is-unknown",
        }
    }

    /// Value of the `data-tone` attribute (stable for tests and page CSS).
    pub fn name(self) -> &'static str {
        match self {
            Tone::Neutral => "neutral",
            Tone::Ok => "ok",
            Tone::Warn => "warn",
            Tone::Fail => "fail",
            Tone::Unknown => "unknown",
        }
    }
}

impl From<Verdict> for Tone {
    fn from(verdict: Verdict) -> Self {
        match verdict {
            Verdict::Ok => Tone::Ok,
            Verdict::Warn => Tone::Warn,
            Verdict::Fail => Tone::Fail,
            Verdict::NotChecked => Tone::Unknown,
        }
    }
}

/// A short mono status word in a square frame.
#[component]
pub fn Badge(
    #[props(default)] tone: Tone,
    #[props(default)] title: Option<String>,
    children: Element,
) -> Element {
    rsx! {
        span { class: tone.class(), "data-tone": tone.name(), title, {children} }
    }
}

/// A determinate bar (`value` = fraction 0..=1) or, with `None`, the moving signal stripes.
/// `label` names it for assistive technology.
#[component]
pub fn ProgressBar(
    value: Option<f64>,
    label: String,
    /// Prints the percentage to the right of the bar.
    #[props(default)]
    show_value: bool,
) -> Element {
    let pct = value.map(percent);
    rsx! {
        div { class: "w-progress-wrap",
            div {
                class: "w-progress",
                class: if pct.is_none() { "is-indeterminate" },
                role: "progressbar",
                aria_label: "{label}",
                aria_valuemin: "0",
                aria_valuemax: "100",
                aria_valuenow: pct.map(|p| p.to_string()),
                if let Some(p) = pct {
                    div { class: "w-progress-fill", style: "width:{p}%" }
                }
            }
            if show_value {
                if let Some(p) = pct {
                    span { class: "w-progress-value swiss-mono", "{p}%" }
                }
            }
        }
    }
}

/// Whole percent of a fraction, clamped to 0..=100 (NaN counts as 0).
pub(crate) fn percent(fraction: f64) -> u8 {
    if fraction.is_nan() {
        return 0;
    }
    (fraction.clamp(0.0, 1.0) * 100.0).round() as u8
}

/// Three blinking squares; decorative (the control or line next to it carries the meaning).
#[component]
pub fn Spinner() -> Element {
    rsx! {
        span { class: "w-spinner", aria_hidden: "true",
            i {}
            i {}
            i {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_is_clamped_and_rounded() {
        assert_eq!(percent(0.0), 0);
        assert_eq!(percent(0.454), 45);
        assert_eq!(percent(0.455), 46);
        assert_eq!(percent(1.7), 100);
        assert_eq!(percent(-0.2), 0);
        assert_eq!(percent(f64::NAN), 0);
    }

    /// "Not checked" never reads as fine (contract §1).
    #[test]
    fn verdicts_map_to_distinct_tones() {
        assert_eq!(Tone::from(Verdict::NotChecked), Tone::Unknown);
        assert_ne!(Tone::from(Verdict::NotChecked).class(), Tone::Ok.class());
        assert_eq!(Tone::from(Verdict::Fail).name(), "fail");
    }
}
