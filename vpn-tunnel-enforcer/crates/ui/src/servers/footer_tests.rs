//! p-live-fix 2: a modal's footer stays inside its dialog. On the owner's screen (200 % scale) the
//! three actions of the delete-group dialog ran out of the small dialog: «Отмена» stuck out on the
//! left. The CSS rules that guarantee the fit, and a layout model of the dialog with them.
use serde_json::Value;

const WIDGETS_CSS: &str = include_str!("../../assets/css/widgets.css");

/// The declarations of the rule whose selector is exactly `selector` (one rule per line or block).
fn rule(selector: &str) -> &'static str {
    let at = WIDGETS_CSS
        .match_indices(selector)
        .map(|(at, _)| at)
        .find(|&at| {
            let before = WIDGETS_CSS[..at].chars().next_back();
            let after = WIDGETS_CSS[at + selector.len()..].trim_start();
            matches!(before, None | Some('\n' | '}')) && after.starts_with('{')
        })
        .unwrap_or_else(|| panic!("no rule {selector}"));
    let body = &WIDGETS_CSS[at..];
    &body[body.find('{').unwrap() + 1..body.find('}').unwrap()]
}

/// Any number of actions fits: they wrap to new rows, a label wider than the dialog wraps inside
/// its button, and with three or more the way back keeps the left edge.
#[test]
fn modal_footers_wrap_instead_of_running_out() {
    assert!(rule(".w-modal-foot").contains("flex-wrap: wrap"));
    let buttons = rule(".w-modal-foot > .w-btn");
    for decl in ["max-width: 100%", "height: auto", "white-space: normal"] {
        assert!(buttons.contains(decl), "{decl}");
    }
    assert!(
        rule(".w-modal-foot:has(> :nth-child(3)) > :first-child").contains("margin-right: auto")
    );
}

/// A label's width, generously: 9 px per glyph of the 14 px semibold label, 16 px padding and a
/// 1 px border each side.
fn button_width(label: &str) -> f32 {
    label.chars().count() as f32 * 9.0 + 2.0 * 16.0 + 2.0
}

/// The rows a wrapping footer makes of `buttons` in `content` px (8 px gaps), as flexbox does.
fn rows(buttons: &[f32], content: f32) -> Vec<f32> {
    let mut rows: Vec<f32> = Vec::new();
    for &width in buttons {
        match rows.last_mut() {
            Some(row) if *row + 8.0 + width <= content => *row += 8.0 + width,
            _ => rows.push(width),
        }
    }
    rows
}

fn labels(json: &str) -> Vec<String> {
    let all: Value = serde_json::from_str(json).expect("locale json");
    let groups = &all["servers"]["groups"];
    ["deleteCancel", "deleteOnlyGroup", "deleteWithServers"]
        .iter()
        .map(|key| groups[key].as_str().expect(key).to_owned())
        .collect()
}

/// The delete dialog (medium, 560 px, 20 px padding) in both languages, at 100 % and in the
/// narrowest window a 200 % scale leaves (a 1280 px screen: 640 px, the dialog 48 px less): every
/// row and every button fits the dialog.
#[test]
fn the_delete_dialog_holds_its_three_actions() {
    let langs = [
        include_str!("../../assets/locales/ru.json"),
        include_str!("../../assets/locales/en.json"),
    ];
    for json in langs {
        let widths: Vec<f32> = labels(json).iter().map(|l| button_width(l)).collect();
        for dialog in [560.0_f32, 560.0_f32.min(640.0 - 48.0)] {
            let content = dialog - 2.0 * 20.0;
            assert!(widths.iter().all(|w| *w <= content), "{widths:?}");
            let rows = rows(&widths, content);
            assert!(rows.iter().all(|r| *r <= content), "{rows:?} in {content}");
        }
    }
    // Without wrapping, the old small dialog could not hold them in one row.
    let ru: Vec<f32> = labels(langs[0]).iter().map(|l| button_width(l)).collect();
    let one_row: f32 = ru.iter().sum::<f32>() + 2.0 * 8.0;
    assert!(one_row > 420.0 - 40.0, "{one_row}");
}
