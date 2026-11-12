//! Headless tests of the support helpers: the Save dialog is built and read back but never shown
//! (CI has no desktop and nobody is at this one), the clipboard decoding runs on fake blocks.
use std::cell::Cell;
use std::collections::BTreeSet;

use vpnte_base::i18n::Lang;
use vpnte_base::{AppResult, ErrorKind, Msg};
use vpnte_profiles::model::TooLarge;
use windows::Win32::UI::Shell::{
    FOS_FILEMUSTEXIST, FOS_FORCEFILESYSTEM, FOS_NOREADONLYRETURN, FOS_OVERWRITEPROMPT,
    FOS_PATHMUSTEXIST,
};

use super::clipboard::{block_text, no_text};
use super::files::{
    OpenFile, SaveFile, StartFolder, configure_open, configure_save, file_name, in_sta, take_path,
};

/// A NUL-terminated UTF-16 block with `slack` units of junk after the terminator, as Windows
/// rounds clipboard allocations up.
fn block(text: &str, slack: usize) -> Vec<u16> {
    let mut units: Vec<u16> = text.encode_utf16().collect();
    units.push(0);
    units.extend(std::iter::repeat_n(u16::from(b'x'), slack));
    units
}

fn read(units: &[u16], limit: usize) -> Result<Option<String>, TooLarge> {
    block_text(units.len(), limit, |i| units[i])
}

/// Suggested names become valid Windows file names; good names stay as they are.
#[test]
fn file_names_are_made_valid_for_windows() {
    let cases = [
        (
            "vpn-tunnel-enforcer-diagnostics-2026-11-11.zip",
            "vpn-tunnel-enforcer-diagnostics-2026-11-11.zip",
        ),
        ("history 12:30.csv", "history 12_30.csv"),
        (
            r#"DE/Frankfurt | "fast" <1>?*\x.txt"#,
            "DE_Frankfurt _ _fast_ _1____x.txt",
        ),
        ("tab\there\u{0}.log", "tab_here_.log"),
        ("  name. . ", "name"),
        ("сервер 🇩🇪.txt", "сервер 🇩🇪.txt"),
        ("CON", "_CON"),
        ("nul.txt", "_nul.txt"),
        ("com1.tar.gz", "_com1.tar.gz"),
        ("Lpt9", "_Lpt9"),
        ("CON .txt", "_CON .txt"),
        ("COM10.txt", "COM10.txt"),
        ("console.txt", "console.txt"),
        ("auxiliary", "auxiliary"),
        ("", ""),
    ];
    for (input, expected) in cases {
        assert_eq!(file_name(input), expected, "{input:?}");
    }
}

/// The builder keeps the extension without its dot, file types in order, Documents by default.
#[test]
fn save_request_builder() {
    let req = SaveFile::new(Msg::new("t"), "a.zip", ".zip")
        .filter(Msg::new("zip"), "*.zip")
        .filter(Msg::new("all"), "*.*");
    assert_eq!(req.extension, "zip");
    assert_eq!(req.folder, StartFolder::Documents);
    let patterns: Vec<&str> = req.filters.iter().map(|(_, p)| p.as_str()).collect();
    assert_eq!(patterns, ["*.zip", "*.*"]);
    let req = req.in_folder(StartFolder::Desktop);
    assert_eq!(req.folder, StartFolder::Desktop);
    assert_eq!(SaveFile::new(Msg::new("t"), "a", "json").extension, "json");
}

/// Clipboard text ends at its NUL (the rounded-up tail is junk) and is trimmed, BOM included.
#[test]
fn clipboard_text_ends_at_the_terminator_and_is_trimmed() {
    let key = "vless://00000000-0000-0000-0000-000000000000@example.invalid:443#fake";
    assert_eq!(read(&block(key, 7), 1024), Ok(Some(key.to_owned())));
    let pasted = format!("\u{feff}  {key}\r\nss://fake@example.invalid:8388 \r\n");
    let expected = format!("{key}\r\nss://fake@example.invalid:8388");
    assert_eq!(read(&block(&pasted, 0), 1024), Ok(Some(expected)));
    // A block without a terminator is all text.
    let bare: Vec<u16> = "trojan://x@example.invalid:443".encode_utf16().collect();
    assert_eq!(
        read(&bare, 1024),
        Ok(Some("trojan://x@example.invalid:443".to_owned()))
    );
}

/// Nothing but spaces, an empty string or an empty block is "no text".
#[test]
fn blank_clipboard_text_is_none() {
    assert_eq!(read(&block(" \r\n\t\u{feff} ", 3), 64), Ok(None));
    assert_eq!(read(&block("", 0), 64), Ok(None));
    assert_eq!(read(&[], 64), Ok(None));
}

/// An unpaired surrogate (valid on the Windows clipboard, not in Rust) is replaced, not fatal.
#[test]
fn unpaired_surrogate_is_replaced() {
    let units = [0xD800, u16::from(b'a'), 0];
    assert_eq!(read(&units, 64), Ok(Some("\u{FFFD}a".to_owned())));
}

/// The limit counts UTF-8 bytes of the trimmed text, as the paste field does; the copied text
/// itself may not have more units than that either (the bound that keeps the read cheap).
#[test]
fn clipboard_limit_counts_utf8_bytes() {
    assert_eq!(read(&block("жжж", 0), 6), Ok(Some("жжж".to_owned())));
    assert_eq!(read(&block("жжж", 0), 5), Err(TooLarge));
    assert_eq!(read(&block("abc", 0), 3), Ok(Some("abc".to_owned())));
    assert_eq!(read(&block("abcd", 0), 3), Err(TooLarge));
    assert_eq!(read(&block("  abc  ", 0), 7), Ok(Some("abc".to_owned())));
    assert_eq!(read(&block("  abc  ", 0), 6), Err(TooLarge));
}

/// A huge block is never read past `limit + 1` units: the copy of a 100 MB text stays cheap.
#[test]
fn huge_block_is_read_only_up_to_the_limit() {
    let highest = Cell::new(0usize);
    let unit = |i: usize| {
        highest.set(highest.get().max(i));
        u16::from(b'a')
    };
    assert_eq!(block_text(1 << 40, 1000, unit), Err(TooLarge));
    assert_eq!(highest.get(), 1000);
}

/// The Save dialog object is created and set up for a request, then read back; it is never shown.
#[test]
fn save_dialog_is_set_up_without_being_shown() {
    let req = SaveFile::new(Msg::new("test.title"), "diagnostics 12:30.zip", "zip")
        .filter(Msg::new("test.zip"), "*.zip")
        .filter(Msg::new("test.all"), "*.*")
        .in_folder(StartFolder::Downloads);
    let (name, index, options) = in_sta(|| {
        let dialog = configure_save(&req, Lang::En)?;
        // SAFETY: getters of a live dialog; the name is the caller's to free (`take_path`).
        unsafe {
            Ok((
                take_path(dialog.GetFileName()?),
                dialog.GetFileTypeIndex()?,
                dialog.GetOptions()?,
            ))
        }
    })
    .expect("dialog set up");
    assert_eq!(name, std::path::PathBuf::from("diagnostics 12_30.zip"));
    assert_eq!(index, 1);
    for flag in [
        FOS_OVERWRITEPROMPT,
        FOS_FORCEFILESYSTEM,
        FOS_PATHMUSTEXIST,
        FOS_NOREADONLYRETURN,
    ] {
        assert!(options.contains(flag), "{flag:?}");
    }
}

/// No file types, no extension and every start folder are accepted as well.
#[test]
fn bare_save_requests_are_set_up_for_every_start_folder() {
    for folder in [
        StartFolder::Documents,
        StartFolder::Downloads,
        StartFolder::Desktop,
    ] {
        let req = SaveFile::new(Msg::new("test.title"), "export", "").in_folder(folder);
        let set_up = in_sta(|| configure_save(&req, Lang::Ru).map(drop));
        assert!(set_up.is_ok(), "{folder:?}: {set_up:?}");
    }
}

/// The Open dialog (domain lists, program picker) is set up for one existing file system file,
/// never shown.
#[test]
fn open_dialog_is_set_up_without_being_shown() {
    let req = OpenFile::new(Msg::new("test.title"))
        .filter(Msg::new("test.programs"), "*.exe")
        .filter(Msg::new("test.all"), "*.*");
    let (index, options) = in_sta(|| {
        let dialog = configure_open(&req, Lang::Ru)?;
        // SAFETY: getters of a live dialog on this COM thread.
        unsafe { Ok((dialog.GetFileTypeIndex()?, dialog.GetOptions()?)) }
    })
    .expect("dialog set up");
    assert_eq!(index, 1);
    for flag in [FOS_FILEMUSTEXIST, FOS_FORCEFILESYSTEM, FOS_PATHMUSTEXIST] {
        assert!(options.contains(flag), "{flag:?}");
    }
    assert!(!options.contains(FOS_OVERWRITEPROMPT));
}

/// Every `app.clickjack.*` key the code uses is in both fragments, and the fragments match.
#[test]
fn locale_fragments_cover_every_key_in_use() {
    let ru = keys(include_str!("../../locales/app-clickjack.ru.json"));
    let en = keys(include_str!("../../locales/app-clickjack.en.json"));
    assert_eq!(ru, en);
    let used: BTreeSet<String> = [include_str!("files.rs"), include_str!("clipboard.rs")]
        .iter()
        .flat_map(|source| {
            source.match_indices("\"app.clickjack.").map(|(at, _)| {
                let key = &source[at + 1..];
                key[..key.find('"').expect("closed string")].to_owned()
            })
        })
        .collect();
    assert_eq!(used, ru);
    let err = no_text();
    assert_eq!(err.kind, ErrorKind::Validation);
    assert_eq!(err.user_msg(), Msg::new("app.clickjack.clipboard.noText"));
}

/// Dotted keys of a nested i18next fragment.
fn keys(json: &str) -> BTreeSet<String> {
    fn walk(prefix: &str, value: &serde_json::Value, out: &mut BTreeSet<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    walk(&path, value, out);
                }
            }
            _ => {
                out.insert(prefix.to_owned());
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(
        "",
        &serde_json::from_str(json).expect("valid JSON"),
        &mut out,
    );
    out
}

/// The pool wrapper hands back the value and the error of the blocking call.
#[tokio::test]
async fn blocking_wrapper_passes_results_through() {
    assert_eq!(super::blocking(|| Ok(7)).await.ok(), Some(7));
    let err = super::blocking(|| -> AppResult<()> { Err(no_text()) })
        .await
        .err();
    assert_eq!(err.map(|e| e.kind), Some(ErrorKind::Validation));
}

/// The real clipboard: a fake key copied with winnet's secret clipboard reads back trimmed. It
/// replaces the user's clipboard, so only CI runs it (disposable runner).
#[tokio::test]
#[ignore = "changes system state"]
async fn system_clipboard_reads_back_copied_text() {
    let clip = vpnte_winnet::clipboard::SecretClipboard::start();
    let key = "vless://00000000-0000-0000-0000-000000000000@example.invalid:443#fake";
    clip.copy(&format!("  {key}\r\n")).expect("copied");
    let read = super::clipboard::read_text().await;
    clip.shutdown();
    assert_eq!(read.expect("read").as_deref(), Some(key));
}
