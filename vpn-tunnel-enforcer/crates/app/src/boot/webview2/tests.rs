use std::cell::RefCell;
use std::path::{Path, PathBuf};

use vpnte_base::Msg;
use vpnte_base::i18n::Lang;

use super::{BOOTSTRAPPER, Host, Outcome, bootstrapper_in, classify, ensure_with};

/// A scripted host that records every box and install.
struct Fake {
    runtime: bool,
    bootstrapper: bool,
    yes: bool,
    outcome: Outcome,
    asked: RefCell<Vec<String>>,
    told: RefCell<Vec<Msg>>,
    installed: RefCell<u32>,
}

impl Fake {
    fn new(runtime: bool, bootstrapper: bool, yes: bool, outcome: Outcome) -> Self {
        Self {
            runtime,
            bootstrapper,
            yes,
            outcome,
            asked: RefCell::default(),
            told: RefCell::default(),
            installed: RefCell::default(),
        }
    }
}

impl Host for Fake {
    fn runtime(&self) -> bool {
        self.runtime
    }
    fn bootstrapper(&self) -> Option<PathBuf> {
        self.bootstrapper.then(|| PathBuf::from(BOOTSTRAPPER))
    }
    fn ask(&self, lines: &[Msg]) -> bool {
        self.asked
            .borrow_mut()
            .extend(lines.iter().map(|m| m.render(Lang::En)));
        self.yes
    }
    fn install(&self, exe: &Path) -> Outcome {
        assert!(exe.ends_with(BOOTSTRAPPER));
        *self.installed.borrow_mut() += 1;
        self.outcome
    }
    fn tell(&self, lines: &[Msg]) {
        self.told.borrow_mut().extend(lines.iter().cloned());
    }
}

fn locales() {
    vpnte_ui::lang::init_locales(&crate::svc_core::locale_layers());
}

/// The runtime is there (Windows 11, CI's runners): the window opens, nothing is asked or run.
#[test]
fn present_runtime_asks_nothing() {
    let host = Fake::new(true, true, true, Outcome::Failed(1));
    assert!(ensure_with(&host));
    assert!(host.asked.borrow().is_empty() && host.told.borrow().is_empty());
    assert_eq!(*host.installed.borrow(), 0);
}

/// Missing: the offer, and the window opens right after a successful install; a declined offer or a
/// cancelled progress window ends the start without another box.
#[test]
fn missing_runtime_is_offered_and_installed_on_yes() {
    locales();
    let host = Fake::new(false, true, true, Outcome::Ready);
    assert!(ensure_with(&host));
    assert_eq!(*host.installed.borrow(), 1);
    let asked = host.asked.borrow().join(" ");
    assert!(asked.contains("Microsoft Edge WebView2") && asked.contains("Install it now?"));
    assert!(asked.contains("no administrator rights"), "{asked}");
    assert!(host.told.borrow().is_empty());

    let declined = Fake::new(false, true, false, Outcome::Ready);
    assert!(!ensure_with(&declined));
    assert_eq!(*declined.installed.borrow(), 0);
    assert!(declined.told.borrow().is_empty());

    let cancelled = Fake::new(false, true, true, Outcome::Cancelled);
    assert!(!ensure_with(&cancelled));
    assert!(cancelled.told.borrow().is_empty());
}

/// Every unsuccessful install ends in one calm line that says what to do; without the bootstrapper next to
/// the app (a development build) the old text with Microsoft's page.
#[test]
fn every_failure_says_what_to_do_in_one_line() {
    locales();
    let cases = [
        (
            Outcome::Pending,
            "app.main.webview2.pending",
            "again in a minute",
        ),
        (
            Outcome::Offline,
            "app.main.webview2.offline",
            "Connect to the internet",
        ),
        (
            Outcome::Failed(0x8007_0005),
            "app.main.webview2.failed",
            "(code 0x80070005)",
        ),
    ];
    for (outcome, key, says) in cases {
        let host = Fake::new(false, true, true, outcome);
        assert!(!ensure_with(&host));
        let told = host.told.borrow();
        assert_eq!(told.len(), 1, "{outcome:?}");
        assert_eq!(told[0].key, key);
        for lang in [Lang::Ru, Lang::En] {
            let text = told[0].render(lang);
            assert!(!text.contains('!') && text != key, "{lang:?} {text}");
        }
        assert!(
            told[0].render(Lang::En).contains(says),
            "{}",
            told[0].render(Lang::En)
        );
    }
    let failed = Fake::new(false, true, true, Outcome::Failed(0x8004_0C01));
    assert!(!ensure_with(&failed));
    let ru = failed.told.borrow()[0].render(Lang::Ru);
    assert!(ru.contains("(код 0x80040C01)"), "{ru}");

    let bare = Fake::new(false, false, true, Outcome::Ready);
    assert!(!ensure_with(&bare));
    assert!(bare.asked.borrow().is_empty());
    assert_eq!(bare.told.borrow()[0].key, "ui.frame.webview2Missing");
    // Read from the fragments: which layers the process-wide catalogue holds depends on the test order.
    for fragment in [
        include_str!("../../../../ui/locales/ui-frame.ru.json"),
        include_str!("../../../../ui/locales/ui-frame.en.json"),
    ] {
        let text: serde_json::Value = serde_json::from_str(fragment).unwrap();
        let missing = text["ui"]["frame"]["webview2Missing"].as_str().unwrap();
        assert!(missing.contains("https://developer.microsoft.com/microsoft-edge/webview2/"));
    }
}

/// Microsoft documents only 0 = success; a missing runtime after exit 0 is still being installed
/// (WebView2Feedback #1349), WinHTTP / WinINet codes are a connection problem, the rest keeps its code.
#[test]
fn exit_codes_are_classified() {
    assert_eq!(classify(0), Outcome::Pending);
    for offline in [
        0x8007_2EE7,
        0x8007_2EFD,
        0x8007_2EFE,
        0x8007_2EE2,
        0x8007_2F8F,
    ] {
        assert_eq!(classify(offline), Outcome::Offline, "{offline:#x}");
    }
    for failed in [
        1,
        0x8007_0005,
        0x8007_0652,
        0x8004_0C01,
        0x8000_4005,
        0x8008_2EE7,
    ] {
        assert_eq!(classify(failed), Outcome::Failed(failed), "{failed:#x}");
    }
}

/// The app looks for the file the manifest installs under `resources/`; in the dev drop it is there once
/// `cargo xtask engines` ran (skipped quietly otherwise).
#[test]
fn bootstrapper_is_the_pinned_file_in_resources() {
    let manifest = include_str!("../../../../../resources/engines.toml");
    assert!(manifest.contains(&format!("install = \"resources/{BOOTSTRAPPER}\"")));
    let resources = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources"));
    assert_eq!(bootstrapper_in(&resources.join("absent")), None);
    if resources.join(BOOTSTRAPPER).is_file() {
        assert_eq!(
            bootstrapper_in(resources),
            Some(resources.join(BOOTSTRAPPER))
        );
    }
}

/// The real check (wry's, the one the window makes) sees a runtime wherever Microsoft's registry rule names
/// one (this PC, CI's runners), so such a start asks nothing; skipped where none is registered.
#[test]
fn real_detection_sees_a_registered_runtime() {
    use vpnte_winnet::registry::{Access, Hive, Key, View};
    const CLIENT: &str = r"Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
    let pv = |hive, path: String| {
        let key = Key::open(hive, &path, Access::Read, View::Native).ok()??;
        let version = key.string("pv").ok()??;
        (!version.is_empty() && version != "0.0.0.0").then_some(version)
    };
    let machine = pv(
        Hive::LocalMachine,
        format!(r"SOFTWARE\WOW6432Node\{CLIENT}"),
    );
    let Some(version) = machine.or_else(|| pv(Hive::CurrentUser, format!(r"Software\{CLIENT}")))
    else {
        eprintln!("skipped: no WebView2 runtime registered here");
        return;
    };
    let host = super::Windows { lang: Lang::En };
    assert!(host.runtime(), "registered {version}, but no runtime found");
}
