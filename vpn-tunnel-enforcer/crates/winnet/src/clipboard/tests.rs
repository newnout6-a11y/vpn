use super::*;

/// Clipboard stand-in: a sequence number, the text, and failure switches.
#[derive(Default)]
struct Fake {
    seq: u32,
    text: Option<String>,
    fail_writes: bool,
    no_sequence: bool,
    busy_clears: u32,
    clears: u32,
}

#[derive(Clone, Default)]
struct Shared(Arc<parking_lot::Mutex<Fake>>);

impl Shared {
    fn text(&self) -> Option<String> {
        self.0.lock().text.clone()
    }
    fn clears(&self) -> u32 {
        self.0.lock().clears
    }
    /// The user or another program changes the clipboard.
    fn external_change(&self, text: Option<&str>) {
        let mut fake = self.0.lock();
        fake.seq += 1;
        if let Some(text) = text {
            fake.text = Some(text.into());
        }
    }
}

impl Clip for Shared {
    fn write(&self, text: &str) -> AppResult<u32> {
        let mut fake = self.0.lock();
        if fake.fail_writes {
            return Err(AppError::msg(
                ErrorKind::Conflict,
                Msg::new("winnet.clipboard.busy"),
            ));
        }
        fake.seq += 1;
        fake.text = Some(text.into());
        Ok(if fake.no_sequence { 0 } else { fake.seq })
    }
    fn clear_if(&self, seq: u32) -> Result<bool> {
        let mut fake = self.0.lock();
        if fake.busy_clears > 0 {
            fake.busy_clears -= 1;
            return Err(Error::from_hresult(E_FAIL));
        }
        if fake.seq != seq {
            return Ok(false);
        }
        fake.seq += 1;
        fake.text = None;
        fake.clears += 1;
        Ok(true)
    }
}

fn core(fake: &Shared) -> Core {
    Core {
        clip: Box::new(fake.clone()),
        owned: Mutex::new(None),
        wake: Notify::new(),
    }
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// AT-01-008: 60 s, still there at 59 999 ms, cleared exactly once at 60 000 ms.
#[test]
fn clears_exactly_once_at_the_deadline() {
    let (fake, t0) = (Shared::default(), Instant::now());
    let core = core(&fake);
    assert_eq!(
        core.copy("vless://fake-key", t0).unwrap(),
        Duration::from_secs(60)
    );
    assert_eq!(core.tick(t0 + ms(59_999)), Some(t0 + ms(60_000)));
    assert_eq!(fake.text().as_deref(), Some("vless://fake-key"));
    assert_eq!(core.tick(t0 + ms(60_000)), None);
    assert_eq!((fake.text(), fake.clears()), (None, 1));
    core.tick(t0 + ms(61_000));
    assert_eq!(fake.clears(), 1);
}

/// AT-01-008: the user copied something else, or another app added formats: never cleared.
#[test]
fn content_changed_by_others_is_never_cleared() {
    for user_text in [Some("user text"), None] {
        let (fake, t0) = (Shared::default(), Instant::now());
        let core = core(&fake);
        core.copy("vless://fake-key", t0).unwrap();
        fake.external_change(user_text);
        assert_eq!(core.tick(t0 + ms(60_000)), None, "ownership dropped");
        assert_eq!(fake.clears(), 0);
        core.tick(t0 + ms(120_000));
        assert_eq!(fake.clears(), 0);
    }
}

/// AT-01-008: OLD at 0 s, NEW at 30 s: NEW survives 60 s and is cleared at 90 s.
#[test]
fn a_newer_copy_moves_the_deadline() {
    let (fake, t0) = (Shared::default(), Instant::now());
    let core = core(&fake);
    core.copy("old", t0).unwrap();
    core.copy("new", t0 + ms(30_000)).unwrap();
    assert_eq!(core.tick(t0 + ms(60_000)), Some(t0 + ms(90_000)));
    assert_eq!(fake.text().as_deref(), Some("new"));
    core.tick(t0 + ms(90_000));
    assert_eq!((fake.text(), fake.clears()), (None, 1));
}

/// AT-01-008: a failed write of NEW keeps OLD's deadline.
#[test]
fn a_failed_write_keeps_the_previous_deadline() {
    let (fake, t0) = (Shared::default(), Instant::now());
    let core = core(&fake);
    core.copy("old", t0).unwrap();
    fake.0.lock().fail_writes = true;
    let err = core.copy("new", t0 + ms(30_000)).unwrap_err();
    assert_eq!(err.user_msg().key, "winnet.clipboard.busy");
    assert_eq!(core.tick(t0 + ms(30_001)), Some(t0 + ms(60_000)));
    core.tick(t0 + ms(60_000));
    assert_eq!((fake.text(), fake.clears()), (None, 1));
}

/// AT-01-008: a clipboard that cannot be opened at the deadline is retried 5 s later.
#[test]
fn a_busy_clipboard_is_retried_after_5_s() {
    let (fake, t0) = (Shared::default(), Instant::now());
    let core = core(&fake);
    core.copy("vless://fake-key", t0).unwrap();
    fake.0.lock().busy_clears = 1;
    assert_eq!(core.tick(t0 + ms(60_000)), Some(t0 + ms(65_000)));
    assert_eq!(core.tick(t0 + ms(64_999)), Some(t0 + ms(65_000)));
    assert_eq!(fake.clears(), 0);
    assert_eq!(core.tick(t0 + ms(65_000)), None);
    assert_eq!(fake.clears(), 1);
}

/// AT-01-008: ownership not established at copy time (no sequence number): never cleared.
#[test]
fn unknown_ownership_is_never_cleared() {
    let (fake, t0) = (Shared::default(), Instant::now());
    fake.0.lock().no_sequence = true;
    let core = core(&fake);
    core.copy("vless://fake-key", t0).unwrap();
    assert_eq!(core.tick(t0 + ms(600_000)), None);
    assert_eq!(fake.clears(), 0);
}

/// AT-00-003: shutdown clears now and stops the clearing task.
#[tokio::test]
async fn shutdown_clears_now_and_stops_the_task() {
    let fake = Shared::default();
    let clipboard = SecretClipboard::with_clip(Box::new(fake.clone()));
    clipboard.copy("vless://fake-key").unwrap();
    clipboard.shutdown();
    assert_eq!((fake.text(), fake.clears()), (None, 1));
    assert!(clipboard.stop.is_cancelled());
    assert_eq!(clipboard.core.tick(Instant::now() + CLEAR_AFTER), None);
    assert_eq!(fake.clears(), 1);
}

/// The clearing task wakes up for a new copy and clears it once due.
#[tokio::test]
async fn the_task_clears_when_due() {
    let fake = Shared::default();
    let clipboard = SecretClipboard::with_clip(Box::new(fake.clone()));
    clipboard.copy("not due yet").unwrap();
    tokio::time::sleep(ms(100)).await;
    assert_eq!(fake.clears(), 0);
    // A copy made "60 s ago" is due right away.
    let past = Instant::now().checked_sub(CLEAR_AFTER).unwrap();
    clipboard.core.copy("vless://fake-key", past).unwrap();
    for _ in 0..250 {
        if fake.clears() > 0 {
            break;
        }
        tokio::time::sleep(ms(20)).await;
    }
    assert_eq!((fake.text(), fake.clears()), (None, 1));
}

/// The owner window lives on its own message-pump thread (never the caller's, so a clear
/// cannot wait for a blocked UI thread) and is destroyed with the clipboard object.
#[test]
fn the_owner_window_has_its_own_thread_and_goes_away() {
    use windows::Win32::UI::WindowsAndMessaging::IsWindow;
    let clip = SystemClipboard::new();
    let hwnd = HWND(clip.owner as *mut c_void);
    // SAFETY: `IsWindow` accepts any value; `GetCurrentThreadId` has no preconditions.
    let alive = || unsafe { IsWindow(Some(hwnd)) }.as_bool();
    assert!(clip.owner != 0 && alive());
    assert_ne!(clip.pump, unsafe { GetCurrentThreadId() });
    drop(clip);
    for _ in 0..200 {
        if !alive() {
            return;
        }
        std::thread::sleep(ms(10));
    }
    panic!("the owner window outlived its clipboard");
}

fn real_formats() -> Vec<u32> {
    use windows::Win32::System::DataExchange::EnumClipboardFormats;
    let _session = Session::open(0).unwrap();
    let mut formats = Vec::new();
    let mut format = 0;
    loop {
        // SAFETY: the clipboard is open.
        format = unsafe { EnumClipboardFormats(format) };
        if format == 0 {
            return formats;
        }
        formats.push(format);
    }
}

fn real_text() -> Option<String> {
    use windows::Win32::Foundation::HGLOBAL;
    use windows::Win32::System::DataExchange::GetClipboardData;
    let _session = Session::open(0).unwrap();
    // SAFETY: the clipboard is open; the block is only read while locked and NUL-terminated.
    unsafe {
        let handle = GetClipboardData(u32::from(CF_UNICODETEXT.0)).ok()?;
        let mem = HGLOBAL(handle.0);
        let ptr = GlobalLock(mem).cast::<u16>();
        let mut units = Vec::new();
        while !ptr.is_null() && *ptr.add(units.len()) != 0 {
            units.push(*ptr.add(units.len()));
        }
        let _ = GlobalUnlock(mem);
        Some(String::from_utf16_lossy(&units))
    }
}

/// Writes, verifies the markers, clears, and checks that someone else's change is kept.
/// Puts the user's plain text back (marked private, so no new history entry); skips when
/// the clipboard holds anything that cannot be restored faithfully, or cannot be opened at all
/// (a sandboxed shell, a session without a desktop).
#[test]
#[ignore = "changes system state"]
fn system_clipboard_round_trip() {
    const TEXT_FORMATS: [u32; 4] = [1, 7, 13, 16]; // CF_TEXT, CF_OEMTEXT, CF_UNICODETEXT, CF_LOCALE
    if let Err(e) = Session::open(0) {
        eprintln!("skipped: the clipboard is not accessible from this process: {e}");
        return;
    }
    if !real_formats().iter().all(|f| TEXT_FORMATS.contains(f)) {
        eprintln!("skipped: the clipboard holds non-text content");
        return;
    }
    let saved = real_text();
    let clip = SystemClipboard::new();
    assert_ne!(clip.owner, 0, "the owner window exists");

    let seq = clip.write("vpnte-test-secret").unwrap();
    assert_ne!(seq, 0);
    assert_eq!(real_text().as_deref(), Some("vpnte-test-secret"));
    let formats = real_formats();
    for name in PRIVACY_FORMATS {
        assert!(formats.contains(&registered(name).unwrap()));
    }
    assert!(clip.clear_if(seq).unwrap());
    assert!(real_formats().is_empty());

    let seq = clip.write("vpnte-test-secret").unwrap();
    clip.write("someone else").unwrap();
    assert!(!clip.clear_if(seq).unwrap());
    assert_eq!(real_text().as_deref(), Some("someone else"));

    match saved {
        Some(text) => {
            clip.write(&text).unwrap();
        }
        None => {
            let _session = Session::open(0).unwrap();
            // SAFETY: the clipboard is open.
            unsafe { EmptyClipboard() }.unwrap();
        }
    }
}
