//! A window rebuilt after a WebView2 crash gets a new root over the same [`Inbox`]: commands of
//! later launches, toast clicks and notices keep arriving, those sent while no window was mounted
//! included.
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use dioxus::core::NoOpMutations;
use vpnte_base::types::{Level, Notice};

use super::*;

/// What the mounted roots received, as `<mount>:<item>`.
#[derive(Clone, Default)]
struct Seen(Rc<RefCell<Vec<String>>>);

impl Seen {
    /// The items received since the last call, sorted (each pump is its own task).
    fn take(&self) -> Vec<String> {
        let mut items = std::mem::take(&mut *self.0.borrow_mut());
        items.sort();
        items
    }
}

#[derive(Clone, Copy)]
struct MountNo(u32);

fn root() -> Element {
    let inbox = use_context::<Rc<Inbox>>();
    let seen = use_context::<Seen>();
    let MountNo(n) = use_context::<MountNo>();
    let log = move |item: String| seen.0.borrow_mut().push(format!("{n}:{item}"));
    use_commands(&inbox, {
        let log = log.clone();
        move |command| log(format!("{command:?}"))
    });
    use_clicks(&inbox, {
        let log = log.clone();
        move || log("click".into())
    });
    use_notices(&inbox, move |item| log(item.notice.title.key.to_string()));
    rsx! {}
}

fn notice(key: &'static str) -> InAppNotice {
    InAppNotice {
        notice: Notice::new(Level::Info, key),
        category: None,
        at: 0,
        popup: true,
    }
}

async fn settle(dom: &mut VirtualDom) {
    for _ in 0..6 {
        tokio::select! {
            () = dom.wait_for_work() => {}
            () = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
        dom.render_immediate(&mut NoOpMutations);
    }
}

/// p-webview-recover: the first root gets what is sent while it is mounted; once it is dropped
/// (the crashed window closed), the rebuilt root takes the receivers over, with what waited in
/// between.
#[tokio::test]
async fn the_wiring_reaches_a_rebuilt_root() {
    let (commands, commands_rx) = mpsc::unbounded_channel();
    let (clicks, clicks_rx) = mpsc::unbounded_channel();
    let (notices, notices_rx) = broadcast::channel(16);
    let inbox = Rc::new(Inbox::new(Some(commands_rx), clicks_rx, notices_rx));
    let seen = Seen::default();
    let mount = |n| {
        let mut dom = VirtualDom::new(root)
            .with_root_context(inbox.clone())
            .with_root_context(seen.clone())
            .with_root_context(MountNo(n));
        dom.rebuild_in_place();
        dom
    };
    let mut first = mount(1);
    settle(&mut first).await;
    commands.send(Command::Activate).unwrap();
    clicks.send(()).unwrap();
    notices.send(notice("a")).unwrap();
    settle(&mut first).await;
    assert_eq!(seen.take(), ["1:Activate", "1:a", "1:click"]);

    drop(first);
    commands
        .send(Command::OpenLink("vless://x".into()))
        .unwrap();
    clicks.send(()).unwrap();
    notices.send(notice("b")).unwrap();
    let mut second = mount(2);
    settle(&mut second).await;
    assert_eq!(seen.take(), ["2:OpenLink(\"vless://x\")", "2:b", "2:click"]);
    commands.send(Command::ShutdownForUpdate).unwrap();
    notices.send(notice("c")).unwrap();
    settle(&mut second).await;
    assert_eq!(seen.take(), ["2:ShutdownForUpdate", "2:c"]);
}

/// The start link is handed over once per process; the page shown is kept for the next root.
#[test]
fn the_start_link_is_handed_over_once_and_the_page_kept() {
    let (_, commands) = mpsc::unbounded_channel();
    let (_, clicks) = mpsc::unbounded_channel();
    let (_, notices) = broadcast::channel(1);
    let inbox = Inbox::new(Some(commands), clicks, notices);
    inbox.set_first_link(Some("vless://start".into()));
    assert_eq!(inbox.take_first_link().as_deref(), Some("vless://start"));
    assert_eq!(inbox.take_first_link(), None);
    assert_eq!(inbox.page(), Page::Dashboard);
    inbox.keep_page(Page::Settings);
    assert_eq!(inbox.page(), Page::Settings);
}
