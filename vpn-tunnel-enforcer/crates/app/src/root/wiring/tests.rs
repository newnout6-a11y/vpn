//! A window rebuilt after a WebView2 crash gets a new root over the same [`Inbox`]: notices keep
//! arriving, those sent while no window was mounted included.
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
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.borrow_mut())
    }
}

#[derive(Clone, Copy)]
struct MountNo(u32);

fn root() -> Element {
    let inbox = use_context::<Rc<Inbox>>();
    let seen = use_context::<Seen>();
    let MountNo(n) = use_context::<MountNo>();
    use_notices(&inbox, move |item| {
        seen.0
            .borrow_mut()
            .push(format!("{n}:{}", item.notice.title.key));
    });
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
/// (the crashed window closed), the rebuilt root takes the receiver over, with what waited in
/// between.
#[tokio::test]
async fn the_wiring_reaches_a_rebuilt_root() {
    let (notices, notices_rx) = broadcast::channel(16);
    let inbox = Rc::new(Inbox::new(notices_rx));
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
    notices.send(notice("a")).unwrap();
    settle(&mut first).await;
    assert_eq!(seen.take(), ["1:a"]);

    drop(first);
    notices.send(notice("b")).unwrap();
    let mut second = mount(2);
    settle(&mut second).await;
    assert_eq!(seen.take(), ["2:b"]);
    notices.send(notice("c")).unwrap();
    settle(&mut second).await;
    assert_eq!(seen.take(), ["2:c"]);
}

/// The page shown is kept for the next root.
#[test]
fn the_page_shown_is_kept() {
    let (_, notices) = broadcast::channel(1);
    let inbox = Inbox::new(notices);
    assert_eq!(inbox.page(), Page::Dashboard);
    inbox.keep_page(Page::Settings);
    assert_eq!(inbox.page(), Page::Settings);
}
