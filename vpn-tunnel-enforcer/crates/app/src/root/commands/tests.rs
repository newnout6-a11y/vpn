//! The commands against fakes: nothing waits for a window, and the installer's request ends even
//! a hidden app whose cleanup hangs, in bounded time, with 73.
use parking_lot::Mutex;
use tokio::time::Instant;

use super::*;

/// What the fake app was asked to do, in order.
#[derive(Clone, Default)]
struct Fake {
    events: Arc<Mutex<Vec<String>>>,
    /// The cleanup's duration; `None`: it never ends.
    cleanup: Option<Duration>,
}

impl Fake {
    fn log(&self, event: impl Into<String>) {
        self.events.lock().push(event.into());
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().clone()
    }
}

impl Effects for Fake {
    // A hidden app: the window never answers; nothing may wait for it.
    fn show(&self) {
        self.log("show");
    }

    fn hide(&self) {
        self.log("hide");
    }

    fn offer(&self, link: String) {
        self.log(format!("offer {link}"));
    }

    fn cleanup(&self) -> Work {
        let (fake, duration) = (self.clone(), self.cleanup);
        Box::pin(async move {
            match duration {
                Some(duration) => tokio::time::sleep(duration).await,
                None => std::future::pending().await,
            }
            fake.log("cleaned");
        })
    }

    fn exit(&self, code: u8) {
        self.log(format!("exit {code}"));
    }
}

fn channel(commands: &[Command]) -> mpsc::UnboundedReceiver<Command> {
    let (tx, rx) = mpsc::unbounded_channel();
    for command in commands {
        tx.send(command.clone()).unwrap();
    }
    rx
}

/// p-exit-gate: `activate` and a link reach the window and the add dialog without the UI, and
/// the start's link goes to the add dialog first.
#[tokio::test]
async fn activate_and_links_show_the_window_without_the_ui() {
    let fake = Fake::default();
    let commands = channel(&[Command::Activate, Command::OpenLink("vless://x".into())]);
    spawn(None, Some("vless://start".into()), Arc::new(fake.clone()));
    serve(commands, Arc::new(fake.clone())).await;
    assert_eq!(
        fake.events(),
        ["offer vless://start", "show", "offer vless://x", "show"]
    );
}

/// p-exit-gate (owner, 15.11: setup «просто встал»): the installer's request ends a hidden app
/// with 73 as soon as the cleanup is done; nothing after it is served.
#[tokio::test(start_paused = true)]
async fn the_installer_ends_a_hidden_app_with_73() {
    let fake = Fake {
        cleanup: Some(Duration::from_secs(5)),
        ..Fake::default()
    };
    let commands = channel(&[Command::ShutdownForUpdate, Command::Activate]);
    let started = Instant::now();
    serve(commands, Arc::new(fake.clone())).await;
    assert_eq!(started.elapsed(), Duration::from_secs(5));
    assert_eq!(fake.events(), ["hide", "cleaned", "exit 73"]);
}

/// A cleanup that never ends does not keep the installer waiting: 73 after the budget.
#[tokio::test(start_paused = true)]
async fn a_hanging_cleanup_still_ends_with_73_in_bounded_time() {
    let fake = Fake::default();
    let commands = channel(&[Command::ShutdownForUpdate]);
    let started = Instant::now();
    serve(commands, Arc::new(fake.clone())).await;
    assert_eq!(started.elapsed(), UPDATE_BUDGET);
    assert_eq!(fake.events(), ["hide", "exit 73"]);
}
