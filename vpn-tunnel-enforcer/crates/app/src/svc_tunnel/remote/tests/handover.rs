//! speed3 S3-06 (b): the user's routing inputs reach the service while it is idle: right after
//! the connection's Hello made it the controller, before any start, and again after every Smart
//! RU list update (lab live-10 L10-3: the service checked the lists inside the first start).
use super::*;

/// The app's inputs, changed by the test.
struct Mine(Mutex<UserInputs>);

#[async_trait]
impl InputsSource for Mine {
    async fn snapshot(&self) -> AppResult<UserInputs> {
        Ok(self.0.lock().clone())
    }
}

/// Waits (bounded) until the service's inputs satisfy `seen`.
async fn service_sees(inputs: &SharedInputs, seen: impl Fn(&UserInputs) -> bool) -> bool {
    let wait = async {
        while !seen(&inputs.get()) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(Duration::from_secs(5), wait)
        .await
        .is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_inputs_go_after_hello_and_after_a_list_update() {
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let pipe = pipe_name(n);
    let dir = TempDir::new(&format!("remote-handover-{n}"));
    let listener = Listener::bind(&pipe_config(&pipe)).expect("private pipe");
    let runtime = FakeRuntime::new();
    let inputs = Arc::new(SharedInputs::new(None));
    let host = Host::new(HostDeps {
        runtime: runtime.clone(),
        kill_switch: kill_switch(),
        inputs: inputs.clone(),
        users: Arc::new(Users::open(&dir.0.join("users.json"))),
        check: admit_all(),
        on_last_user: Arc::new(|| {}),
        service_version: "2.0.0-test".into(),
        refuse_tunnel: None,
    });
    let cancel = CancellationToken::new();
    tokio::spawn(host.serve(listener, cancel.clone()));
    let mine = Arc::new(Mine(Mutex::new(UserInputs {
        public_wifi: true,
        ..UserInputs::default()
    })));
    let protection = Arc::new(Store::<ProtectionDoc>::open(&dir.0));
    let r = Remote::on_pipe(&pipe, mine.clone(), protection);
    let (lists, updates) = watch::channel(0_u64);
    r.hand_over_updates(updates, cancel.clone());
    assert!(!inputs.get().public_wifi);
    r.attach().await;
    assert!(
        service_sees(&inputs, |i| i.public_wifi).await,
        "handed over at the Hello"
    );
    assert_eq!(runtime.starts.load(Ordering::SeqCst), 0, "before any start");
    mine.0.lock().stealth = true;
    lists.send_replace(1);
    assert!(
        service_sees(&inputs, |i| i.stealth).await,
        "handed over after the update"
    );
    assert_eq!(
        runtime.starts.load(Ordering::SeqCst),
        0,
        "nothing restarted"
    );
    cancel.cancel();
}
