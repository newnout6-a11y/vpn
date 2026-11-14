use super::*;
use crate::test_support::{Served, Server, TestKey, sample_feed};

fn files(dir: &str, key: &TestKey, feed: &Feed) -> Vec<(String, Served)> {
    let bytes = serde_json::to_vec(feed).unwrap();
    let sig = key.sign(&bytes).into_bytes();
    vec![
        (
            format!("{dir}/update.json"),
            Served {
                body: bytes,
                ..Served::default()
            },
        ),
        (
            format!("{dir}/update.json.minisig"),
            Served {
                body: sig,
                ..Served::default()
            },
        ),
    ]
}

async fn serve(all: Vec<Vec<(String, Served)>>) -> Server {
    let flat: Vec<(String, Served)> = all.into_iter().flatten().collect();
    Server::start(flat.iter().map(|(p, s)| (p.as_str(), s.clone())).collect()).await
}

/// AT-11-010: the network check takes the first fresh feed whose signature verifies; a mirror
/// that is down or serves a feed signed by another key is passed over.
#[tokio::test]
async fn the_first_verified_fresh_feed_wins() {
    let (key, other) = (TestKey::new(), TestKey::new());
    let server = serve(vec![
        files("b", &other, &sample_feed(9)),
        files("c", &key, &sample_feed(5)),
    ])
    .await;
    let bases = [
        format!("{}a/", server.base),
        format!("{}b/", server.base),
        format!("{}c/", server.base),
    ];
    let bases: Vec<&str> = bases.iter().map(String::as_str).collect();
    let got = fetch_feed(&bases, &[Way::direct()], &[key.public()], 3)
        .await
        .unwrap();
    assert_eq!(
        (got.feed.seq, got.stale, got.source.via),
        (5, false, Via::Direct)
    );
    assert_eq!(got.source.host, "127.0.0.1");
    assert_eq!(
        verify(&got.bytes, &got.sig, &[key.public()]).unwrap(),
        got.feed
    );

    // Only the foreign-key mirror left: refused, never accepted.
    let err = fetch_feed(&bases[..2], &[Way::direct()], &[key.public()], 0)
        .await
        .unwrap_err();
    assert_eq!(err, FetchError::Refused(FeedError::Signature));
    assert_eq!(
        fetch_feed(&bases[..1], &[Way::direct()], &[key.public()], 0).await,
        Err(FetchError::Unreachable)
    );
}

/// A replayed (lower `seq`) feed is skipped for the next mirror; nothing newer = `Older`.
#[tokio::test]
async fn an_older_seq_is_skipped() {
    let key = TestKey::new();
    let server = serve(vec![
        files("a", &key, &sample_feed(4)),
        files("b", &key, &sample_feed(8)),
    ])
    .await;
    let (a, b) = (format!("{}a/", server.base), format!("{}b/", server.base));
    let got = fetch_feed(&[&a, &b], &[Way::direct()], &[key.public()], 6)
        .await
        .unwrap();
    assert_eq!(got.feed.seq, 8);
    assert_eq!(
        fetch_feed(&[&a], &[Way::direct()], &[key.public()], 6).await,
        Err(FetchError::Older)
    );
}

/// A feed issued more than 90 days ago is "stale" (never "up to date"), used only when no
/// mirror has a fresh one.
#[tokio::test]
async fn an_old_feed_is_stale() {
    let key = TestKey::new();
    let mut old = sample_feed(10);
    old.issued = "2026-01-01T00:00:00Z".into();
    let server = serve(vec![
        files("a", &key, &old),
        files("b", &key, &sample_feed(10)),
    ])
    .await;
    let (a, b) = (format!("{}a/", server.base), format!("{}b/", server.base));
    let got = fetch_feed(&[&a], &[Way::direct()], &[key.public()], 0)
        .await
        .unwrap();
    assert!(got.stale);
    let got = fetch_feed(&[&a, &b], &[Way::direct()], &[key.public()], 0)
        .await
        .unwrap();
    assert!(!got.stale);
    assert_eq!(
        freshness(&sample_feed(1), 2, Timestamp::now()),
        Freshness::Older
    );
    let mut bad = sample_feed(3);
    bad.issued = "yesterday".into();
    assert_eq!(freshness(&bad, 0, Timestamp::now()), Freshness::Stale);
}

/// A mirror that accepts connections and never answers (a frozen path to GitHub).
async fn frozen() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/a/", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    (base, task)
}

/// ops5: a frozen first mirror no longer holds the check for `FEED_TIMEOUT` per way (20 s, 40 s
/// with the session way): the next mirror starts after `HEAD_START` and its fresh feed wins;
/// json and signature come in one go. Measured here: before >= 20 s, after ~3 s.
#[tokio::test]
async fn a_frozen_mirror_gives_way_after_the_head_start() {
    let key = TestKey::new();
    let server = serve(vec![files("b", &key, &sample_feed(7))]).await;
    let (frozen, task) = frozen().await;
    let good = format!("{}b/", server.base);
    let started = std::time::Instant::now();
    let got = fetch_feed(&[&frozen, &good], &[Way::direct()], &[key.public()], 0)
        .await
        .unwrap();
    let took = started.elapsed();
    assert_eq!((got.feed.seq, got.stale), (7, false));
    assert!(took >= HEAD_START, "{took:?}");
    assert!(took < HEAD_START + Duration::from_secs(4), "{took:?}");
    assert_eq!(server.log.lock().len(), 2, "json and signature, once each");
    task.abort();
}

/// Mirrors that end without a fresh feed hand over at once, and every error keeps its rank:
/// a refused signature over an older feed over nothing.
#[tokio::test]
async fn ended_mirrors_hand_over_at_once() {
    let (key, other) = (TestKey::new(), TestKey::new());
    let server = serve(vec![
        files("old", &key, &sample_feed(2)),
        files("foreign", &other, &sample_feed(9)),
    ])
    .await;
    let base = |dir: &str| format!("{}{dir}/", server.base);
    let (missing, old, foreign) = (base("missing"), base("old"), base("foreign"));
    let started = std::time::Instant::now();
    let err = fetch_feed(
        &[&missing, &old, &foreign],
        &[Way::direct()],
        &[key.public()],
        5,
    )
    .await;
    assert_eq!(err, Err(FetchError::Refused(FeedError::Signature)));
    assert!(started.elapsed() < HEAD_START, "no head start waited");
    let err = fetch_feed(&[&old, &missing], &[Way::direct()], &[key.public()], 5).await;
    assert_eq!(err, Err(FetchError::Older));
}
