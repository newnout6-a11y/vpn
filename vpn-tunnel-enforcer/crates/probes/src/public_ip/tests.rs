use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures_util::future::BoxFuture;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// AT-07-007: Cloudflare trace (IPv4 / IPv6), JSON string and object, plain text.
#[test]
fn provider_bodies_parse() {
    let trace = "fl=84f22\nh=cloudflare.com\nip=203.0.113.195\nts=1726246345.123\nvisit_scheme=https\nuag=Mozilla/5.0";
    assert_eq!(parse_provider_body(trace), Some(ip("203.0.113.195")));
    let trace6 = "fl=84f22\nh=cloudflare.com\nip=2001:db8::1\nts=1726246345.123";
    assert_eq!(parse_provider_body(trace6), Some(ip("2001:db8::1")));
    let json = r#"{"ip":"198.51.100.42","country":"Germany"}"#;
    assert_eq!(parse_provider_body(json), Some(ip("198.51.100.42")));
    assert_eq!(
        parse_provider_body(r#"{"query":"198.51.100.77"}"#),
        Some(ip("198.51.100.77"))
    );
    assert_eq!(
        parse_provider_body("203.0.113.88\n"),
        Some(ip("203.0.113.88"))
    );
    assert_eq!(
        parse_provider_body("ip=1.1.1.1\r\nts=1\r\n"),
        Some(ip("1.1.1.1"))
    );
}

/// AT-07-007: "response did not contain a valid IP".
#[test]
fn junk_bodies_are_rejected() {
    for body in [
        "<html>502 Bad Gateway</html>",
        "",
        "{}",
        r#"{"ip":""}"#,
        "999.1.1.1",
        "{",
    ] {
        assert_eq!(parse_provider_body(body), None, "{body}");
    }
}

/// B-IP-5 / B-IP-3: non-public answers and the wrong family are not samples.
#[test]
fn acceptance_needs_public_address_of_the_family() {
    assert_eq!(accept(ip("8.8.8.8"), Family::V4), Ok(ip("8.8.8.8")));
    assert_eq!(accept(ip("::ffff:8.8.8.8"), Family::V4), Ok(ip("8.8.8.8")));
    assert_eq!(
        accept(ip("2606:4700:4700::1111"), Family::V4),
        Err(Fault::FamilyMismatch)
    );
    assert_eq!(
        accept(ip("8.8.8.8"), Family::V6),
        Err(Fault::FamilyMismatch)
    );
    for private in [
        "10.1.2.3",
        "100.64.0.1",
        "192.168.1.1",
        "203.0.113.5",
        "127.0.0.1",
    ] {
        assert_eq!(
            accept(ip(private), Family::V4),
            Err(Fault::NotPublic),
            "{private}"
        );
    }
    assert_eq!(accept(ip("fd00::1"), Family::V6), Err(Fault::NotPublic));
    assert_eq!(
        accept(ip("2001:4860:4860::8888"), Family::V6),
        Ok(ip("2001:4860:4860::8888"))
    );
}

/// AT-07-007: 429 backoff, seconds or HTTP date (B-IP-6), 60 s default, 300 s cap.
#[test]
fn retry_after_values() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    assert_eq!(retry_after(Some("60"), now), Duration::from_secs(60));
    assert_eq!(retry_after(Some(" 1.5 "), now), Duration::from_millis(1500));
    assert_eq!(retry_after(Some("100000"), now), BACKOFF_MAX);
    for fallback in [None, Some("0"), Some("-5"), Some("soon"), Some("NaN")] {
        assert_eq!(retry_after(fallback, now), BACKOFF_DEFAULT, "{fallback:?}");
    }
    // 1_700_000_000 = Tue, 14 Nov 2023 22:13:20 GMT
    let later = "Tue, 14 Nov 2023 22:15:20 GMT";
    assert_eq!(retry_after(Some(later), now), Duration::from_secs(120));
    let past = "Tue, 14 Nov 2023 22:00:00 GMT";
    assert_eq!(retry_after(Some(past), now), BACKOFF_DEFAULT);
    let far = "Wed, 15 Nov 2023 22:13:20 GMT";
    assert_eq!(retry_after(Some(far), now), BACKOFF_MAX);
}

#[test]
fn budget_is_capped() {
    assert_eq!(clamp_budget(Duration::ZERO), WAVE_BUDGET);
    assert_eq!(clamp_budget(Duration::from_secs(9)), WAVE_BUDGET);
    assert_eq!(
        clamp_budget(Duration::from_millis(600)),
        Duration::from_millis(600)
    );
    assert_eq!(Family::of(ip("::ffff:1.2.3.4")), Family::V4);
    assert_eq!(
        PROVIDERS[0].url(Family::V6),
        Some("https://[2606:4700:4700::1111]/cdn-cgi/trace")
    );
    assert_eq!(PROVIDERS[3].url(Family::V6), None);
}

type Asked = Arc<parking_lot::Mutex<Vec<(usize, tokio::time::Instant)>>>;

/// Scripted providers by index: `(delay ms, result)`; every start is recorded with its time.
fn scripted(
    plan: Vec<(u64, Result<IpAddr, Fault>)>,
) -> (
    impl FnMut(usize, &'static str) -> BoxFuture<'static, Result<IpAddr, Fault>>,
    Asked,
) {
    let asked = Asked::default();
    let record = asked.clone();
    let ask =
        move |index: usize, _url: &'static str| -> BoxFuture<'static, Result<IpAddr, Fault>> {
            record.lock().push((index, tokio::time::Instant::now()));
            let (delay, result) = plan[index];
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                result
            })
        };
    (ask, asked)
}

fn providers(n: usize) -> Vec<(usize, &'static str)> {
    (0..n).map(|i| (i, "https://provider.invalid/")).collect()
}

fn indices(asked: &Asked) -> Vec<usize> {
    asked.lock().iter().map(|(i, _)| *i).collect()
}

/// Consecutive starts keep the discipline's gap (no handshake burst through a tunnel).
fn assert_spaced(asked: &Asked) {
    for pair in asked.lock().windows(2) {
        assert!(
            pair[1].1 - pair[0].1 >= MIN_GAP,
            "{:?}",
            pair[1].1 - pair[0].1
        );
    }
}

/// AT-07-007 / AT-00-005: one provider rate-limited, the next answers; providers after the
/// answer are never asked (one connection at a time); all failing gives nothing.
#[tokio::test]
async fn a_wave_asks_one_provider_at_a_time_and_stops_at_the_first_answer() {
    let cancel = CancellationToken::new();
    let (ask, asked) = scripted(vec![
        (10, Err(Fault::RateLimited(BACKOFF_DEFAULT))),
        (50, Ok(ip("198.51.100.1"))),
        (5, Ok(ip("198.51.100.2"))),
        (5, Err(Fault::Timeout)),
    ]);
    let ended = first_answer(providers(4), ask, WAVE_BUDGET, &cancel).await;
    assert_eq!(ended, Ended::Answer(1, ip("198.51.100.1")));
    assert_eq!(indices(&asked), [0, 1]);
    assert_spaced(&asked);

    let (failing, asked) = scripted(vec![(5, Err(Fault::Network)); 4]);
    let ended = first_answer(providers(4), failing, WAVE_BUDGET, &cancel).await;
    assert_eq!(ended, Ended::Failed);
    assert_eq!(indices(&asked), [0, 1, 2, 3]);
    assert_spaced(&asked);
}

/// AT-07-007: a provider that hangs uses up the wave (no second connection) and cannot
/// stretch it; a gap that would end past the budget asks nobody; cancel ends it at once.
#[tokio::test]
async fn a_wave_respects_budget_and_cancel() {
    let cancel = CancellationToken::new();
    let (hang, asked) = scripted(vec![(5_000, Ok(ip("1.1.1.1"))), (5, Ok(ip("8.8.8.8")))]);
    let started = Instant::now();
    let ended = first_answer(providers(2), hang, Duration::from_millis(300), &cancel).await;
    assert_eq!(ended, Ended::Hung(0));
    assert_eq!(indices(&asked), [0]);
    assert!(started.elapsed() < Duration::from_millis(1000));

    let (fail_fast, asked) = scripted(vec![(5, Err(Fault::Connect)), (5, Ok(ip("8.8.8.8")))]);
    let ended = first_answer(providers(2), fail_fast, Duration::from_millis(300), &cancel).await;
    assert_eq!(ended, Ended::Failed);
    assert_eq!(indices(&asked), [0]);

    // The request's own timeout fires DRAIN before the wave's: still a hang, nobody else asked.
    let (timed_out, asked) = scripted(vec![(5, Err(Fault::Timeout)), (5, Ok(ip("8.8.8.8")))]);
    let ended = first_answer(providers(2), timed_out, WAVE_BUDGET, &cancel).await;
    assert_eq!(ended, Ended::Hung(0));
    assert_eq!(indices(&asked), [0]);

    let child = cancel.child_token();
    let cancel_later = child.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel_later.cancel();
    });
    let (pending, _) = scripted(vec![(500, Ok(ip("1.1.1.1")))]);
    let started = Instant::now();
    assert_eq!(
        first_answer(providers(1), pending, WAVE_BUDGET, &child).await,
        Ended::Cancelled
    );
    assert!(started.elapsed() < Duration::from_millis(400));
}

/// The provider that answered opens the next wave; one that hung hands the first turn on;
/// failures and cancels change nothing; providers in backoff are left out.
#[test]
fn the_last_answer_opens_the_next_wave() {
    let order = |reader: &IpReader, family| -> Vec<usize> {
        reader.order(family).iter().map(|(i, _)| *i).collect()
    };
    let reader = IpReader::new();
    assert_eq!(order(&reader, Family::V4), [0, 1, 2, 3]);
    assert_eq!(
        reader.settle(Ended::Answer(2, ip("198.51.100.7"))),
        Some((2, ip("198.51.100.7")))
    );
    assert_eq!(order(&reader, Family::V4), [2, 3, 0, 1]);
    assert_eq!(order(&reader, Family::V6), [2, 0, 1]);
    assert_eq!(reader.settle(Ended::Hung(3)), None);
    assert_eq!(order(&reader, Family::V4), [0, 1, 2, 3]);
    assert_eq!(reader.settle(Ended::Hung(0)), None);
    assert_eq!(order(&reader, Family::V4), [1, 2, 3, 0]);
    assert_eq!(reader.settle(Ended::Failed), None);
    assert_eq!(reader.settle(Ended::Cancelled), None);
    assert_eq!(order(&reader, Family::V4), [1, 2, 3, 0]);
    reader
        .backoff
        .lock()
        .insert(PROVIDERS[2].v4, Instant::now() + Duration::from_secs(60));
    assert_eq!(order(&reader, Family::V4), [1, 3, 0]);
}

/// A one-shot HTTP/1.1 server on loopback that answers every request with `response`.
async fn serve(response: &'static str) -> (&'static str, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 2048];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });
    (
        Box::leak(format!("http://127.0.0.1:{port}/").into_boxed_str()),
        hits,
    )
}

fn direct_client() -> reqwest::Client {
    build_client(&IpRoute::Direct, Family::V4, Duration::from_secs(2)).unwrap()
}

/// AT-07-007: a 429 puts the provider into backoff for its `Retry-After`.
#[tokio::test]
async fn rate_limit_sets_backoff() {
    let (url, _) = serve("HTTP/1.1 429 Too Many Requests\r\nretry-after: 120\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
    let reader = IpReader::new();
    let result = reader.fetch(0, &direct_client(), url, Family::V4).await;
    assert_eq!(result, Err(Fault::RateLimited(Duration::from_secs(120))));
    let until = *reader.backoff.lock().get(url).unwrap();
    assert!(until > Instant::now() + Duration::from_secs(110));
}

/// Body parsing end to end; private answers and oversized bodies are refused.
#[tokio::test]
async fn fetch_parses_and_filters_answers() {
    let reader = IpReader::new();
    let client = direct_client();
    let (ok, _) = serve("HTTP/1.1 200 OK\r\ncontent-length: 22\r\nconnection: close\r\n\r\n{\"ip\":\"8.8.4.4\",\"x\":1}").await;
    assert_eq!(
        reader.fetch(1, &client, ok, Family::V4).await,
        Ok(ip("8.8.4.4"))
    );
    let (private, _) =
        serve("HTTP/1.1 200 OK\r\ncontent-length: 9\r\nconnection: close\r\n\r\n10.0.0.1\n").await;
    assert_eq!(
        reader.fetch(1, &client, private, Family::V4).await,
        Err(Fault::NotPublic)
    );
    let big: &'static str = Box::leak(
        format!(
            "HTTP/1.1 200 OK\r\ncontent-length: 5000\r\nconnection: close\r\n\r\n{}",
            "1".repeat(5000)
        )
        .into_boxed_str(),
    );
    let (large, _) = serve(big).await;
    assert_eq!(
        reader.fetch(1, &client, large, Family::V4).await,
        Err(Fault::TooLarge)
    );
    let (status, _) =
        serve("HTTP/1.1 503 Busy\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
    assert_eq!(
        reader.fetch(1, &client, status, Family::V4).await,
        Err(Fault::Status(503))
    );
}

/// A TUN route without an IPv6 address has no IPv6 path: no request, no sample.
#[tokio::test]
async fn tun_route_without_v6_has_no_v6_path() {
    let route = IpRoute::Tun {
        v4: Ipv4Addr::new(192, 168, 250, 253),
        v6: None,
    };
    assert!(route.is_tun());
    let cancel = CancellationToken::new();
    assert_eq!(
        IpReader::new()
            .wave(&route, Family::V6, WAVE_BUDGET, &cancel)
            .await,
        None
    );
    cancel.cancel();
    assert_eq!(
        IpReader::new()
            .wave(&IpRoute::Direct, Family::V4, WAVE_BUDGET, &cancel)
            .await,
        None
    );
}

/// Names resolve to the wave's family only; a loopback route needs a real port.
#[tokio::test]
async fn resolver_keeps_one_family() {
    use reqwest::dns::Resolve;
    let name: reqwest::dns::Name = "localhost".parse().unwrap();
    let addrs: Vec<_> = FamilyResolver(Family::V4)
        .resolve(name)
        .await
        .unwrap()
        .collect();
    assert!(!addrs.is_empty());
    assert!(addrs.iter().all(|a| a.is_ipv4()));
    let lo = IpRoute::Loopback(Loopback {
        port: 0,
        creds: None,
    });
    assert!(matches!(
        build_client(&lo, Family::V4, WAVE_BUDGET),
        Err(Fault::NoPath)
    ));
}

/// Live providers, once, over the plain route. Run by hand: `cargo test … -- --ignored`.
#[tokio::test]
#[ignore = "calls the public IP providers"]
async fn live_wave_reads_a_public_ipv4() {
    let cancel = CancellationToken::new();
    let sample = IpReader::new()
        .wave(&IpRoute::Direct, Family::V4, WAVE_BUDGET, &cancel)
        .await
        .expect("a provider answered");
    assert!(sample.ip.is_ipv4() && net::is_public_ip(sample.ip));
    assert!(usize::from(sample.provider) < PROVIDERS.len());
}
