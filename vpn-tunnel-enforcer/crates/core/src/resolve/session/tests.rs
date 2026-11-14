//! speed3 S3-09: the names of ended sessions (memory only, per Windows user, 10 min).
use std::net::IpAddr;

use super::*;
use crate::resolve::resolve_server;
use crate::resolve::tests::SESSIONS;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("ip")
}

/// S3-09 (a): a name its session dialled answers for 10 min after the session ended, from
/// memory (the documentation address proves no resolver was asked), then it is gone.
#[tokio::test(start_paused = true)]
async fn an_ended_sessions_name_answers_for_ten_minutes() {
    let _one = SESSIONS.lock().await;
    let name = "recent.s3-09.invalid";
    keep_resolved(77_000, &[(name.to_owned(), vec![ip("203.0.113.21")])]);
    assert_eq!(kept(name), Some(vec![ip("203.0.113.21")]), "kept");
    end_session();
    assert_eq!(recent(name), Some(vec![ip("203.0.113.21")]), "recent");
    assert!(!running());
    let found = resolve_server(name, |_| true).await.expect("recent");
    assert_eq!(
        (found.addrs, found.last_known),
        (vec![ip("203.0.113.21")], false)
    );
    tokio::time::advance(RECENT_FOR).await;
    assert_eq!(recent(name), None);
}

/// S3-09 (Sec): the helper service keeps the names per Windows user: a session's names return
/// to the user it ran for, another user never gets them, «Забыть меня» drops them.
#[tokio::test]
async fn two_users_never_see_each_others_names() {
    let _one = SESSIONS.lock().await;
    let name = "sids.s3-09.invalid";
    let (a, b) = ("S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002");
    let names = HashMap::from([(name.to_owned(), vec![ip("203.0.113.22")])]);
    *KEPT.lock() = Some(Kept {
        started: 78_000,
        owner: Some(a.to_owned()),
        names,
    });
    end_session();
    assert_eq!(recent_of(Some(a), name), Some(vec![ip("203.0.113.22")]));
    assert_eq!(recent_of(Some(b), name), None);
    assert_eq!(recent_of(None, name), None);
    remember_of(Some(b.to_owned()), name, vec![ip("203.0.113.23")]);
    assert_eq!(recent_of(Some(a), name), Some(vec![ip("203.0.113.22")]));
    forget(a);
    assert_eq!(recent_of(Some(a), name), None);
    assert_eq!(recent_of(Some(b), name), Some(vec![ip("203.0.113.23")]));
    forget(b);
}

/// S3-09 (e): a start that failed with a remembered answer drops it: the next one asks.
#[tokio::test]
async fn a_failed_start_drops_its_remembered_names() {
    let _one = SESSIONS.lock().await;
    let name = "stale.s3-09.invalid";
    remember(name, vec![ip("203.0.113.24")]);
    assert_eq!(recent(name), Some(vec![ip("203.0.113.24")]));
    drop_names(&[name.to_owned()]);
    assert_eq!(recent(name), None);
    // Literals and empty answers are never remembered.
    remember("203.0.113.25", vec![ip("203.0.113.25")]);
    remember("empty.s3-09.invalid", Vec::new());
    assert_eq!(recent("empty.s3-09.invalid"), None);
}
