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

/// speed3-a3: «Забыть меня» while the service keeps the user's session running: its names
/// still serve it, but its end never brings them back as his recent names (nor anyone's);
/// another user's running session keeps its owner.
#[tokio::test]
async fn a_forgotten_users_running_session_leaves_no_names() {
    let _one = SESSIONS.lock().await;
    let name = "forgotten.s3-09.invalid";
    let (a, b) = ("S-1-5-21-1-2-3-1003", "S-1-5-21-1-2-3-1004");
    let names = HashMap::from([(name.to_owned(), vec![ip("203.0.113.26")])]);
    *KEPT.lock() = Some(Kept {
        started: 79_000,
        owner: Some(a.to_owned()),
        names,
    });
    forget(b);
    let owner = || KEPT.lock().as_ref().and_then(|k| k.owner.clone());
    assert_eq!(owner().as_deref(), Some(a));
    forget(a);
    assert_eq!(owner(), None);
    assert_eq!(
        kept(name),
        Some(vec![ip("203.0.113.26")]),
        "still serves its run"
    );
    end_session();
    assert_eq!(recent_of(Some(a), name), None);
    assert_eq!(recent_of(Some(b), name), None);
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

/// Review tunready-a2: a profile keeps its host as written, the answers are stored by the parsed
/// (lowercase) name. A failed start or switch that dialled «Stale-Case…» drops both its kept and
/// its recent answer; before, the exact compare dropped nothing and every retry dialled them.
#[tokio::test]
async fn a_failed_start_drops_a_name_written_with_capitals() {
    let _one = SESSIONS.lock().await;
    let (written, stored) = ("Stale-Case.S3-09.invalid", "stale-case.s3-09.invalid");
    keep_resolved(80_000, &[(written.to_owned(), vec![ip("203.0.113.27")])]);
    remember(written, vec![ip("203.0.113.28")]);
    assert_eq!(kept(stored), Some(vec![ip("203.0.113.27")]), "kept");
    assert_eq!(recent(stored), Some(vec![ip("203.0.113.28")]), "recent");
    drop_names(&[written.to_owned()]);
    assert_eq!(kept(stored), None, "kept");
    assert_eq!(recent(stored), None, "recent");
    end_session();
}
