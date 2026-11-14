use super::*;

fn temp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("vpnte-users-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("dir");
    dir
}

const A: &str = "S-1-5-21-1-2-3-1001";
const B: &str = "S-1-5-21-1-2-3-1002";

#[test]
fn the_last_user_leaving_is_reported_once() {
    let dir = temp("last");
    let path = dir.join("users.json");
    let users = Users::with_lookup(&path, |_| true);
    assert!(users.is_empty());
    users.add(A).expect("add");
    users.add(B).expect("add");
    users.add(B).expect("add twice");
    assert_eq!(Users::open(&path).len(), 2, "persisted");
    assert!(!users.remove(A).expect("remove"));
    assert!(users.remove(B).expect("remove"));
    assert!(!users.remove(B).expect("unknown"), "only once");
    assert!(Users::open(&path).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Review service-a8: a failed save changes nothing in memory, so a retry does the work.
#[test]
fn a_failed_save_changes_nothing() {
    let dir = temp("save");
    let path = dir.join("users.json");
    let users = Users::with_lookup(&path, |_| true);
    users.add(A).expect("add");
    // A folder where the temp file goes makes every save fail.
    let tmp = dir.join("users.json.tmp");
    std::fs::create_dir_all(&tmp).expect("block the temp file");
    users.add(B).expect_err("not saved");
    assert_eq!(users.len(), 1, "not kept either");
    users.remove(A).expect_err("not saved");
    assert_eq!(users.len(), 1, "still recorded");
    std::fs::remove_dir(&tmp).expect("unblock");
    assert!(
        users.remove(A).expect("retried"),
        "the retry sees the last user leave"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Review service-b5: accounts Windows no longer knows do not keep the service.
#[test]
fn deleted_accounts_do_not_count() {
    let dir = temp("prune");
    let path = dir.join("users.json");
    let users = Users::with_lookup(&path, |sid| sid != B);
    users.add(A).expect("add");
    users.add(B).expect("add");
    assert!(users.remove(A).expect("remove"), "B's account is gone");
    assert!(Users::open(&path).is_empty());
    assert!(account_exists("S-1-5-18"), "SYSTEM");
    assert!(!account_exists(A), "no such account");
    if let Some(sid) = session_user() {
        assert!(sid.starts_with("S-1-5-") && account_exists(&sid), "{sid}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
