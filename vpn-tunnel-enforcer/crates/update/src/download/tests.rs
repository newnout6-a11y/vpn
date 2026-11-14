use super::*;
use crate::test_support::{Served, Server, TempDir};

const SHARING_VIOLATION: i32 = 32;

fn body() -> Vec<u8> {
    (0..200_000u32).map(|i| (i % 251) as u8).collect()
}

fn sha_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

async fn get(urls: &[String], size: u64, sha: &str, dir: &Path) -> Result<Verified, DownloadError> {
    let wanted = Wanted {
        urls,
        size,
        sha256: sha,
        name: "setup.exe",
    };
    download(
        &wanted,
        &[Way::direct()],
        dir,
        None,
        &CancellationToken::new(),
    )
    .await
}

/// The verified file is held: nobody can write, rename or delete it; no `.part` is left, and an
/// old `.part` of a crashed run is swept.
#[tokio::test]
async fn a_download_is_verified_and_held() {
    let dir = TempDir::new("dl");
    std::fs::write(dir.path().join("0123.part"), b"old").unwrap();
    let server = Server::start(vec![(
        "f",
        Served {
            body: body(),
            ..Served::default()
        },
    )])
    .await;
    let (tx, rx) = watch::channel(0);
    let urls = [format!("{}f", server.base)];
    let wanted = Wanted {
        urls: &urls,
        size: 200_000,
        sha256: &sha_hex(&body()),
        name: "setup.exe",
    };
    let got = download(
        &wanted,
        &[Way::direct()],
        dir.path(),
        Some(&tx),
        &CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(got.path, dir.path().join("setup.exe"));
    assert_eq!(*rx.borrow(), 200_000);
    let write = OpenOptions::new().write(true).open(&got.path).unwrap_err();
    assert_eq!(write.raw_os_error(), Some(SHARING_VIOLATION));
    assert!(std::fs::remove_file(&got.path).is_err());
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert_eq!(names, ["setup.exe"]);
    drop(got);
}

/// A source that sends more than the feed's size, or other bytes of the right size, is passed
/// over for the next URL; with no honest source the reason is the error.
#[tokio::test]
async fn too_large_and_wrong_bytes_move_on() {
    let dir = TempDir::new("dl-bad");
    let mut wrong = body();
    wrong[7] ^= 1;
    let mut big = body();
    big.push(0);
    let server = Server::start(vec![
        (
            "big",
            Served {
                body: big,
                ..Served::default()
            },
        ),
        (
            "wrong",
            Served {
                body: wrong,
                ..Served::default()
            },
        ),
        (
            "good",
            Served {
                body: body(),
                ..Served::default()
            },
        ),
    ])
    .await;
    let url = |p: &str| format!("{}{p}", server.base);
    let sha = sha_hex(&body());
    let got = get(
        &[url("big"), url("wrong"), url("good")],
        200_000,
        &sha,
        dir.path(),
    )
    .await;
    assert!(got.is_ok());
    drop(got);
    let err = get(&[url("big")], 200_000, &sha, dir.path())
        .await
        .unwrap_err();
    assert!(matches!(err, DownloadError::TooLarge), "{err:?}");
    let err = get(&[url("wrong")], 200_000, &sha, dir.path())
        .await
        .unwrap_err();
    assert!(matches!(err, DownloadError::Mismatch), "{err:?}");
    let err = get(&[url("missing")], 200_000, &sha, dir.path())
        .await
        .unwrap_err();
    assert!(matches!(err, DownloadError::Unreachable), "{err:?}");
}

/// A dropped transfer resumes with `Range` where the server allows it, and starts over where
/// it does not; the result is the same verified file either way.
#[tokio::test]
async fn a_dropped_transfer_resumes() {
    let dir = TempDir::new("dl-resume");
    let server = Server::start(vec![
        (
            "ranged",
            Served {
                body: body(),
                ranges: true,
                cut_after: Some(70_000),
            },
        ),
        (
            "plain",
            Served {
                body: body(),
                ranges: false,
                cut_after: Some(70_000),
            },
        ),
    ])
    .await;
    let sha = sha_hex(&body());
    drop(
        get(
            &[format!("{}ranged", server.base)],
            200_000,
            &sha,
            dir.path(),
        )
        .await
        .unwrap(),
    );
    drop(
        get(
            &[format!("{}plain", server.base)],
            200_000,
            &sha,
            dir.path(),
        )
        .await
        .unwrap(),
    );
    let log = server.log.lock().clone();
    let ranged: Vec<_> = log
        .iter()
        .filter(|(p, _)| p == "/ranged")
        .map(|(_, r)| *r)
        .collect();
    assert_eq!(ranged.len(), 2);
    assert_eq!(ranged[0], None);
    assert!(
        ranged[1].is_some_and(|n| n > 0 && n <= 70_000),
        "{ranged:?}"
    );
    assert_eq!(log.iter().filter(|(p, _)| p == "/plain").count(), 2);
}

/// A name that would leave the folder is refused before anything is written.
#[tokio::test]
async fn names_stay_inside_the_folder() {
    let dir = TempDir::new("dl-name");
    for name in [r"..\x.exe", "a/b.exe", ".hidden", "C:x.exe"] {
        let wanted = Wanted {
            urls: &[],
            size: 1,
            sha256: &"00".repeat(32),
            name,
        };
        let err = download(
            &wanted,
            &[Way::direct()],
            dir.path(),
            None,
            &CancellationToken::new(),
        )
        .await;
        assert!(matches!(err, Err(DownloadError::Io(_))), "{name}");
    }
}
