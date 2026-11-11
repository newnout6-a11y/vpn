//! The transfer check against the scripted SOCKS5 far side (plain TCP after the CONNECT:
//! `Wire::plain`), standing in for the probe engine and the far side of the tunnel.
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use super::super::far_side::{Answer, download, far_side, head, trace};
use super::super::transfer::{Limits, Trace, Transfer, TransferReport, check};
use crate::live::wire::Wire;

/// Short limits so the stalls take a fraction of a second.
const FAST: Limits = Limits {
    first_byte: Duration::from_millis(800),
    gap: Duration::from_millis(300),
    deadline: Duration::from_secs(5),
};

async fn report(answers: Vec<Answer>, with_trace: bool) -> TransferReport {
    let (inbound, task) = far_side(answers).await;
    let cancel = CancellationToken::new();
    let out = check(&Wire::plain(), &inbound, with_trace, FAST, &cancel)
        .await
        .unwrap();
    task.abort();
    out
}

async fn run(answers: Vec<Answer>, with_trace: bool) -> (Transfer, Option<Trace>) {
    let r = report(answers, with_trace).await;
    (r.transfer, r.trace)
}

/// The trace and 64 KiB on one connection: complete, with the exit IP, country and the round
/// trip to the first answer.
#[tokio::test]
async fn a_full_download_passes_with_the_trace() {
    let r = report(vec![trace(), Answer::Send(download(64 * 1024))], true).await;
    assert!(r.transfer.complete(), "{r:?}");
    let (ip, country) = r.trace.expect("trace");
    assert_eq!(ip, "185.220.101.5".parse().ok());
    assert_eq!(
        country.map(|c| c.as_str().to_owned()),
        Some("NL".to_owned())
    );
    assert!(r.answer_ms.is_some_and(|ms| ms < 2000), "{r:?}");
}

/// The trace survives a transfer that then freezes (the exit IP is still evidence).
#[tokio::test]
async fn the_trace_is_kept_when_the_transfer_freezes() {
    let r = report(
        vec![trace(), Answer::SendThenHang(download(15 * 1024))],
        true,
    )
    .await;
    assert!(r.transfer.frozen(), "{r:?}");
    assert!(r.trace.is_some());
}

/// Fact (b): 16 KiB, then silence without FIN or RST, is the freeze signature, not "healthy"
/// (a short answer would have looked fine).
#[tokio::test]
async fn a_stall_after_16_kib_is_a_freeze() {
    let (transfer, _) = run(vec![Answer::SendThenHang(download(16 * 1024))], false).await;
    let Transfer::Stalled { bytes } = transfer else {
        panic!("{transfer:?}");
    };
    assert!(bytes > 16 * 1024 && bytes < 17 * 1024, "{bytes}");
    assert!(transfer.frozen());
}

/// A stall at another volume is a stall, not the freeze signature.
#[tokio::test]
async fn a_stall_after_40_kib_is_no_freeze() {
    let (transfer, _) = run(vec![Answer::SendThenHang(download(40 * 1024))], false).await;
    assert!(matches!(transfer, Transfer::Stalled { .. }), "{transfer:?}");
    assert!(!transfer.frozen());
}

/// Nothing back at all; an HTTP error after data; a body cut short by a close.
#[tokio::test]
async fn silence_errors_and_early_close_are_told_apart() {
    let (transfer, _) = run(vec![Answer::Hang], false).await;
    assert_eq!(transfer, Transfer::NoData);
    let (transfer, _) = run(vec![Answer::Send(head("403 Forbidden", 0))], false).await;
    assert!(
        matches!(&transfer, Transfer::Failed { bytes, error } if *bytes > 0 && error == "http status 403"),
        "{transfer:?}"
    );
    let (transfer, _) = run(vec![Answer::SendThenClose(download(1000))], false).await;
    assert!(
        matches!(&transfer, Transfer::Failed { error, .. } if error.starts_with("closed after")),
        "{transfer:?}"
    );
}
