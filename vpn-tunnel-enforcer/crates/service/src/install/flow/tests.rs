//! The decision logic of install / uninstall against a recording fake: which steps run, in which
//! order, after which failure (reviews 4555679947 / 4555679938).
use std::cell::RefCell;
use std::path::PathBuf;

use vpnte_base::{AppError, AppResult, ErrorKind};

use super::*;

/// Records every call; the step named in `fail` fails (each time it runs).
#[derive(Default)]
struct Fake {
    calls: RefCell<Vec<&'static str>>,
    fail: Vec<&'static str>,
}

impl Fake {
    fn failing(steps: &[&'static str]) -> Self {
        Self {
            fail: steps.to_vec(),
            ..Self::default()
        }
    }

    fn run(&self, step: &'static str) -> AppResult<()> {
        self.calls.borrow_mut().push(step);
        if self.fail.contains(&step) {
            Err(AppError::new(ErrorKind::Internal).with_source(std::io::Error::other(step)))
        } else {
            Ok(())
        }
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.borrow().clone()
    }
}

impl Machine for Fake {
    fn set_enabled(&self, on: bool) -> AppResult<()> {
        self.run(if on { "enable" } else { "disable" })
    }
    fn stop(&self) -> AppResult<()> {
        self.run("stop")
    }
    fn start(&self) -> AppResult<()> {
        self.run("start")
    }
    fn place(&self) -> AppResult<PathBuf> {
        self.run("place").map(|()| PathBuf::from("svc.exe"))
    }
    fn remove_wfp(&self) -> AppResult<()> {
        self.run("wfp")
    }
    fn delete(&self) -> AppResult<()> {
        self.run("delete")
    }
    fn remove_folders(&self) -> AppResult<()> {
        self.run("folders")
    }
}

fn key(err: &AppError) -> String {
    err.user_msg().key.to_string()
}

#[test]
fn an_install_runs_stop_place_start() {
    let m = Fake::default();
    assert_eq!(install(&m).expect("installed"), PathBuf::from("svc.exe"));
    assert_eq!(m.calls(), ["disable", "stop", "place", "start"]);
}

/// Review 4555679947: a failure after the stop starts the service again and returns the original
/// error; nothing is placed after a stop that did not finish.
#[test]
fn a_failure_after_the_stop_starts_the_service_again() {
    let m = Fake::failing(&["place"]);
    let err = install(&m).expect_err("place failed");
    assert_eq!(m.calls(), ["disable", "stop", "place", "enable", "start"]);
    assert_eq!(err.kind, ErrorKind::Internal);
    assert_ne!(key(&err), NOT_RESTARTED, "the original error");

    let m = Fake::failing(&["stop"]);
    install(&m).expect_err("stop failed");
    assert_eq!(
        m.calls(),
        ["disable", "stop", "enable"],
        "still stopping: no start"
    );

    let m = Fake::failing(&["disable"]);
    install(&m).expect_err("nothing changed");
    assert_eq!(m.calls(), ["disable"]);
}

/// A service that cannot be started again is never a quiet failure: the error says it is stopped.
#[test]
fn a_service_that_does_not_start_again_is_reported() {
    let m = Fake::failing(&["place", "start"]);
    let err = install(&m).expect_err("place failed");
    assert_eq!(m.calls(), ["disable", "stop", "place", "enable", "start"]);
    assert_eq!(key(&err), NOT_RESTARTED);
    let source = format!("{:#}", err.source.expect("original kept as the source"));
    assert!(source.contains("place"), "{source}");
}

#[test]
fn an_uninstall_removes_everything() {
    let m = Fake::default();
    uninstall(&m).expect("removed");
    assert_eq!(m.calls(), ["disable", "stop", "wfp", "delete", "folders"]);
}

/// Review 4555679938: when the WFP clean-up fails the registration and the files stay and the
/// service runs again (a retry or its start-up removes the filters).
#[test]
fn a_failed_wfp_cleanup_keeps_the_service() {
    let m = Fake::failing(&["wfp"]);
    let err = uninstall(&m).expect_err("filters kept");
    assert_eq!(key(&err), FILTERS_KEPT);
    assert_eq!(m.calls(), ["disable", "stop", "wfp", "enable", "start"]);
}

/// Other failed steps do not stop the rest; the first one is reported.
#[test]
fn every_other_step_is_tried() {
    let m = Fake::failing(&["stop", "delete"]);
    let err = uninstall(&m).expect_err("stop failed");
    assert_eq!(m.calls(), ["disable", "stop", "wfp", "delete", "folders"]);
    let source = format!("{:#}", err.source.expect("source"));
    assert!(source.contains("stop"), "first failure: {source}");
}
