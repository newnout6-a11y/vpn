//! Journal algorithm vectors (spec §7.6) on an in-memory backend.
use vpnte_base::{AppError, ErrorKind};

use super::*;
use crate::test_support::TempDir;
use crate::tweaks::test_support::Fake;

fn env(var: EnvVar) -> Target {
    Target::Env { var }
}

fn sz(s: &str) -> Val {
    Val::Sz(s.into())
}

fn soft_plan(url: &str) -> Vec<(Feature, Target, Val)> {
    EnvVar::ALL
        .into_iter()
        .map(|var| {
            let v = if var == EnvVar::NoProxy {
                "localhost,127.0.0.1,::1"
            } else {
                url
            };
            (Feature::SoftEnv, env(var), sz(v))
        })
        .collect()
}

fn corporate() -> Vec<(Target, Val)> {
    vec![
        (env(EnvVar::HttpProxy), sz("http://corporate:8080")),
        (env(EnvVar::HttpsProxy), sz("http://secure-corporate:8443")),
        (env(EnvVar::AllProxy), sz("socks5h://corporate:1080")),
        (env(EnvVar::NoProxy), sz("localhost,internal.corp")),
    ]
}

fn open(dir: &TempDir) -> Journal {
    Journal::open(dir.path(), no_registry)
}

/// AT-11-002 / F-183: apply, refresh with another endpoint, rollback to the originals exactly.
#[test]
fn refresh_keeps_the_original_baseline() {
    let dir = TempDir::new("tweaks");
    let journal = open(&dir);
    let fake = Fake::with(&corporate());
    journal
        .apply(&fake, &soft_plan("socks5h://127.0.0.1:10808"))
        .unwrap();
    assert_eq!(
        fake.get(&env(EnvVar::AllProxy)),
        sz("socks5h://127.0.0.1:10808")
    );
    assert_eq!(
        fake.get(&env(EnvVar::NoProxy)),
        sz("localhost,127.0.0.1,::1")
    );
    journal
        .apply(&fake, &soft_plan("http://127.0.0.1:10809"))
        .unwrap();
    assert_eq!(
        fake.get(&env(EnvVar::HttpProxy)),
        sz("http://127.0.0.1:10809")
    );
    let recs = journal.records(Feature::SoftEnv);
    assert_eq!(recs.len(), 4);
    assert_eq!(recs[0].baseline, sz("http://corporate:8080"));

    let report = journal.rollback(&fake, &[Feature::SoftEnv]);
    assert!(report.is_complete());
    assert_eq!(report.restored.len(), 4);
    for (t, v) in corporate() {
        assert_eq!(fake.get(&t), v);
    }
    assert!(!journal.is_applied(Feature::SoftEnv));
}

/// Originals only for two names: rollback writes those back and deletes the other two.
#[test]
fn absent_originals_are_deleted_on_rollback() {
    let dir = TempDir::new("tweaks");
    let journal = open(&dir);
    let fake = Fake::with(&[
        (env(EnvVar::HttpProxy), sz("http://corp:8080")),
        (env(EnvVar::NoProxy), sz("localhost")),
    ]);
    journal
        .apply(&fake, &soft_plan("socks5h://127.0.0.1:10808"))
        .unwrap();
    journal.rollback(&fake, &[Feature::SoftEnv]);
    assert_eq!(fake.get(&env(EnvVar::HttpProxy)), sz("http://corp:8080"));
    assert_eq!(fake.get(&env(EnvVar::NoProxy)), sz("localhost"));
    assert_eq!(fake.get(&env(EnvVar::HttpsProxy)), Val::Absent);
    assert_eq!(fake.get(&env(EnvVar::AllProxy)), Val::Absent);
    assert!(journal.records(Feature::SoftEnv).is_empty());
}

/// No records: rollback writes nothing; already-restored values cost no write either.
#[test]
fn nothing_to_do_means_no_writes() {
    let dir = TempDir::new("tweaks");
    let journal = open(&dir);
    let fake = Fake::with(&corporate());
    let report = journal.rollback(&fake, &[Feature::SoftEnv]);
    assert_eq!(report, RollbackReport::default());
    assert_eq!(fake.write_count(), 0);
    assert!(!journal.is_applied(Feature::SoftEnv));

    journal
        .apply(&fake, &soft_plan("socks5h://127.0.0.1:10808"))
        .unwrap();
    for (t, v) in corporate() {
        fake.set(&t, v); // someone already put the originals back
    }
    let writes = fake.write_count();
    let report = journal.rollback(&fake, &[Feature::SoftEnv]);
    assert_eq!(report.restored.len(), 4);
    assert_eq!(fake.write_count(), writes, "already restored: no write");
    assert_eq!(*fake.broadcasts.lock(), 1, "only the apply broadcast");
}

/// An unreadable original aborts the apply with zero writes and no record.
#[test]
fn unreadable_original_aborts_without_writes() {
    let dir = TempDir::new("tweaks");
    let journal = open(&dir);
    let fake = Fake::with(&corporate());
    fake.fail_read.lock().insert(env(EnvVar::AllProxy));
    let err = journal.apply(&fake, &soft_plan("socks5h://127.0.0.1:10808"));
    assert!(matches!(err, Err(TweakError::Unreadable(..))));
    assert_eq!(fake.write_count(), 0);
    assert!(!journal.is_applied(Feature::SoftEnv));
    let app: AppError = err.unwrap_err().into();
    assert_eq!(app.kind, ErrorKind::Permission);
    assert_eq!(app.user_msg().key, "automation.tweaks.unreadable");
}

/// A refresh failing midway puts the previous Soft values back and keeps the baseline.
#[test]
fn failed_refresh_restores_the_previous_values() {
    let dir = TempDir::new("tweaks");
    let journal = open(&dir);
    let fake = Fake::with(&corporate());
    journal
        .apply(&fake, &soft_plan("socks5h://127.0.0.1:10808"))
        .unwrap();
    fake.fail_write.lock().insert(env(EnvVar::AllProxy));
    let err = journal.apply(&fake, &soft_plan("http://127.0.0.1:10809"));
    assert!(matches!(err, Err(TweakError::Write(..))));
    for var in [EnvVar::HttpProxy, EnvVar::HttpsProxy, EnvVar::AllProxy] {
        assert_eq!(fake.get(&env(var)), sz("socks5h://127.0.0.1:10808"));
    }
    let recs = journal.records(Feature::SoftEnv);
    assert_eq!(recs.len(), 4);
    assert!(
        recs.iter()
            .all(|r| r.applied != sz("http://127.0.0.1:10809"))
    );
    fake.fail_write.lock().clear();
    assert!(journal.rollback(&fake, &[Feature::SoftEnv]).is_complete());
    for (t, v) in corporate() {
        assert_eq!(fake.get(&t), v);
    }
}

/// Rollback with one failing value: the others are restored, the failing record stays, and a
/// second rollback finishes the job.
#[test]
fn rollback_continues_past_a_failure() {
    for fault in ["write", "garble", "read"] {
        let dir = TempDir::new("tweaks");
        let journal = open(&dir);
        let fake = Fake::with(&corporate());
        journal
            .apply(&fake, &soft_plan("socks5h://127.0.0.1:10808"))
            .unwrap();
        let bad = env(EnvVar::HttpsProxy);
        match fault {
            "write" => fake.fail_write.lock().insert(bad.clone()),
            "garble" => fake.garble.lock().insert(bad.clone()),
            _ => fake.fail_read.lock().insert(bad.clone()),
        };
        let report = journal.rollback(&fake, &[Feature::SoftEnv]);
        assert_eq!(report.failed, vec![bad.clone()], "{fault}");
        assert_eq!(report.restored.len(), 3, "{fault}");
        assert_eq!(
            report.failure_msg().unwrap().key,
            "automation.tweaks.rollbackFailed"
        );
        assert_eq!(journal.records(Feature::SoftEnv).len(), 1, "{fault}");
        fake.fail_write.lock().clear();
        fake.garble.lock().clear();
        fake.fail_read.lock().clear();
        if fault == "garble" {
            fake.set(&bad, sz("socks5h://127.0.0.1:10808"));
        }
        assert!(
            journal.rollback(&fake, &[Feature::SoftEnv]).is_complete(),
            "{fault}"
        );
        assert!(!journal.is_applied(Feature::SoftEnv), "{fault}");
        for (t, v) in corporate() {
            assert_eq!(fake.get(&t), v, "{fault}");
        }
    }
}

/// AT-09-001 (F-121): a value the user changed after our apply survives the rollback.
#[test]
fn user_change_after_apply_is_kept() {
    let dir = TempDir::new("tweaks");
    let journal = open(&dir);
    let fake = Fake::with(&corporate());
    journal
        .apply(&fake, &soft_plan("socks5h://127.0.0.1:10808"))
        .unwrap();
    fake.set(&env(EnvVar::HttpProxy), sz("http://user:3128"));
    assert_eq!(journal.status(&fake, Feature::SoftEnv), TweakState::Drifted);
    let report = journal.rollback(&fake, &[Feature::SoftEnv]);
    assert_eq!(report.kept_user_value, vec![env(EnvVar::HttpProxy)]);
    assert_eq!(report.restored.len(), 3);
    assert_eq!(report.kept_msg().unwrap().args[0].1, "1");
    assert_eq!(fake.get(&env(EnvVar::HttpProxy)), sz("http://user:3128"));
    assert_eq!(
        fake.get(&env(EnvVar::NoProxy)),
        sz("localhost,internal.corp")
    );
    assert!(!journal.is_applied(Feature::SoftEnv));
}

/// `index.test.ts` compensation: env applied, then Git fails, so the env values are put back and
/// nothing stays journalled; a rollback of several features goes on past one failing feature.
#[test]
fn a_failing_target_undoes_the_whole_apply() {
    let dir = TempDir::new("tweaks");
    let journal = open(&dir);
    let fake = Fake::with(&corporate());
    let git = Target::Git {
        key: GitKey::HttpProxy,
    };
    let mut plan = soft_plan("socks5h://127.0.0.1:10808");
    plan.push((
        Feature::DevGit,
        git.clone(),
        Val::Text("socks5h://127.0.0.1:10808".into()),
    ));
    fake.fail_write.lock().insert(git.clone());
    assert!(journal.apply(&fake, &plan).is_err());
    for (t, v) in corporate() {
        assert_eq!(fake.get(&t), v);
    }
    assert_eq!(fake.get(&git), Val::Absent);
    assert!(!journal.is_applied(Feature::SoftEnv) && !journal.is_applied(Feature::DevGit));

    fake.fail_write.lock().clear();
    journal.apply(&fake, &plan).unwrap();
    fake.fail_read.lock().insert(git.clone());
    let report = journal.rollback(&fake, &[Feature::SoftEnv, Feature::DevGit]);
    assert_eq!(report.failed, vec![git.clone()]);
    assert_eq!(report.restored.len(), 4);
    assert!(journal.is_applied(Feature::DevGit) && !journal.is_applied(Feature::SoftEnv));
}

/// The journal is saved before the first write and survives a restart; a crash between the save
/// and the write leaves a record that a later rollback retires without writing.
#[test]
fn obligations_survive_a_restart() {
    let dir = TempDir::new("tweaks");
    let fake = Fake::with(&corporate());
    open(&dir)
        .apply(&fake, &soft_plan("socks5h://127.0.0.1:10808"))
        .unwrap();
    let journal = open(&dir);
    assert_eq!(journal.records(Feature::SoftEnv).len(), 4);
    assert!(journal.rollback(&fake, &[Feature::SoftEnv]).is_complete());
    for (t, v) in corporate() {
        assert_eq!(fake.get(&t), v);
    }

    // Intent saved, then "crash": the values were never written.
    let crashed = Fake::with(&corporate());
    crashed.fail_write.lock().insert(env(EnvVar::HttpProxy));
    let _ = open(&dir).apply(&crashed, &soft_plan("socks5h://127.0.0.1:10808"));
    let doc = TweakDoc {
        records: soft_plan("socks5h://127.0.0.1:10808")
            .into_iter()
            .zip(corporate())
            .map(|((f, t, v), (_, base))| Record {
                feature: f,
                target: t,
                baseline: base,
                applied: v,
                created: false,
            })
            .collect(),
        ..TweakDoc::default()
    };
    Store::<TweakDoc>::open(dir.path()).replace(doc).unwrap();
    let journal = open(&dir);
    let fresh = Fake::with(&corporate());
    assert_eq!(
        journal.rollback(&fresh, &[Feature::SoftEnv]).restored.len(),
        4
    );
    assert_eq!(fresh.write_count(), 0);
    assert!(!journal.is_applied(Feature::SoftEnv));
}

/// Status reads the values back: on, drifted, unknown, off.
#[test]
fn status_is_read_back() {
    let dir = TempDir::new("tweaks");
    let journal = open(&dir);
    let fake = Fake::with(&corporate());
    assert_eq!(journal.status(&fake, Feature::SoftEnv), TweakState::Off);
    journal
        .apply(&fake, &soft_plan("socks5h://127.0.0.1:10808"))
        .unwrap();
    assert_eq!(journal.status(&fake, Feature::SoftEnv), TweakState::On);
    fake.set(&env(EnvVar::NoProxy), Val::Absent);
    assert_eq!(journal.status(&fake, Feature::SoftEnv), TweakState::Drifted);
    fake.fail_read.lock().insert(env(EnvVar::HttpProxy));
    assert_eq!(journal.status(&fake, Feature::SoftEnv), TweakState::Unknown);
}

/// A container our first write created is pruned after the rollback, and only then.
#[test]
fn created_containers_are_pruned() {
    let dir = TempDir::new("tweaks");
    let journal = open(&dir);
    let fake = Fake::with(&corporate());
    let git = Target::Git {
        key: GitKey::HttpsProxy,
    };
    let plan = vec![(
        Feature::DevGit,
        git.clone(),
        Val::Text("http://127.0.0.1:1".into()),
    )];
    journal.apply(&fake, &plan).unwrap();
    assert!(journal.records(Feature::DevGit)[0].created);
    journal.apply(&fake, &plan).unwrap();
    assert!(
        journal.records(Feature::DevGit)[0].created,
        "kept across refreshes"
    );
    journal.rollback(&fake, &[Feature::DevGit]);
    assert_eq!(*fake.pruned.lock(), vec![git]);
    journal
        .apply(&fake, &soft_plan("socks5h://127.0.0.1:10808"))
        .unwrap();
    journal.rollback(&fake, &[Feature::SoftEnv]);
    assert_eq!(
        fake.pruned.lock().len(),
        1,
        "pre-existing values: nothing pruned"
    );
}

fn location_admit(hive: RegHive, key: &str, name: &str, v: &Val) -> bool {
    hive == RegHive::Hklm
        && key == r"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
        && name == "DisableLocation"
        && matches!(v, Val::Absent | Val::Dword(_))
}

/// B1 / L1: a doctored journal cannot steer an elevated write: records outside the allow-list
/// (an IFEO key, a file that is not ours, a value of the wrong type, a foreign block) are dropped
/// at load and never acted on.
#[test]
fn records_outside_the_allow_list_are_dropped() {
    let dir = TempDir::new("tweaks");
    let reg = |key: &str, name: &str, v: Val| Record {
        feature: Feature::LocationPrivacy,
        target: Target::Reg {
            hive: RegHive::Hklm,
            key: key.into(),
            name: name.into(),
        },
        baseline: Val::Absent,
        applied: v,
        created: false,
    };
    let location = r"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors";
    let ok = reg(location, "DisableLocation", Val::Dword(1));
    let block = |path: &str, text: &str| Record {
        feature: Feature::DevGradle,
        target: Target::Block {
            kind: BlockKind::Gradle,
            path: path.into(),
        },
        baseline: Val::Absent,
        applied: Val::Text(text.into()),
        created: false,
    };
    let ours = "# >>> VPN Tunnel Enforcer (managed) >>>\nsystemProp.socksProxyHost=127.0.0.1\n# <<< VPN Tunnel Enforcer <<<\n";
    let good_block = block(r"C:\Users\someone\.gradle\gradle.properties", ours);
    let records = vec![
        ok.clone(),
        reg(
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\x.exe",
            "Debugger",
            Val::Sz("evil.exe".into()),
        ),
        reg(location, "DisableLocation", Val::Sz("1".into())),
        block(r"C:\Windows\System32\drivers\etc\hosts", ours),
        block(r"C:\Users\someone\.gradle\..\x\gradle.properties", ours),
        block(r"\\server\share\gradle.properties", ours),
        block(r"\gradle.properties", ours),
        block(
            r"C:\Users\someone\.gradle\gradle.properties",
            "127.0.0.1 example.com\n",
        ),
        Record {
            feature: Feature::SoftEnv,
            target: env(EnvVar::HttpProxy),
            baseline: Val::Dword(7),
            applied: sz("socks5h://127.0.0.1:1"),
            created: false,
        },
        Record {
            feature: Feature::DevGit,
            target: env(EnvVar::NoProxy),
            baseline: Val::Absent,
            applied: sz("x"),
            created: false,
        },
        good_block.clone(),
    ];
    Store::<TweakDoc>::open(dir.path())
        .replace(TweakDoc {
            records,
            ..TweakDoc::default()
        })
        .unwrap();
    let journal = Journal::open(dir.path(), location_admit);
    assert_eq!(journal.records(Feature::LocationPrivacy), vec![ok]);
    assert_eq!(journal.records(Feature::DevGradle), vec![good_block]);
    assert!(journal.records(Feature::SoftEnv).is_empty());
    assert!(journal.records(Feature::DevGit).is_empty());
    let on_disk = Store::<TweakDoc>::open(dir.path()).snapshot();
    assert_eq!(
        on_disk.records.len(),
        2,
        "the rejected records are gone from the file"
    );
    assert!(
        Journal::open(dir.path(), no_registry)
            .records(Feature::LocationPrivacy)
            .is_empty()
    );
}

/// A record that does not parse is dropped alone; a corrupt file is moved aside with a warning
/// instead of being trusted or refusing Soft mode forever.
#[test]
fn damaged_journals_never_pass_as_clean() {
    let dir = TempDir::new("tweaks");
    let path = dir.path().join("tweaks.json");
    let good = r#"{"feature":"soft-env","target":{"t":"env","var":"HTTP_PROXY"},"baseline":{"t":"Absent"},"applied":{"t":"Sz","v":"socks5h://127.0.0.1:1"}}"#;
    let text = format!(r#"{{"schemaVersion":1,"records":[{good},{{"feature":"warp-drive"}}]}}"#);
    std::fs::write(&path, text).unwrap();
    let journal = open(&dir);
    assert_eq!(journal.records(Feature::SoftEnv).len(), 1);
    assert_eq!(journal.notice(), None);

    std::fs::write(&path, "{ not json").unwrap();
    let journal = open(&dir);
    assert!(!journal.is_applied(Feature::SoftEnv));
    assert_eq!(
        journal.notice().unwrap().key,
        "automation.tweaks.journalCorrupt"
    );
    let aside = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains("corrupt"))
        .count();
    assert_eq!(aside, 1);
    let fake = Fake::with(&corporate());
    journal
        .apply(&fake, &soft_plan("socks5h://127.0.0.1:10808"))
        .unwrap();
    assert!(
        journal.is_applied(Feature::SoftEnv),
        "the journal works again"
    );
}
