//! The descriptor strings parse, mean what they say, and the trusted-folder check refuses a
//! folder or binary that ordinary users can change (security model §3.1, §3.8).
use super::*;

fn admin_only(sddl: &str) -> bool {
    SecurityDescriptor::from_sddl(sddl)
        .expect("valid SDDL")
        .admin_only_writes()
}

#[test]
fn every_descriptor_parses() {
    for sddl in [
        PIPE_SDDL,
        SERVICE_SDDL,
        ADMIN_ONLY_DIR_SDDL,
        PRIVATE_DIR_SDDL,
    ] {
        SecurityDescriptor::from_sddl(sddl).expect(sddl);
    }
}

/// Review service-b2: the service's own files (users, kill-switch settings with exception paths,
/// its log) sit in a folder that grants other accounts nothing, not even reading: nobody else
/// can read them or hold them open against the service.
#[test]
fn the_private_folder_grants_users_nothing() {
    let any_right = |sddl: &str| {
        SecurityDescriptor::from_sddl(sddl)
            .expect("valid SDDL")
            .trusted_only(u32::MAX)
    };
    assert!(any_right(PRIVATE_DIR_SDDL));
    assert!(PRIVATE_DIR_SDDL.contains("D:P"), "nothing inherited");
    assert!(
        !any_right(ADMIN_ONLY_DIR_SDDL),
        "users read the data folder"
    );
    let files = crate::paths::DataFiles::new(Path::new(r"C:\data"));
    for file in [&files.users, &files.protection, &files.service_log] {
        assert_eq!(file.parent(), Some(files.private.as_path()), "{file:?}");
    }
}

/// The private folder as the service creates it really grants users nothing.
#[test]
#[ignore = "needs elevation"]
fn elevated_the_private_folder_grants_users_nothing() {
    assert!(vpnte_winnet::elevation::is_elevated(), "run elevated");
    let root = std::env::temp_dir().join(format!("vpnte-sddl-private-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let files = crate::paths::DataFiles::new(&root);
    let secured = files.secure();
    let verdict = (
        path_descriptor(&files.private).is_ok_and(|sd| sd.trusted_only(u32::MAX)),
        path_admin_only(&root),
    );
    let _ = std::fs::remove_dir_all(&root);
    secured.expect("data folders created");
    assert_eq!(verdict, (true, true));
}

#[test]
fn pipe_dacl_never_lets_users_create_instances() {
    // FILE_CREATE_PIPE_INSTANCE (= FILE_APPEND_DATA, 0x4) is what pipe squatting needs.
    let users = PIPE_SDDL
        .split(")(")
        .find(|ace| ace.ends_with(";IU)") || ace.ends_with(";IU"))
        .expect("an interactive-users ACE");
    let mask = users.split(';').nth(2).expect("mask");
    let mask = u32::from_str_radix(mask.trim_start_matches("0x"), 16).expect("hex mask");
    assert_eq!(mask, 0x0012_019b);
    assert_eq!(mask & 0x4, 0, "no FILE_CREATE_PIPE_INSTANCE");
    assert_eq!(mask & 0x3, 0x3, "read and write data");
    assert!(
        !PIPE_SDDL.contains("GRGW"),
        "GW includes FILE_CREATE_PIPE_INSTANCE"
    );
    assert!(PIPE_SDDL.starts_with("D:P"), "protected: nothing inherited");
    assert!(PIPE_NAME.starts_with(r"\\.\pipe\ProtectedPrefix\Administrators\"));
}

#[test]
fn service_sddl_gives_users_no_stop_or_config() {
    let users = SERVICE_SDDL
        .split(")(")
        .find(|ace| ace.contains(";;;IU"))
        .expect("interactive users");
    let rights = users.split(';').nth(2).expect("rights");
    for right in ["WP", "DT", "DC", "SD", "WD", "WO"] {
        assert!(
            !rights.as_bytes().chunks(2).any(|c| c == right.as_bytes()),
            "{right} in {rights}"
        );
    }
    assert!(rights.as_bytes().chunks(2).any(|c| c == b"RP"), "start");
}

#[test]
fn admin_only_folders_are_trusted_and_user_writable_ones_are_not() {
    assert!(admin_only(ADMIN_ONLY_DIR_SDDL));
    // Program Files' own shape: CREATOR OWNER inherit-only, TrustedInstaller full.
    assert!(admin_only(
        "O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464\
         D:PAI(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)\
         (A;OICIIO;GA;;;CO)(A;;FA;;;SY)(A;;0x1301bf;;;BA)(A;OICI;0x1200a9;;;BU)"
    ));
    for bad in [
        "O:BAD:(A;;FA;;;BU)",                  // users write
        "O:BAD:(A;;0x2;;;AU)",                 // add file
        "O:BAD:(A;;0x40;;;IU)",                // delete child
        "O:BAD:(A;;GW;;;WD)",                  // generic write for everyone
        "O:BUD:(A;;FA;;;SY)",                  // owned by users: they can rewrite the DACL
        "O:BA",                                // no DACL: everyone has full access
        "O:BAD:(A;;FA;;;S-1-5-21-1-2-3-1001)", // one ordinary account
    ] {
        assert!(!admin_only(bad), "{bad}");
    }
    // Users may read and execute: still trusted.
    assert!(admin_only(
        "O:SYD:(A;;FA;;;SY)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;WD)"
    ));
}

#[test]
fn user_folders_on_this_machine_are_refused() {
    // The test binary lives in the user's build folder: writable by its owner.
    let exe = std::env::current_exe().expect("test exe");
    assert!(!path_admin_only(&exe));
    assert!(!path_admin_only(&std::env::temp_dir()));
    assert!(!path_admin_only(Path::new(r"C:\no\such\file.exe")));
    // The reason names the file and its owner, so a refused install says what to fix.
    let reason = untrusted_reason(&exe).expect("refused");
    let name = exe
        .file_name()
        .expect("name")
        .to_string_lossy()
        .into_owned();
    assert!(
        reason.contains(&name) && reason.contains("owner S-1-5-"),
        "{reason}"
    );
    let missing = untrusted_reason(Path::new(r"C:\no\such\file.exe")).expect("refused");
    assert!(missing.contains("unreadable"), "{missing}");
}

/// A file an elevated installer writes into the admin-only folder is born owned by
/// Administrators, so the service's own check accepts it (CI: an elevated user's files were
/// owned by that user, and the service refused every Tunnel start with `service.folder.untrusted`).
#[test]
#[ignore = "needs elevation"]
fn elevated_installed_files_pass_the_trusted_folder_check() {
    assert!(vpnte_winnet::elevation::is_elevated(), "run elevated");
    let dir = std::env::temp_dir().join(format!("vpnte-sddl-owner-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    crate::paths::secure_dir(&dir).expect("admin-only folder");
    let file = dir.join("engine.exe");
    crate::install::pins::write_replacing(&file, b"bytes").expect("written");
    let verdict = (untrusted_reason(&dir), untrusted_reason(&file));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(verdict, (None, None));
}
