//! ks-d (research killswitch §3.1, §5.3, §5.4, §5.7): the lifetime of each set per owner, a
//! crashed service's block taken over by its restart, and the provider of "Always".
use super::*;

/// "If the VPN drops" in an app run as administrator: dynamic, gone with the process.
#[test]
fn app_on_drop_is_dynamic() {
    let (p, fake) = protection(KillSwitchLevel::Standard);
    p.startup().unwrap();
    p.connect_begin(&[], &[TUN_V4.into()]).unwrap();
    p.tun_up(7).unwrap();
    assert_eq!(fake.0.lock().lifetime, Some(Lifetime::Dynamic));
    p.tun_lost().unwrap();
    fake.clone().close_dynamic(); // the process died
    assert!(fake.groups(false).is_empty(), "nothing outlives the app");
}

/// AT-03-001 through the service: "If the VPN drops" is static there. The service crashes
/// while the drop is held; Windows restarts it, its start takes the block over without a gap,
/// the resumed session replaces it and a disconnect gives the internet back.
#[test]
fn service_on_drop_is_static_and_held_across_its_crash() {
    let (p, fake) = with_service(KillSwitchLevel::Standard);
    p.startup().unwrap();
    p.connect_begin(&[], &[TUN_V4.into()]).unwrap();
    p.tun_up(7).unwrap();
    assert_eq!(fake.0.lock().lifetime, Some(Lifetime::Static));
    p.tun_lost().unwrap();
    assert!(p.paused());
    drop(p); // crash: no shutdown
    fake.clone().close_dynamic();
    assert!(
        fake.has(false, "block4"),
        "a static block survives its owner"
    );

    let restarted = over(&fake, KillSwitchLevel::Standard, service_owner());
    fake.0.lock().churn.clear();
    restarted.startup().unwrap();
    assert!(restarted.paused() && fake.has(false, "block4"));
    // One transaction replaces the crashed run's set (the empty persistent sweep aside).
    let churn: Vec<_> = fake.0.lock().churn.clone();
    let changes: Vec<_> = churn.iter().filter(|c| **c != (0, 0)).collect();
    assert!(
        matches!(changes[..], [(d, a)] if d == a && *d > 0),
        "taken over in one transaction: {churn:?}"
    );
    assert_eq!(restarted.status().kill_switch, KillSwitchState::Blocking);

    restarted.connect_begin(&[], &[TUN_V4.into()]).unwrap();
    assert!(
        fake.has(false, "block4"),
        "the resumed connect keeps the block"
    );
    restarted.tun_up(9).unwrap();
    assert!(!restarted.paused() && fake.has(false, "tun"));
    restarted.disconnected().unwrap();
    assert!(fake.groups(false).is_empty() && fake.groups(true).is_empty());
}

/// A restarted service lets go of what does not hold a drop: a first connect's leak
/// protection set, or a block whose level is now Off; a planned stop removes a static set.
#[test]
fn service_releases_what_does_not_hold_a_drop() {
    let (p, fake) = with_service(KillSwitchLevel::Standard);
    p.startup().unwrap();
    p.connect_begin(&[], &[TUN_V4.into()]).unwrap();
    drop(p);
    assert!(fake.has(false, "dns") && !fake.has(false, "block4"));
    let restarted = over(&fake, KillSwitchLevel::Standard, service_owner());
    restarted.startup().unwrap();
    assert!(!restarted.paused() && fake.groups(false).is_empty());

    restarted.connect_begin(&[], &[TUN_V4.into()]).unwrap();
    restarted.tun_up(7).unwrap();
    restarted.tun_lost().unwrap();
    drop(restarted);
    let off = over(&fake, KillSwitchLevel::Off, service_owner());
    off.startup().unwrap();
    assert!(!off.paused() && fake.groups(false).is_empty());

    let (p, fake) = with_service(KillSwitchLevel::Standard);
    p.startup().unwrap();
    p.connect_begin(&[], &[TUN_V4.into()]).unwrap();
    p.tun_up(7).unwrap();
    p.shutdown();
    assert!(
        fake.groups(false).is_empty(),
        "a service stop removes its static set"
    );
}

/// "Always" in the service: persistent, under a provider registered with the service's name;
/// a provider without it (an app run as administrator made it) is re-created first.
#[test]
fn always_belongs_to_the_service_provider() {
    let fake = Fake::default();
    fake.0.lock().provider = Some(ProviderInfo {
        flags: 1,
        service_name: None,
    });
    fake.0.lock().apply(true, &[], &crate::wfp::spec::block4());
    let p = over(&fake, KillSwitchLevel::Strict, service_owner());
    p.startup().unwrap();
    let provider = fake.0.lock().provider.clone().expect("provider");
    assert_eq!(provider.service_name.as_deref(), Some("VpnteTestService"));
    assert!(fake.has(true, "block4"));
    p.connect_begin(&[], &[TUN_V4.into()]).unwrap();
    assert_eq!(fake.0.lock().lifetime, Some(Lifetime::Static));
    p.disconnected().unwrap();
    p.shutdown();
    assert!(
        fake.has(true, "block4"),
        "Always stays after the session and the stop"
    );

    let (app, fake) = protection(KillSwitchLevel::Standard);
    app.startup().unwrap();
    app.connect_begin(&[], &[TUN_V4.into()]).unwrap();
    let provider = fake.0.lock().provider.clone().expect("provider");
    assert_eq!(
        provider.service_name, None,
        "the app's provider names no service"
    );
}
