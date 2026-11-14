//! DNS profiles, domain rules and the domain-list import.
use vpnte_base::ErrorKind;
use vpnte_ui::settings::{self as ui, SettingsApi};

use super::super::super::SettingsService;
use super::super::super::rules;
use super::super::super::test_support::FakeAutostart;
use super::{setup, until};

/// DNS: a bad address says why; a profile is created, chosen, shown and deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_profiles_round_trip() {
    let (shared, _, _, _dir) = setup("dns", false, FakeAutostart::default());
    let api = SettingsService(shared.clone());
    assert_eq!(
        api.validate_dns("tls://dns.example".into())
            .await
            .expect("dot"),
        ui::DnsKind::Dot
    );
    let bad = api
        .create_dns("Bad".into(), "ftp://x".into())
        .await
        .expect_err("refused");
    assert_eq!(bad.kind, ErrorKind::Validation);
    api.create_dns("Lab".into(), "192.0.2.53".into())
        .await
        .expect("created");
    let view = until(&api.dns(), |d| d.profiles.iter().any(|p| p.name == "Lab")).await;
    let id = view
        .profiles
        .iter()
        .find(|p| p.name == "Lab")
        .map(|p| p.id.clone())
        .expect("listed");
    api.select_dns(Some(id.clone())).await.expect("selected");
    until(&api.dns(), |d| d.active.as_deref() == Some(id.as_str())).await;
    api.select_dns(None).await.expect("automatic");
    api.delete_dns(id.clone()).await.expect("deleted");
    api.delete_dns(id).await.expect("already gone is fine");
    until(&api.dns(), |d| d.profiles.iter().all(|p| p.name != "Lab")).await;
}

/// Domain rules: add (a bad pattern says why), update, reorder (unknown ids ignored), delete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn domain_rules_round_trip() {
    let (shared, _, _, _dir) = setup("domains", false, FakeAutostart::default());
    let api = SettingsService(shared.clone());
    let bad = api
        .add_domain_rule("192.0.2.1".into(), ui::DomainAction::Vpn)
        .await
        .expect_err("ip literal");
    assert_eq!(bad.kind, ErrorKind::Validation);
    api.add_domain_rule("example.com".into(), ui::DomainAction::Vpn)
        .await
        .expect("added");
    api.add_domain_rule("*.example.org".into(), ui::DomainAction::Direct)
        .await
        .expect("added");
    let view = until(&api.domains(), |d| d.rules.len() == 2).await;
    let (first, second) = (view.rules[0].id.clone(), view.rules[1].id.clone());
    api.reorder_domain_rules(vec![second.clone(), "unknown".into(), first.clone()])
        .await
        .expect("reordered");
    until(&api.domains(), |d| d.rules[0].id == second).await;
    api.update_domain_rule(first.clone(), "example.net".into(), ui::DomainAction::Block)
        .await
        .expect("updated");
    let view = until(&api.domains(), |d| d.rules[1].pattern == "example.net").await;
    assert_eq!(view.rules[1].action, ui::DomainAction::Block);
    let gone = api
        .update_domain_rule("unknown".into(), "a.example".into(), ui::DomainAction::Vpn)
        .await
        .expect_err("gone");
    assert_eq!(gone.kind, ErrorKind::Conflict);
    api.delete_domain_rule(first).await.expect("deleted");
    until(&api.domains(), |d| d.rules.len() == 1).await;
}

/// A list is checked against the current rules without writing; the import uses one action for
/// all its domains and consumes the pick.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn domain_list_preview_and_import() {
    let (shared, _, _, dir) = setup("domain-list", false, FakeAutostart::default());
    rules::add_domain_rule(&shared.backend, "example.com", ui::DomainAction::Vpn).expect("rule");
    let file = dir.0.join("list.txt");
    let text = "# comment\nexample.com\nnew.example\nnew.example\n192.0.2.1\n*.other.example\n";
    std::fs::write(&file, text).expect("list file");
    let (picked, preview) = rules::read_list(&shared.backend, file).expect("read");
    assert_eq!(preview.file_name, "list.txt");
    assert_eq!(preview.new_rules, 2);
    assert_eq!(
        preview.duplicates, 2,
        "one inside the file, one already listed"
    );
    assert_eq!(preview.invalid, 1);
    assert_eq!(preview.over_limit, 0);
    assert_eq!(
        shared.backend.rules.read(|d| d.domain_rules.len()),
        1,
        "preview only"
    );
    shared.local.lock().domain_list = Some(picked);
    let report = rules::import_domain_list(&shared, ui::DomainAction::Direct).expect("imported");
    assert_eq!(report.added, 2);
    let again = rules::import_domain_list(&shared, ui::DomainAction::Direct).expect_err("consumed");
    assert_eq!(again.kind, ErrorKind::Conflict);
    let api = SettingsService(shared);
    let view = until(&api.domains(), |d| d.rules.len() == 3).await;
    assert!(
        view.rules[1..]
            .iter()
            .all(|r| r.action == ui::DomainAction::Direct)
    );
}
