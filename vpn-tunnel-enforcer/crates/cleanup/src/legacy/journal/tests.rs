//! Vectors of spec §7.9 (`firewallManifestSecurity.test.ts`, `physicalAdapterLifecycle.test.ts`,
//! `physicalAdapterLockdownSource.test.ts`) for the salvage reader.
use serde_json::{Value, json};
use vpnte_winnet::wfp::FwProfile;

use super::adapters::policy_value;
use super::*;
use crate::test_support::TempDir;

fn firewall(extra: Value) -> Value {
    let mut base = json!({
        "schemaVersion": 1, "owner": "VPNTE",
        "operationId": "12345678-1234-1234-1234-123456789abc",
        "phase": "active", "strictMode": false, "createdAt": 1_700_000_000_000_i64,
        "ruleNames": ["VPNTE-killswitch-allow-app"], "singboxExePath": null,
        "savedProfiles": [
            {"name": "Domain", "defaultOutbound": "Block"},
            {"name": "Private", "defaultOutbound": "Allow"},
            {"name": "Public", "defaultOutbound": "NotConfigured"}
        ]
    });
    if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
        b.extend(e.clone());
    }
    base
}

fn read_firewall(v: &Value) -> Slot<FirewallJournal> {
    parse_envelope(v.to_string().as_bytes()).and_then(parse_firewall)
}

/// AT-03-002: a valid `firewall.json` is kept with all three profiles.
#[test]
fn valid_firewall_journal_is_kept() {
    let journal = read_firewall(&firewall(json!({})));
    let journal = journal.valid().expect("valid");
    assert_eq!(
        journal.profiles,
        [
            (FwProfile::Domain, Outbound::Block),
            (FwProfile::Private, Outbound::Allow),
            (FwProfile::Public, Outbound::NotConfigured)
        ]
    );
    assert!(journal.skipped.is_empty());
    assert!(!journal.strict_mode);
}

/// AT-03-002: tampered envelopes are never acted on.
#[test]
fn tampered_firewall_journals_are_rejected() {
    for bad in [
        json!(null),
        json!({}),
        firewall(json!({"schemaVersion": 2})),
        firewall(json!({"owner": "attacker"})),
        firewall(json!({"ruleNames": ["foreign-rule"]})),
        firewall(json!({"operationId": "x"})),
        firewall(json!({"phase": "done"})),
        firewall(json!({"createdAt": 0})),
        firewall(json!({"singboxExePath": "\\\\server\\share\\x.exe"})),
        firewall(json!({"ipv6Policy": {"schemaVersion": 2, "rules": []}})),
    ] {
        assert!(
            matches!(read_firewall(&bad), Slot::Rejected(_)),
            "accepted {bad}"
        );
    }
    assert_eq!(
        read_firewall(&firewall(json!({"schemaVersion": 2}))),
        Slot::Rejected("unsupported version".into())
    );
}

/// AT-03-002 (recovery salvage): bad profile entries are skipped, valid neighbours stay.
#[test]
fn bad_profile_entries_are_skipped() {
    let two = firewall(json!({"savedProfiles": [
        {"name": "Domain", "defaultOutbound": "Block"},
        {"name": "Private", "defaultOutbound": "Allow"}
    ]}));
    let j = read_firewall(&two);
    let j = j.valid().unwrap();
    assert_eq!(j.profiles.len(), 2);
    assert_eq!(j.skipped, ["firewall Public: no valid snapshot"]);

    let hostile = firewall(json!({"savedProfiles": [
        {"name": "Domain", "defaultOutbound": "Allow"},
        {"name": "Domain", "defaultOutbound": "Block"},
        {"name": "Public'; Write-Output 'injected'", "defaultOutbound": "Allow"}
    ]}));
    let j = read_firewall(&hostile);
    assert!(j.valid().unwrap().profiles.is_empty());
    let injected = firewall(json!({"savedProfiles": [
        {"name": "Domain", "defaultOutbound": "Allow; whoami"},
        {"name": "Private", "defaultOutbound": "Allow"},
        {"name": "Public", "defaultOutbound": "Block"}
    ]}));
    let j = read_firewall(&injected);
    let j = j.valid().unwrap();
    assert_eq!(
        j.profiles,
        [
            (FwProfile::Private, Outbound::Allow),
            (FwProfile::Public, Outbound::Block)
        ]
    );
    assert!(j.skipped.contains(&"firewall profile entry 0".to_string()));
    let four = firewall(json!({"savedProfiles": [{}, {}, {}, {}]}));
    assert!(matches!(read_firewall(&four), Slot::Rejected(_)));
}

/// AT-03-002: invalid program scopes do not cost the profiles (salvage keeps them; the cleanup
/// removes rules by prefix and never needs the scopes).
#[test]
fn invalid_program_rules_keep_the_profiles() {
    let v = firewall(json!({"programRules": [{"name": "foreign", "program": "Any"}]}));
    assert_eq!(read_firewall(&v).valid().unwrap().profiles.len(), 3);
}

const GUID_A: &str = "{0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0}";
const GUID_B: &str = "11111111-2222-3333-4444-555555555555";

fn adapter(guid: &str) -> Value {
    json!({
        "ifIndex": 7, "interfaceGuid": guid, "alias": "Wi-Fi", "ipv6Enabled": true,
        "ipv4DnsServers": ["192.0.2.53", "2001:db8::53"], "ipv4DnsSource": "static",
        "forcedDnsTo": ["192.168.250.254"], "forcedIpv6Off": true
    })
}

fn lockdown(adapters: Value, extra: Value) -> Value {
    let mut base = json!({
        "schemaVersion": 1, "owner": "VPNTE", "appliedAt": 1_700_000_000_000_i64,
        "tunDnsIpv4": "192.168.250.254", "adapters": adapters,
        "transitionAdapters": {"teredoType": "client", "sixToFourState": null, "isatapState": "disabled"},
        "dnsRegistryPolicy": {
            "smartNameResolution": {"exists": false},
            "parallelAandAAAA": {"exists": true, "type": "REG_DWORD", "data": "0x0"}
        }
    });
    if let (Some(b), Some(e)) = (base.as_object_mut(), extra.as_object()) {
        b.extend(e.clone());
    }
    base
}

fn read_lockdown(v: &Value) -> Slot<AdapterJournal> {
    parse_envelope(v.to_string().as_bytes()).and_then(parse_adapters)
}

#[test]
fn valid_lockdown_journal() {
    let j = read_lockdown(&lockdown(json!([adapter(GUID_A)]), json!({})));
    let j = j.valid().unwrap();
    assert!(j.skipped.is_empty(), "{:?}", j.skipped);
    let a = &j.adapters[0];
    assert_eq!(
        a.guid,
        GUID::from_u128(0x0f1e2d3c_4b5a_6978_8796_a5b4c3d2e1f0)
    );
    assert_eq!(a.dns_source, DnsSource::Static);
    assert_eq!(a.dns_servers.len(), 2);
    assert!(a.forced_ipv6_off && a.ipv6_enabled);
    assert_eq!(j.transition.teredo.as_deref(), Some("client"));
    assert_eq!(j.transition.six_to_four, None);
    assert_eq!(
        j.smart_name_resolution,
        Some(PolicyValue {
            exists: false,
            data: 0
        })
    );
    assert_eq!(
        j.parallel_a_aaaa,
        Some(PolicyValue {
            exists: true,
            data: 0
        })
    );
}

/// AT-03-012: an invalid adapter is reported by field name only.
#[test]
fn adapter_errors_name_the_field_only() {
    let cases = [
        ("ifIndex", json!(0)),
        ("alias", json!("Wi-Fi\n")),
        ("ipv6Enabled", json!(null)),
        ("forcedIpv6Off", json!("private")),
        ("interfaceGuid", json!("not-a-guid")),
        ("ipv4DnsSource", json!("private")),
        ("ipv4DnsServers", json!(["dns.example"])),
        ("forcedDnsTo", json!(["999.1.1.1"])),
    ];
    for (field, value) in cases {
        let mut bad = adapter(GUID_B);
        bad[field] = value;
        let j = read_lockdown(&lockdown(json!([bad, adapter(GUID_A)]), json!({})));
        let j = j.valid().unwrap();
        assert_eq!(j.adapters.len(), 1, "{field}");
        assert_eq!(j.skipped, [format!("adapter entry 0: invalid {field}")]);
        assert!(!j.skipped[0].contains("Wi-Fi"));
    }
}

/// AT-03-012: salvage restores valid neighbours of a bad GUID, a duplicate GUID (`{UPPER}` is
/// the same adapter), an injected Teredo state and an overflowing DWORD.
#[test]
fn salvage_keeps_valid_neighbours() {
    let upper = GUID_A.to_uppercase();
    let list = json!([
        adapter("{bad}"),
        adapter(GUID_A),
        adapter(&upper),
        adapter(GUID_B)
    ]);
    let extra = json!({
        "transitionAdapters": {"teredoType": "client; Invoke-Expression evil"},
        "dnsRegistryPolicy": {
            "smartNameResolution": {"exists": true, "type": "REG_DWORD", "data": "0 & evil"},
            "parallelAandAAAA": {"exists": true, "type": "REG_DWORD", "data": "4294967296"}
        }
    });
    let j = read_lockdown(&lockdown(list, extra));
    let j = j.valid().unwrap();
    assert_eq!(j.adapters.len(), 1);
    assert_eq!(j.adapters[0].guid, parse_guid(GUID_B).unwrap());
    assert_eq!(j.transition, Transition::default());
    assert_eq!((j.smart_name_resolution, j.parallel_a_aaaa), (None, None));
    assert_eq!(
        j.skipped,
        [
            "adapter entry 0: invalid interfaceGuid",
            "adapter entry 1: duplicate adapter identity",
            "adapter entry 2: duplicate adapter identity",
            "transition/teredoType: invalid",
            "DNS policy/smartNameResolution: invalid or missing",
            "DNS policy/parallelAandAAAA: invalid or missing",
        ]
    );
    let empty = read_lockdown(&lockdown(json!([]), json!({})));
    assert_eq!(
        empty.valid().unwrap().skipped,
        ["physical adapters: none recorded"]
    );
}

/// AT-03-012: one invalid DNS policy neighbour (`null`, `REG_SZ '0'`, `'4294967296'`) is
/// skipped while the valid one stays; a missing policy object reports both, writes nothing.
#[test]
fn dns_policy_neighbours() {
    let valid = json!({"exists": true, "type": "REG_DWORD", "data": "0"});
    for bad in [
        json!(null),
        json!({"exists": true, "type": "REG_SZ", "data": "0"}),
        json!({"exists": true, "type": "REG_DWORD", "data": "4294967296"}),
        json!({"exists": "false"}),
    ] {
        let extra =
            json!({"dnsRegistryPolicy": {"smartNameResolution": bad, "parallelAandAAAA": valid}});
        let j = read_lockdown(&lockdown(json!([adapter(GUID_A)]), extra));
        let j = j.valid().unwrap();
        assert_eq!(j.smart_name_resolution, None);
        assert_eq!(
            j.parallel_a_aaaa,
            Some(PolicyValue {
                exists: true,
                data: 0
            })
        );
    }
    assert_eq!(
        policy_value(&json!({"exists": true, "type": "REG_DWORD", "data": "0xFFFFFFFF"})),
        Some(PolicyValue {
            exists: true,
            data: u32::MAX
        })
    );
    assert_eq!(
        policy_value(&json!({"exists": true, "type": "REG_DWORD", "data": "0x+1"})),
        None
    );
    let missing = lockdown(json!([adapter(GUID_A)]), json!({"dnsRegistryPolicy": null}));
    let j = read_lockdown(&missing);
    assert_eq!(j.valid().unwrap().skipped.len(), 2);
}

fn temp_root(tag: &str) -> TempDir {
    let dir = TempDir::new(tag);
    std::fs::create_dir_all(dir.path().join("manifests")).unwrap();
    dir
}

fn write(root: &Path, name: &str, v: &Value) {
    let mut bytes = "\u{feff}".as_bytes().to_vec();
    bytes.extend(serde_json::to_vec_pretty(v).unwrap());
    std::fs::write(root.join("manifests").join(name), bytes).unwrap();
}

/// Strict evidence comes from a trusted `recovery-policy.json` or `firewall.json`; the BOM is
/// tolerated; an untrusted folder makes every journal unusable.
#[test]
fn reads_a_manifests_folder() {
    let dir = temp_root("journals");
    let root = dir.path();
    write(
        root,
        POLICY,
        &json!({"schemaVersion": 1, "owner": "VPNTE", "strictMode": true}),
    );
    write(root, FIREWALL, &firewall(json!({})));
    write(
        root,
        TUN_OWNER,
        &json!({"schemaVersion": 1, "owner": "VPNTE", "alias": "Ethernet 5", "interfaceGuid": GUID_B}),
    );
    std::fs::write(root.join("manifests").join(ADAPTERS), b"{ not json").unwrap();
    let trust_all = |_: &Path, _: bool| Ok(());
    let j = Journals::read(root, &trust_all);
    assert_eq!(j.policy, Slot::Valid(true));
    assert!(j.strict_evidence());
    assert_eq!(j.firewall.valid().unwrap().profiles.len(), 3);
    assert_eq!(j.tun_owner.valid().unwrap().alias, "Ethernet 5");
    assert_eq!(j.adapters, Slot::Rejected("corrupt JSON".into()));
    let record = j.record();
    assert_eq!(record.outcome, Outcome::Skipped);
    assert!(record.detail.contains(ADAPTERS));

    let distrust_files = |_: &Path, dir: bool| match dir {
        true => Ok(()),
        false => Err(Untrusted::Owner),
    };
    let j = Journals::read(root, &distrust_files);
    assert!(!j.strict_evidence());
    assert!(matches!(j.policy, Slot::Rejected(_)));
    let distrust_dir = |_: &Path, _: bool| Err(Untrusted::ReparsePoint);
    let j = Journals::read(root, &distrust_dir);
    assert_eq!(j.dir_problem, Some(Untrusted::ReparsePoint));
    assert!(j.firewall.valid().is_none());
    assert_eq!(j.record().outcome, Outcome::Skipped);
    std::fs::remove_dir_all(root).unwrap();

    let empty = Journals::read(root, &trust_all);
    assert_eq!(empty.firewall, Slot::Absent);
    assert_eq!(empty.record().outcome, Outcome::Done);
}

#[test]
fn guid_forms() {
    let g = GUID::from_u128(0x11111111_2222_3333_4444_555555555555);
    assert_eq!(parse_guid(GUID_B), Some(g));
    assert_eq!(
        parse_guid("{11111111-2222-3333-4444-555555555555}"),
        Some(g)
    );
    assert_eq!(parse_guid("{11111111-2222-3333-4444-555555555555"), Some(g));
    assert_eq!(parse_guid("11111111-2222-3333-4444-55555555555"), None);
    assert_eq!(parse_guid("1111111g-2222-3333-4444-555555555555"), None);
    assert_eq!(parse_guid("+1111111-2222-3333-4444-555555555555"), None);
}
