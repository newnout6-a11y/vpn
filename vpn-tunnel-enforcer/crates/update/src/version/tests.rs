use super::*;

#[test]
fn versions_parse_and_order_numerically() {
    let v: Version = "1.14.10".parse().unwrap();
    assert_eq!(v, Version(1, 14, 10));
    assert!(v > "1.14.9".parse().unwrap());
    assert!("26.11.20".parse::<Version>().unwrap() > Version(26, 11, 9));
    assert_eq!(Version(2, 0, 1).to_string(), "2.0.1");
    for bad in [
        "",
        "1.14",
        "1.14.4.1",
        "1.14.x",
        "1.14.4-rc.1",
        "v1.14.4",
        "01.2.3",
    ] {
        assert_eq!(bad.parse::<Version>(), Err(BadVersion), "{bad}");
    }
}

#[test]
fn ranges_are_and_joined_comparators() {
    let r: Range = ">=1.14.4 <1.15.0".parse().unwrap();
    assert!(r.contains(Version(1, 14, 4)) && r.contains(Version(1, 14, 99)));
    assert!(!r.contains(Version(1, 14, 3)) && !r.contains(Version(1, 15, 0)));
    assert_eq!(r.minimum(), Some(Version(1, 14, 4)));
    assert_eq!(r.to_string(), ">=1.14.4 <1.15.0");
    let any: Range = "".parse().unwrap();
    assert!(any.contains(Version(0, 0, 1)) && any.minimum().is_none());
    assert!(
        "=2.0.0"
            .parse::<Range>()
            .unwrap()
            .contains(Version(2, 0, 0))
    );
    assert!("~1.14".parse::<Range>().is_err() && ">=1.14".parse::<Range>().is_err());
}

#[test]
fn serde_uses_the_text_forms() {
    let v: Version = serde_json::from_str("\"26.11.9\"").unwrap();
    assert_eq!(serde_json::to_string(&v).unwrap(), "\"26.11.9\"");
    let r: Range = serde_json::from_str("\">=2.0.0 <2.1.0\"").unwrap();
    assert!(r.contains(Version(2, 0, 7)));
    assert!(serde_json::from_str::<Version>("\"2.0\"").is_err());
}
