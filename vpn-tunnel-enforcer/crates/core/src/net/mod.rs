//! Network vocabulary shared by the whole app: strict `host:port` parsing, the one public-IP
//! predicate, and the egress routes of app-originated HTTP requests.
mod addr;
mod ip;
mod route;

pub use addr::{AddrError, Host, HostPort};
pub use ip::{is_cgnat, is_link_local, is_loopback, is_private, is_public_ip, unmap};
pub use route::{Route, builder_for, client_for};

#[cfg(test)]
mod locale_tests {
    /// The `core-net` fragment holds exactly the keys returned by `net`, `socks5` and `resolve`.
    #[test]
    fn fragment_holds_the_package_keys() {
        let used = [
            "core.net.addressInvalid",
            "core.net.socksUnreachable",
            "core.net.socksMalformed",
            "core.net.socksAuthRequired",
            "core.net.socksAuthRejected",
            "core.net.socksUpstreamRejected",
            "core.net.socksInvalidInput",
            "core.net.resolveInvalidName",
            "core.net.resolveNotFound",
            "core.net.resolveFiltered",
            "core.net.resolvePoisoned",
            "core.net.resolveFailed",
            "core.net.resolveLastKnown",
        ];
        let used: std::collections::BTreeSet<String> = used.map(String::from).into();
        assert_eq!(crate::test_support::package_keys("core-net"), used);
    }
}
