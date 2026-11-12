//! Where a deep link may send the app's first request. A link comes from a web page or a chat, so
//! the subscription it carries must live on the internet: an address in the user's own network
//! (a router, another program's local API, a cloud metadata service) is refused before any
//! request is made; a page would otherwise reach the LAN through the app, around the browser's
//! own protections. A subscription the user runs in the LAN is pasted as its plain address, which
//! stays allowed. Hosts are judged as the fetcher's URL parser reads them (`0x7f.1` and
//! `2130706433` are 127.0.0.1); names by their form only, as nothing is resolved here.
use std::net::{Ipv4Addr, Ipv6Addr};

use url::{Host, Url};

use super::{DeepLinkError, Hosts, first_token};

/// The http(s) URL a deep link carries, when it names an internet host (any host for
/// [`Hosts::Any`], whose caller judges the target itself).
pub(super) fn carried_url(text: &str, hosts: Hosts) -> Result<String, DeepLinkError> {
    let token = first_token(text);
    let url = Url::parse(token).map_err(|_| DeepLinkError::AddPayloadUnrecognised)?;
    let public = match url.host() {
        Some(Host::Ipv4(ip)) => public_v4(ip),
        Some(Host::Ipv6(ip)) => public_v6(ip),
        Some(Host::Domain(name)) => public_name(name),
        None => false,
    };
    if public || (hosts == Hosts::Any && url.host().is_some()) {
        Ok(token.to_owned())
    } else {
        Err(DeepLinkError::LocalTarget)
    }
}

/// Names that only mean something inside a network: one label (`router`), `localhost` and the
/// special-use suffixes for local networks.
fn public_name(name: &str) -> bool {
    const LOCAL: [&str; 5] = ["localhost", "local", "lan", "internal", "home.arpa"];
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    name.contains('.')
        && !LOCAL.iter().any(|suffix| {
            name == *suffix
                || name
                    .strip_suffix(suffix)
                    .is_some_and(|head| head.ends_with('.'))
        })
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let reserved = a == 0                          // "this network"
        || (a == 100 && (64..128).contains(&b))    // carrier-grade NAT (RFC 6598)
        || (a == 192 && b == 0 && c == 0)          // IETF protocol assignments
        || (a == 198 && (b == 18 || b == 19))      // benchmarking
        || a >= 240; // reserved and broadcast
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_documentation()
        || reserved)
}

fn public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return public_v4(v4);
    }
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_unique_local()
        || ip.is_unicast_link_local())
}
