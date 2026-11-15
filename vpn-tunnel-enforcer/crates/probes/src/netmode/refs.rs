//! Reference hosts of the network-mode check. Chosen to be stable for years, reachable over
//! HTTPS on 443, not ours, and on the right side of the line: the Russian ones are services
//! every operator's mobile whitelist carries (research 2.9: Yandex, VK), the foreign ones are
//! hosted abroad on their own networks and are not blocked in Russia (so outside whitelist mode
//! they connect). The QUIC ones answer a version-negotiation probe (RFC 9000 §6.1), the STUN
//! ones a Binding Request (RFC 8489).

/// Russian whitelisted hosts: TLS to them still works under a mobile whitelist.
pub const RU_HOSTS: [&str; 2] = ["ya.ru", "vk.com"];

/// Foreign hosts: `github.com` (GitHub's own AS36459, US), `www.debian.org` (EU mirrors).
pub const FOREIGN_HOSTS: [&str; 2] = ["github.com", "www.debian.org"];

/// QUIC servers on UDP 443 (Cloudflare's QUIC test site, Google's front end).
pub const QUIC_HOSTS: [&str; 2] = ["cloudflare-quic.com", "www.google.com"];

/// Public STUN servers on their own UDP ports (Google's for a decade, Cloudflare's since 2023):
/// plain UDP on other ports than QUIC's 443, from two providers.
pub const STUN_HOSTS: [(&str, u16); 2] =
    [("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478)];

/// The name the DNS step resolves (system resolver vs DoH by name): foreign, not blocked.
pub const DNS_NAME: &str = "github.com";

/// HTTPS port of every TCP reference.
pub const HTTPS: u16 = 443;
