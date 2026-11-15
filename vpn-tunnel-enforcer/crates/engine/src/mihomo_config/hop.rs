//! The hop from the session's sing-box to mihomo (audit mihomo-a4/a5): a Shadowsocks 2022
//! listener on 127.0.0.1 keyed per run, TCP only, with UDP carried as UDP-over-TCP (v2) inside
//! the keyed stream. mihomo's SOCKS5 UDP relay checks no credentials at all (any local process
//! could push datagrams into the tunnel past sing-box's rules), and a UDP socket of its own could
//! lose a bind race without mihomo exiting; this hop has no UDP socket and answers no one
//! without the key.
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use vpnte_profiles::emit_singbox::SingBoxFragment;

use crate::ports::{PortsExhausted, alloc_port, random16};
use crate::singbox_config::{UdpPolicy, Upstream};
use crate::tags::PROXY_OUT;

/// Name of the hop listener in the mihomo config.
pub const HOP_INBOUND: &str = "vpnte-hop";
/// AEAD of the hop; both engines implement it (sing-shadowsocks), the key is 16 random bytes.
pub const HOP_METHOD: &str = "2022-blake3-aes-128-gcm";

/// The loopback hop of one run. `Debug` hides the key.
#[derive(Clone, PartialEq, Eq)]
pub struct HopEndpoint {
    port: u16,
    key: String,
}

impl HopEndpoint {
    /// A free loopback TCP port outside `taken` and a fresh key.
    pub fn allocate(taken: &[u16]) -> Result<Self, PortsExhausted> {
        Ok(Self {
            port: alloc_port(false, taken)?,
            key: STANDARD.encode(random16()),
        })
    }

    /// The listener's port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The key (base64 of 16 bytes; a secret).
    pub fn key(&self) -> &str {
        &self.key
    }

    /// sing-box's `proxy-out` to the hop. UDP is relayed (over TCP); QUIC is rejected as for
    /// every loopback proxy, so browsers fall back to TCP at once.
    pub fn upstream(&self) -> Upstream {
        Upstream::Native {
            fragment: SingBoxFragment::Outbound(json!({
                "type": "shadowsocks",
                "tag": PROXY_OUT,
                "server": "127.0.0.1",
                "server_port": self.port,
                "method": HOP_METHOD,
                "password": self.key,
                "udp_over_tcp": { "enabled": true, "version": 2 },
            })),
            udp: UdpPolicy {
                udp: true,
                block_quic: true,
            },
        }
    }

    /// The listener entry of the mihomo config.
    pub(super) fn listener(&self) -> Value {
        json!({
            "name": HOP_INBOUND,
            "type": "shadowsocks",
            "listen": "127.0.0.1",
            "port": self.port,
            "cipher": HOP_METHOD,
            "password": self.key,
            "udp": false,
        })
    }
}

impl fmt::Debug for HopEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HopEndpoint")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
