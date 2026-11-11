//! One share-link builder per protocol. Each returns `None` when a field of the profile has no
//! place in its link, so a key is never exported in a degraded form.
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::link::{Query, TlsMode, fragment, pct, server, stream};
use crate::common::fields::HY2_OBFS_TYPES;
use crate::model::{Hy2Obfs, Kind, Profile, SsPlugin, WireGuard};

/// The link of a profile, or `None` when it would lose something.
pub(super) fn link(p: &Profile) -> Option<String> {
    // No link format carries mux, dial options, raw sing-box options or a provider graph.
    let linkable = p.mux.is_none()
        && p.dial.is_default()
        && p.singbox_extra.is_empty()
        && p.native_xray.is_none();
    if !linkable {
        return None;
    }
    let host = server(&p.server, p.port)?;
    let name = fragment(&p.name, p.description.as_deref());
    let mut q = Query::default();
    let (tls, transport) = (p.tls.as_ref(), p.transport.as_ref());
    let userinfo = match &p.kind {
        Kind::Vless {
            uuid,
            flow,
            packet_encoding,
            encryption,
        } => {
            match encryption.as_deref() {
                None => q.set("encryption", "none"),
                // The importer reads `none` (and nothing) as "no VLESS Encryption".
                Some(e) if e.is_empty() || e.eq_ignore_ascii_case("none") => return None,
                Some(e) => q.set("encryption", e),
            }
            stream(&mut q, tls, transport, TlsMode::Optional, "allowInsecure")?;
            q.opt("flow", flow.as_deref())?;
            q.opt("packetEncoding", packet_encoding.as_deref())?;
            credential(uuid)?
        }
        Kind::Vmess { .. } => return super::vmess::link(p),
        Kind::Trojan { password } => {
            stream(&mut q, tls, transport, TlsMode::DefaultOn, "allowInsecure")?;
            credential(password)?
        }
        Kind::Shadowsocks {
            method,
            password,
            plugin,
            shadowtls,
            uot,
        } => {
            // ShadowTLS chains and UDP-over-TCP have no SIP002 form; SS links carry no TLS.
            if shadowtls.is_some() || uot.is_some() || tls.is_some() || transport.is_some() {
                return None;
            }
            let userinfo = ss_userinfo(method, password)?;
            return Some(match plugin {
                Some(plugin) => format!(
                    "ss://{userinfo}@{host}/?plugin={}{name}",
                    pct(&ss_plugin(plugin)?)
                ),
                None => format!("ss://{userinfo}@{host}{name}"),
            });
        }
        Kind::Hysteria2 {
            password,
            obfs,
            ports,
            hop_interval_s,
            hop_interval_max_s,
            up_mbps,
            down_mbps,
            bbr_profile,
        } => {
            // The link knows one hop interval and no BBR profile.
            if transport.is_some() || hop_interval_max_s.is_some() || bbr_profile.is_some() {
                return None;
            }
            stream(&mut q, tls, None, TlsMode::AlwaysNoReality, "insecure")?;
            if let Some(obfs) = obfs {
                hy2_obfs(&mut q, obfs)?;
            }
            if !ports.is_empty() {
                q.set("mport", port_ranges(ports)?);
            }
            q.positive("hop_interval", *hop_interval_s, "s")?;
            q.positive("upmbps", *up_mbps, "")?;
            q.positive("downmbps", *down_mbps, "")?;
            credential(password)?
        }
        Kind::Tuic {
            uuid,
            password,
            congestion,
            udp_relay_mode,
            zero_rtt,
            heartbeat_s,
        } => {
            if transport.is_some() {
                return None;
            }
            stream(
                &mut q,
                tls,
                None,
                TlsMode::AlwaysNoReality,
                "allow_insecure",
            )?;
            // The importer lower-cases the algorithm and spells NewReno `new_reno`.
            if let Some(cc) = congestion
                && (*cc != cc.to_ascii_lowercase() || cc.contains("new-reno"))
            {
                return None;
            }
            q.opt("congestion_control", congestion.as_deref())?;
            q.opt("udp_relay_mode", udp_relay_mode.as_deref())?;
            q.flag("reduce_rtt", *zero_rtt);
            q.positive("heartbeat", *heartbeat_s, "s")?;
            format!("{}:{}@", pct(nonempty(uuid)?), pct(nonempty(password)?))
        }
        Kind::Naive {
            username,
            password,
            quic,
            extra_headers,
            insecure_concurrency,
        } => {
            if transport.is_some() {
                return None;
            }
            stream(&mut q, tls, None, TlsMode::AlwaysNoReality, "insecure")?;
            if !extra_headers.is_empty() {
                q.set("extra-headers", naive_headers(extra_headers)?);
            }
            q.positive("insecure-concurrency", *insecure_concurrency, "")?;
            let scheme = if *quic { "naive+quic" } else { "naive+https" };
            let userinfo = match (username.as_str(), password.as_str()) {
                ("", "") => String::new(),
                (user, pass) => format!("{}:{}@", pct(user), pct(pass)),
            };
            return Some(format!("{scheme}://{userinfo}{host}{}{name}", q.render()));
        }
        Kind::Anytls {
            password,
            idle_check_s,
            idle_timeout_s,
            min_idle,
        } => {
            if transport.is_some() {
                return None;
            }
            stream(&mut q, tls, None, TlsMode::Always, "insecure")?;
            q.positive("idle_session_check_interval", *idle_check_s, "s")?;
            q.positive("idle_session_timeout", *idle_timeout_s, "s")?;
            if let Some(min) = min_idle {
                q.set("min_idle_session", min.to_string());
            }
            credential(password)?
        }
        Kind::Wireguard(wg) => {
            if tls.is_some() || transport.is_some() {
                return None;
            }
            let private_key = wireguard(&mut q, p, wg)?;
            format!("{}@", pct(private_key))
        }
        Kind::Socks { username, password } => {
            if tls.is_some() || transport.is_some() {
                return None;
            }
            let userinfo = proxy_login(username.as_deref(), password.as_deref())?;
            return Some(format!("socks://{userinfo}{host}{name}"));
        }
        Kind::Http { username, password } => {
            if transport.is_some() {
                return None;
            }
            let scheme = if tls.is_some() { "https" } else { "http" };
            if tls.is_some() {
                stream(&mut q, tls, None, TlsMode::AlwaysNoReality, "insecure")?;
            }
            let userinfo = proxy_login(username.as_deref(), password.as_deref())?;
            return Some(format!("{scheme}://{userinfo}{host}{}{name}", q.render()));
        }
    };
    Some(format!(
        "{}://{userinfo}{host}{}{name}",
        p.kind.label(),
        q.render()
    ))
}

fn nonempty(text: &str) -> Option<&str> {
    (!text.is_empty()).then_some(text)
}

/// `<credential>@`; the importer skips a link without one.
fn credential(secret: &str) -> Option<String> {
    Some(format!("{}@", pct(nonempty(secret)?)))
}

/// `user:pass@` of a SOCKS / HTTP proxy. The `:` is always written, so the importer never
/// mistakes a lone user name for base64; an empty part reads back as absent.
fn proxy_login(user: Option<&str>, pass: Option<&str>) -> Option<String> {
    match (user, pass) {
        (None, None) => Some(String::new()),
        (Some(""), _) | (_, Some("")) => None,
        (user, pass) => Some(format!(
            "{}:{}@",
            pct(user.unwrap_or_default()),
            pct(pass.unwrap_or_default())
        )),
    }
}

/// SIP002 userinfo: URL-safe base64 of `method:password` without padding, except SIP022
/// `2022-*` ciphers, whose key is already base64 and stays plain (percent-encoded).
fn ss_userinfo(method: &str, password: &str) -> Option<String> {
    // The importer lower-cases the method and needs a password for every cipher but `none`.
    let readable = !method.is_empty()
        && !method.contains(':')
        && method == method.to_ascii_lowercase()
        && (method == "none" || !password.is_empty());
    if !readable {
        return None;
    }
    Some(if method.starts_with("2022-") {
        format!("{}:{}", pct(method), pct(password))
    } else {
        URL_SAFE_NO_PAD.encode(format!("{method}:{password}"))
    })
}

/// SIP003 `plugin` value `<name>[;<opts>]` for the two plugins sing-box runs.
fn ss_plugin(plugin: &SsPlugin) -> Option<String> {
    if !matches!(plugin.name.as_str(), "obfs-local" | "v2ray-plugin") {
        return None;
    }
    Some(match plugin.opts.as_str() {
        "" => plugin.name.clone(),
        opts => format!("{};{opts}", plugin.name),
    })
}

fn hy2_obfs(q: &mut Query, obfs: &Hy2Obfs) -> Option<()> {
    if !HY2_OBFS_TYPES.contains(&obfs.kind.as_str()) {
        return None;
    }
    q.set("obfs", obfs.kind.as_str());
    q.set("obfs-password", nonempty(&obfs.password)?);
    Some(())
}

/// Port-hopping ranges as `20000-30000,443` (a single port without the dash).
fn port_ranges(ports: &[(u16, u16)]) -> Option<String> {
    let items: Option<Vec<String>> = ports
        .iter()
        .map(|&(start, end)| match (start, end) {
            (0, _) => None,
            (start, end) if start == end => Some(start.to_string()),
            (start, end) if start < end => Some(format!("{start}-{end}")),
            _ => None,
        })
        .collect();
    items.map(|items| items.join(","))
}

/// NaiveProxy `extra-headers`: `Name: value` lines joined with CRLF, as the importer splits them.
fn naive_headers(headers: &[(String, String)]) -> Option<String> {
    let line_safe = |s: &str| s.trim() == s && !s.contains(['\r', '\n']);
    let exact = headers.iter().all(|(name, value)| {
        !name.is_empty() && !name.contains(':') && line_safe(name) && line_safe(value)
    });
    let lines: Vec<String> = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}"))
        .collect();
    exact.then(|| lines.join("\r\n"))
}

/// WireGuard parameters of the single peer; returns the private key for the userinfo.
fn wireguard<'a>(q: &mut Query, p: &Profile, wg: &'a WireGuard) -> Option<&'a str> {
    // A link has exactly one peer, at the profile's endpoint.
    let [peer] = wg.peers.as_slice() else {
        return None;
    };
    if peer.host != p.server || peer.port != p.port {
        return None;
    }
    q.set("publicKey", nonempty(&peer.public_key)?);
    q.opt("psk", peer.pre_shared_key.as_deref())?;
    let texts = |items: &[ipnet::IpNet]| items.iter().map(ToString::to_string).collect::<Vec<_>>();
    q.list("address", &texts(&wg.local_address))?;
    q.list("allowedIPs", &texts(&peer.allowed_ips))?;
    let dns: Vec<String> = wg.dns.iter().map(ToString::to_string).collect();
    q.list("dns", &dns)?;
    q.positive("mtu", wg.mtu.map(u32::from), "")?;
    if let Some(keepalive) = peer.keepalive_s {
        q.set("keepalive", keepalive.to_string());
    }
    if let Some([a, b, c]) = peer.reserved {
        q.set("reserved", format!("{a},{b},{c}"));
    }
    nonempty(&wg.private_key)
}
