# vpnte-profiles — API for dependent crates

Typed VPN profiles: the model every crate stores and passes, importers (share links, JSON,
Clash YAML, WireGuard / AmneziaWG `.conf`, AmneziaVPN `vpn://` keys, app deep links, Electron
rows), the text pipeline building blocks,
the sing-box emitter, the native Xray graph, exporters, identity and capability summaries.
Depends only on `vpnte-base`. Pure code: no I/O, no network, no async, nothing needs elevation
(the one Win32 call, `device::MachineIdentity::current`, reads host and user names).

```toml
vpnte-profiles.workspace = true
```

| module | what |
| --- | --- |
| `model` | `Profile` and its parts, `ParseReport`, `Skipped`/`SkipReason`, `SubscriptionMeta`, `TooLarge` |
| `uri` | one share link -> `Profile` |
| `json` | sing-box / Xray / wrapped JSON -> `ParseReport` |
| `clash`, `wg_ini` | Clash (mihomo) YAML, WireGuard / AmneziaWG `.conf` |
| `awg` | AmneziaWG parameters: checks before import and start, generation, field names |
| `amnezia` | AmneziaVPN share keys `vpn://…` (decode, server descriptions with containers) |
| `deeplink` | `happ://` / `mantaray://` / `v2raytun://` / `incy://` / `sing-box://` / `clash://` / `hiddify://` -> carried text or URL |
| `legacy` | one stored Electron row -> `Profile` |
| `text` | limits, body decoding, base64 layers, JSON spans, link candidates, subscription metadata |
| `device`, `countries` | subscription UA / HWID headers, uTLS default per device; ISO country guess |
| `caps` | capability summary + i18n of `Note` / `SkipReason` |
| `identity` | `Profile::identity()` (the engine choice is `vpnte_engine::select_engine`) |
| `emit_singbox` | the only producer of sing-box JSON (`Profile` -> outbound / endpoint / chain) |
| `xray_native` | provider Xray graphs: import, validate, compile for the engine, export |
| `export` | share link, share document (link, JSON or AmneziaWG `.conf`), proxy-list line, WireGuard / AmneziaWG `.conf` and mihomo YAML |
| `LOCALES` | the crate's locale fragments, `&[(ru_json, en_json)]` |

## model (`vpnte_profiles::model`)

```rust
pub struct Profile {
    pub name: String,                     // cleaned, <= 256 chars, never empty after import
    pub description: Option<String>,      // Happ `serverDescription`
    pub server: Host, pub port: u16,      // Host::{Ip(IpAddr), Domain(String)}, IPv6 never bracketed
    pub kind: Kind,                       // protocol + credentials (see below)
    pub tls: Option<Tls>, pub transport: Option<Transport>, pub mux: Option<Mux>,
    pub dial: DialPrefs,                  // connect timeout, TFO, MPTCP, udp_fragment, dns_strategy
    pub native_xray: Option<NativeXray>,  // provider Xray graph: runs on Xray only
    pub singbox_extra: Map<String, Value>,// allow-listed sing-box keys as dotted paths (`tls.fragment`)
    pub source: Source,                   // Uri(line) | Json | Clash | WgIni | Legacy
    pub notes: Vec<Note>,                 // what the user should know (render with caps::note_msg)
}
pub enum Kind { Vless{uuid, flow, packet_encoding, encryption}, Vmess{uuid, security, global_padding,
    authenticated_length}, Trojan{password}, Shadowsocks{method, password, plugin: Option<SsPlugin>,
    shadowtls: Option<ShadowTlsLayer>, uot: Option<u8>}, Hysteria2{password, obfs, ports: Vec<(u16,u16)>,
    hop_interval_s, hop_interval_max_s, up_mbps, down_mbps, bbr_profile}, Tuic{uuid, password, congestion,
    udp_relay_mode, zero_rtt, heartbeat_s}, Naive{username, password, quic, extra_headers,
    insecure_concurrency}, Anytls{password, idle_check_s, idle_timeout_s, min_idle}, Wireguard(WireGuard),
    Amneziawg{wg: WireGuard, awg: Box<Awg>} /* label "amneziawg" */, Socks{username, password},
    Http{username, password} }
impl Kind { pub fn label(&self) -> &'static str; pub fn is_udp_transport(&self) -> bool;
    pub fn wireguard(&self) -> Option<&WireGuard> }   // WireGuard part of WG and AWG (keys, peers)
pub struct Awg { generation: AwgGeneration, jc, jmin, jmax: Option<u32>, s: [Option<u32>; 4],
    h: [Option<AwgRange>; 4], i: [Option<String>; 5], j: [Option<String>; 3], itime: Option<u32>,
    header_protection_key: Option<String> /* base64, 32 bytes, stored padded */,
    content_padding: Option<AwgRange>, timers: [Option<AwgRange>; 5] /* RekeyAfterTime, RekeyTimeout,
    RejectAfterTime, KeepaliveTimeout, MaxHandshakeAttempts */, keepalive_range: Option<AwgRange>,
    random_trailers, disable_cookies: Option<bool> }      // Debug hides the protection key
pub enum AwgGeneration { V1_0, V1_5, V2_0, V3 }  // serde "1.0" "1.5" "2.0" "3"; label() "3.x"
pub struct AwgRange { pub min: u32, pub max: u32 }  // "a" | "a-b"; parse, is_range, overlaps
pub enum Transport { Ws{..}, Grpc{service_name, multi_mode}, Http{hosts, path}, HttpUpgrade{host, path},
    Quic, Xhttp{host, path, mode, extra} /* Xray only */, TcpHttpHeader{host, path} /* Xray only */ }
pub enum Note { NaiveInsecureIgnored, CertPinNotEnforced, AlterIdNormalized(u32), ProviderFpDroppedOnQuic,
    UnsupportedField(String), FileReferenceDropped(String), DialFieldDropped(String), Unencrypted,
    MuxSingBoxOnly, Other(String /* an i18n key */) }
impl Note {
    pub const REALITY_FINGERPRINT: &str;     // Other key: REALITY fp current servers refuse
    pub const XRAY_TRANSPORT_REMOVED: &str;  // Other key: Xray h2/QUIC stream converted for sing-box
    pub const NAIVE_PIN_NOT_ENFORCED: &str;  // Other key: naive with an SPKI pin (CA check only)
    pub fn for_tls(tls: Option<&Tls>) -> Option<Note>;  // the note every importer adds for these TLS
}
pub const REALITY_REFUSED_FINGERPRINTS: [&str; 6];  // edge ios qq random android 360
impl Tls { pub fn refused_reality_fingerprint(&self) -> bool }  // REALITY + one of those
impl Tls { pub fn cert_names(&self) -> Option<&str> }  // `verify_peer_cert_by_name` as Xray gets it:
                                                       // TLS only (not REALITY), never blank
impl Reality { pub fn mldsa65_key(&self) -> Option<&str> }  // `mldsa65_verify`, never blank
// TLS tricks against ClientHello DPI (item 18): `Tls::tricks: Option<TlsTricks>` (serde: absent = None)
pub enum TlsTricks { Off, Record, Hello(HelloSplit), Both(HelloSplit) }  // serde {"mode": "both", ..}
pub struct HelloSplit { pub len: Span /* bytes */, pub interval_ms: Span }  // PRESET = 100-200 B, 10-20 ms
pub struct Span { pub min: u16, pub max: u16 }       // stored and shown as "100-200" / "150"; parse
impl TlsTricks {
    pub const STRONG: TlsTricks;                     // «Сильно» = Both(HelloSplit::PRESET)
    pub const SINGBOX_KEYS: [&str; 3];               // tls.fragment / .record_fragment / .fragment_fallback_delay
    pub fn effective(own: Option<TlsTricks>, tls_compat: bool) -> TlsTricks;  // own, else STRONG / Off
    pub fn record(self) -> bool; pub fn hello(self) -> Option<HelloSplit>;
    pub fn from_fragment(packets: &str, length: Option<&str>, interval: Option<&str>) -> Option<TlsTricks>;
    pub fn from_singbox(extra: &Map<String, Value>) -> Option<TlsTricks>;     // pasted keys: flags, preset split
    pub fn with(self, other: TlsTricks) -> TlsTricks;  // both tricks; self's split first
}
impl Profile {
    pub fn own_tls_tricks(&self) -> Option<TlsTricks>;   // Tls::tricks, else pasted keys
    pub fn tls_tricks_for(&self, tls_compat: bool) -> TlsTricks;  // what the key runs with (both engines)
    pub fn takes_tls_tricks(&self) -> bool;              // TCP TLS with an SNI; not REALITY / QUIC / naive /
}                                                        // ShadowTLS / native Xray graph
pub struct ParseReport { pub profiles: Vec<Profile>, pub skipped: Vec<Skipped>, pub meta: SubscriptionMeta }
pub struct Skipped { pub excerpt: String /* redacted, <= 80 chars */, pub reason: SkipReason }
pub enum SkipReason { UnknownScheme(String), Invalid{scheme, detail /* English */}, MissingCredential,
    ShadowTlsNeedsInner, UnsupportedPlugin(String), UnsupportedTransport(String), Duplicate,
    NativeGraphRejected(String), UnsupportedProtocol(String /* "OpenVPN over Cloak" */),
    AwgInvalid(awg::AwgInvalid) }
pub struct SubscriptionMeta { upload, download, total: Option<u64>, expires_at: Option<UnixMs>,
    refresh_hours: Option<u32>, title, web_page_url, support_url, announce: Option<String> }
pub struct TooLarge;                      // input over a limit
```
`Profile` is `Serialize + Deserialize` (the stored form; serde shapes are part of the stored data —
change them only additively).
TLS tricks: `Record` cuts the ClientHello into TLS records sent at once, `Hello` into TCP pieces of
`len` bytes `interval_ms` apart, `Both` sends the records as such pieces (FOCI 2025: the TSPU
reassembled either trick alone). `tls_tricks_for(tls_compat)` is the one rule both engines use:
`Off` where the key cannot take tricks (`takes_tls_tricks`: REALITY never, its hello names a
whitelisted camouflage site), else the typed value (share link, the user's per-server choice the
app merges in) as is, else pasted sing-box keys on top of the app default (they only add: explicit
`false` adds nothing), else the default (stealth or adaptive TLS compatibility -> `STRONG`, else
`Off`). `from_fragment` reads Xray's triple as links and Happ / Hiddify provider keys
(`fragmentation-packets` / `-length` / `-interval`) write it: `tlshello` = records (interval 0 or
none: `Record`; with the provider's own record length `Both` with that length and pause 0, else
`Both`), packets from 1 (`1`, `1-3`) = `Hello`, anything else `None` (not the hello). `from_singbox`
reads flags only: sing-box's `fragment_fallback_delay` is one wait at one cut, not a per-piece pause. Provider values are kept as given: uTLS / ALPN / mux defaults are
applied by `emit_singbox`, never stored. Durations are whole seconds (`*_s`).

## Importing text (servers-parse / servers-refresh)

`parse_text` / `resolve` / fetching live in `vpnte-servers`; this crate gives the pieces:

```rust
use vpnte_profiles::{clash, deeplink, json, text, uri, wg_ini, model::*};

fn parse_text(input: &str) -> Result<ParseReport, TooLarge> {
    let input = text::prepare(input, text::MAX_INPUT_BYTES)?;      // BOM + whitespace, size check
    // A deep link first: Ok(Some(inner)) -> parse `inner` (or fetch it when it is an http(s) URL);
    // Err(e) -> show e.msg().
    if let Ok(Some(inner)) = deeplink::unwrap_deeplink(input) { /* recurse / fetch */ }
    let (meta, body) = text::body_meta(input);                      // leading `#key: value` lines
    let mut report = ParseReport { meta, ..Default::default() };
    for layer in text::layers(body) {                               // text, then <= 3 base64 layers
        let spans = text::json_spans(&layer, text::MAX_JSON_SPANS);
        let mut taken = Vec::new();
        for span in spans {
            if let Ok(v) = serde_json::from_str(&layer[span.clone()]) {
                let r = json::parse_json(&v);
                if !(r.profiles.is_empty() && r.skipped.is_empty()) { taken.push(span); merge(&mut report, r); }
            }
        }
        let rest = text::blank_spans(&layer, &taken);               // blank only spans an importer took
        if let Some(r) = clash::parse_clash(&rest) { merge(&mut report, r); }
        if let Some(r) = wg_ini::parse_wg_ini(&rest) { push(&mut report, r, "[Interface]"); }
        // push(): Ok -> profiles; Err(reason) -> Skipped { excerpt: uri::excerpt(line), reason }
        for line in text::uri_candidates(&rest) { push(&mut report, uri::parse_uri(line), line); }
        if !(report.profiles.is_empty() && report.skipped.is_empty()) { break; }  // first layer that yields wins
    }
    // De-duplicate by `Profile::identity()` (later copies -> SkipReason::Duplicate).
    Ok(report)
}
```
This flow (with two small `merge` / `push` helpers) was compiled and run against the crate.
Subscription bodies: `text::decode_body(bytes, text::MAX_BODY_BYTES)` (gzip / zlib / brotli / UTF-16
aware, never inflates a corrupt stream partially), then the same steps; response headers:
`text::header_meta(headers, meta_from_body)`; provider controls and relocation hints:
`text::header_keys(headers, text::body_keys(text))`. Fetch headers: `device::user_agents(device,
Some(hwid))` and `device::device_headers(device, hwid)` with one `hwid` = `device::hwid_override()`
or the frozen `device::legacy_hwid(device, &MachineIdentity::current())` (compute once, persist);
`user_agents(device, None)` for a subscription that does not send its HWID.

## Importers

```rust
// uri
pub fn parse_uri(line: &str) -> Result<Profile, SkipReason>;  // Source::Uri(trimmed line)
pub fn excerpt(line: &str) -> String;                         // redacted `scheme://host:port` for Skipped
// json
pub fn parse_json(value: &serde_json::Value) -> ParseReport;  // never fails; `meta` stays default
// clash / wg_ini
pub fn parse_clash(text: &str) -> Option<ParseReport>;        // None: not a Clash document
pub fn http_providers(text: &str) -> Vec<HttpProvider>;      // Mihomo `proxy-providers` of `type: http`,
pub struct HttpProvider { pub name: String, pub url: String } // document order, no repeated URL, at most
pub const MAX_PROVIDERS: usize = 16;                           // 16; Debug hides the URL (a token)
pub fn parse_wg_ini(text: &str) -> Option<Result<Profile, SkipReason>>;  // None: not a WireGuard config
// deeplink
pub enum DeepLinkError { Encrypted { app: &'static str, variant: String }, RoutingProfile,
                         AddPayloadUnrecognised, UnknownHost(String) }  // RoutingProfile: happ://routing/…
                         // is no subscription; its message names the Apps page (text::parse_routing)
impl DeepLinkError { pub fn msg(&self) -> Msg }               // profiles.deeplink.*; never the payload
pub fn unwrap_deeplink(input: &str) -> Result<Option<String>, DeepLinkError>;  // Ok(None): not a deep link
pub fn unwrap_redirect(input: &str) -> Result<Option<String>, DeepLinkError>;  // same for a redirect's
                                       // Location: no LocalTarget, the fetcher's hop policy judges it
// legacy (one-time Electron import, the app orchestrates; see CONTRACT §3.5)
pub enum LegacyError { NotAnObject, UnsupportedProtocol(String), Unusable(String), InvalidNativeGraph }
impl From<LegacyError> for AppError;                          // Validation + profiles.legacy.*
pub fn from_legacy(name: &str, protocol: &str, outbound: &Value, source_uri: Option<&str>)
    -> Result<Profile, LegacyError>;                          // a share-link row is re-read from its link
```
- `parse_uri` schemes (any case): `vless vmess trojan ss hysteria2|hy2 tuic naive|naive+https|naive+quic
  anytls wireguard|wg socks|socks5|socks5h http|https vpn` (proxy links need a root path and a
  port; `vpn` = an AmneziaVPN key among other lines: its one server, other containers as
  `Note::UnsupportedField(name)`, several servers -> `Invalid`);
  `shadowtls` -> `ShadowTlsNeedsInner`, others -> `UnknownScheme(scheme)` (`""`: no `scheme://`).
  VLESS / VMess / Trojan `fragment=` (Xray `packets,length,interval`; Hiddify `size,sleep,tlshello`)
  and Hiddify `fgsize` / `fgsleep` -> `Tls::tricks`; without TLS or unreadable ->
  `Note::UnsupportedField("fragment")`; kept but noted the same way where no engine runs them
  (REALITY, XHTTP over HTTP/3).
- `parse_json` reads sing-box outbounds / endpoints (incl. the SS + ShadowTLS chain), Xray outbounds
  and whole provider documents (one document with a native graph = one profile, rejected graph =
  `NativeGraphRejected`), wrappers up to depth 6, JSON strings (nested JSON, <= 2 base64 layers,
  share links, Clash text). Never walks `inbounds dns route routing log ...`. Xray 26 Hysteria
  `finalmask` maps Salamander / Gecko, `udpHop` and the Brutal rates (`brutalUp` / `brutalDown`
  -> `up_mbps` / `down_mbps` as Xray's client applies them; `0` / empty = unset, no Note); other
  masks / QUIC knobs are Notes. A sing-box naive outbound with `certificate_public_key_sha256`
  gets `Note::Other(NAIVE_PIN_NOT_ENFORCED)` (naive takes no pin; the CA check runs). An
  AmneziaVPN server description (`{"containers": […]}`) is read by `amnezia::parse_document`.
- Xray VLESS / VMess / Trojan / Shadowsocks: a lone outbound (or a document routing everything to
  it) that says nothing the model drops is a typed profile without `native_xray`, so both engines
  run it. The graph is kept when the outbound has a balancer / chain / loopback around it, or any
  Xray-only field (enabled `mux`, `sockopt`, `finalmask`, `sendThrough`, kcp, the TCP HTTP header
  mask, several pins, unknown keys; `json/xray_plain.rs` lists what counts as carried). A stream
  Xray 26 removed (`h2` / `http` -> `Transport::Http`, plain `quic` -> `Transport::Quic`) is typed
  with `Note::Other(XRAY_TRANSPORT_REMOVED)` plus an `UnsupportedField` per dropped Xray field;
  `h3`, QUIC with a packet key / header mask, or such a stream behind a `dialerProxy` chain are
  skipped. Xray `socks` / `http` (flat `user`/`pass` or `servers[].users[]`; SOCKS over TLS, a
  transport or a chain -> skipped) and `wireguard` (`secretKey`, `address`, `peers[].endpoint`,
  `reserved`, `mtu`, `remoteDNS`) outbounds are typed profiles. Another protocol pointing at a
  server -> `UnknownScheme(protocol)`; a known one without a server -> `Invalid`; `freedom`,
  `blackhole`, `dns`, `loopback` and stray inbounds stay silent.
- Every importer adds `Note::for_tls` (REALITY with `edge ios qq random android 360`: servers since
  Xray 26.9.8 refuse those hellos; the provider's choice is kept).
- Whole-certificate pins (`Tls::cert_pin_sha256`, lower-case hex) come from Hysteria2 `pinSHA256`,
  Xray `pinnedPeerCertSha256` and its link name `pcs` (first of a comma list), and Clash
  `fingerprint`. A pin that cannot be read is never dropped silently, since that would leave an
  unverified key: a link is skipped, Xray JSON keeps its graph, a Clash entry with
  `skip-cert-verify` is skipped (without it: a Note).
- Xray 26 checks (p-tls-names): `Tls::verify_peer_cert_by_name` (comma list, items trimmed, empty
  ones dropped) from link `vcn` / JSON `verifyPeerCertByName` (TLS only; the SNI stays
  `server_name`, the certificate is CA-checked against these names) and
  `Reality::mldsa65_verify` (ML-DSA-65 public key, 1952 bytes, stored as unpadded base64url;
  either base64 alphabet read) from link `pqv` / JSON `mldsa65Verify`. Links: V2Ray family only;
  `vcn` next to REALITY or `pqv` next to plain TLS -> dropped with `UnsupportedField`; a malformed
  `pqv` skips the link and a malformed `mldsa65Verify` the outbound (Xray refuses such a config).
  v2rayN VMess JSON: `vcn`. Both JSON keys are typed, so a lone Xray outbound with them stays plain.
- `parse_clash` streams only the first root `proxies` list (limits: 5000 entries, nesting 32,
  64 MiB of approximate materialised bytes, alias copies included); every unread key becomes
  `Note::UnsupportedField`, so do unread sub-keys of the transport's `*-opts` map and of
  `reality-opts` (`"grpc-opts.ping-interval"`).
- `unwrap_deeplink`: Happ / MantaRay / v2RayTun / INCY `add` / `import` payloads (URL, key, base64,
  `{"url"|"link": …}`) -> `Some(text)`; `crypt*` hosts -> `Encrypted`; multi-line input -> `None`.
  Remote-profile links -> `Some(http(s) URL)`: `sing-box://import-remote-profile?url=<enc>#name`,
  `clash://install-config?url=<enc>&name=…`, `hiddify://import/<url|key>#name` and
  `hiddify://install-config|install-sub?url=<enc>` (the name is dropped; `url` is percent-decoded,
  `+` kept); no / non-http `url` -> `AddPayloadUnrecognised`, another host -> `UnknownHost`.
  Every http(s) URL a link carries must name an internet host (as the fetcher's `url` parser reads
  it): loopback, private, link-local, CGNAT, reserved, `localhost`, one-label names and `.local` /
  `.lan` / `.internal` / `.home.arpa` -> `LocalTarget` (a page or a chat must not make the app
  request the user's network; a LAN subscription is pasted as its plain address instead).
  `vpn://` (AmneziaVPN) -> `Some(decoded text)` (JSON description, `.conf` or Xray JSON),
  `AmneziaUnsupported("OpenVPN")`, or `AmneziaDamaged`.
- AmneziaWG: a WireGuard entry (`.conf` `[Interface]` / `[Peer]` keys, Clash
  `amnezia-wg-option`, `wg://` link parameters; names in any case, `-` / `_` ignored) whose
  AmneziaWG parameters turn any mechanism on is `Kind::Amneziawg` with its implied generation
  (mihomo `version: 3` forces 3.x); all mechanisms off is plain `Kind::Wireguard` (nothing to
  note). Parameters that fail `awg::validate` (or do not parse) skip the entry with
  `SkipReason::AwgInvalid` naming every field. A 3.x `PersistentKeepalive = a-b` is kept in
  `Awg::keepalive_range`. Unknown `amnezia-wg-option` keys are `UnsupportedField` notes.
- Every importer keeps provider values verbatim and records what it dropped as `Note`s; secrets
  never appear in `Skipped.excerpt`, `SkipReason` or error texts.
- Keys no engine can run are skipped at import as `Invalid` (the same predicates the emitter
  refuses with, so a stored key does not fail only at connect): REALITY over QUIC (Hysteria2,
  TUIC, QUIC transport) or with ECH (`uri`, `json`, `clash`); several WireGuard peers where one
  names no AllowedIPs (`json`, `clash`, `wg_ini`). `from_legacy` keeps old REALITY rows of that
  kind (the user's data is not dropped); the emitter refuses them at connect.

## awg (`vpnte_profiles::awg`, AmneziaWG parameters)

```rust
pub fn validate(awg: &Awg) -> Result<(), AwgInvalid>;   // importers, caps; the runner calls it
                                                         // again before any start (AT-12-003)
pub fn implied_generation(awg: &Awg) -> AwgGeneration;  // lowest generation with every key
pub enum AwgField { Jc, Jmin, Jmax, S1..S4, H1..H4, I1..I5, J1..J3, Itime, HeaderProtectionKey,
    ContentPaddingAddition, RekeyAfterTime, RekeyTimeout, RejectAfterTime, KeepaliveTimeout,
    MaxHandshakeAttempts, PersistentKeepalive, RandomTrailers, DisableCookies, Version }
impl AwgField { pub fn conf_name(self) -> &'static str; pub fn yaml_name(self) -> String;
    pub fn from_key(key: &str) -> Option<AwgField> }
pub struct AwgInvalid { pub fields: Vec<AwgField> }      // field order, each once
impl AwgInvalid { pub fn names(&self) -> String; pub fn msg(&self) -> Msg }  // profiles.awg.invalid
impl From<AwgInvalid> for AppError;                       // Validation
```
Rules (bounds of amneziawg-go v3 and of the legacy 1.x / 2.0 code mihomo carries, never the
MTU-1280 recommendations): `Jc <= 128`; `Jmin <= Jmax < 65535` (absent = 0); `S1`-`S4` keep the
padded message (148 / 92 / 64 / 32 + S) below 65535, and before 3.x the four padded sizes differ
(`S2 != S1 + 56`); `H1`-`H4` (absent = standard 1..4; legacy reads a value starting at 1..4 as
standard) never overlap, ranges only from 2.0; `I1`-`I5` from 1.5, tags `<b 0x..>` `<t>` `<r N>`
`<rc N>` `<rd N>` plus legacy `<c>` `<wt N>` (N <= 1000 / 5000, one `c` / `t` per chain) or v3
`<d>` `<ds>` `<dz N>`, nothing but spaces between tags; `J1`-`J3`, `Itime` 1.5 only;
`HeaderProtectionKey` (base64 of 32 bytes, needs S1-S4 >= 12), `ContentPaddingAddition`
(<= 65535), the timers (`RejectAfterTime` above `RekeyAfterTime`, WireGuard's 180 / 120 for the
missing one), keepalive range, `RandomTrailers`, `DisableCookies` 3.x only.

## amnezia (`vpnte_profiles::amnezia`, AmneziaVPN `vpn://` keys)

```rust
pub const SCHEME: &str = "vpn";
pub enum Payload { Text(String), Unsupported(&'static str) }
pub fn decode_key(link: &str) -> Option<Payload>;        // None: not a key / damaged
pub fn parse_payload(text: &str) -> ParseReport;          // description, `.conf` or Xray JSON
pub fn parse_key(line: &str) -> Result<Profile, SkipReason>;   // `uri::parse_uri` for `vpn`
pub fn parse_document(doc: &Value) -> Option<ParseReport>;     // None: not a description
```
Layout (amnezia-client `ExportController::generateVpnUrl` / `ImportController`): `vpn://` +
base64url without padding (the standard alphabet is accepted too) of Qt `qCompress` output = a
4-byte big-endian length + a zlib stream (inflated only when the whole stream matches the length,
at most 1 MiB; otherwise the raw bytes are read, as AmneziaVPN does). The text is a server
description `{"containers": [{"container": "amnezia-awg2", "awg": {<server params>,
"last_config": "<JSON text>"}}], "defaultContainer", "description", "hostName", "dns1",
"dns2"}`, or a bare `.conf`, an Xray JSON config or an OpenVPN config. Containers:
`amnezia-awg` / `amnezia-awg2` (key `awg`) and `amnezia-wireguard` (`wireguard`): `last_config`
holds the client `.conf` in `config` (older exports leave `$PRIMARY_DNS` / `$SECONDARY_DNS`,
filled from `dns1` / `dns2`) and `mtu` (applied when the `.conf` has none); `amnezia-xray`
(`xray`) / `amnezia-ssxray` (`ssxray`): `last_config` is an Xray client config for `parse_json`.
Profiles are named by `description`. Every other container (`openvpn`, `openvpn-cloak`,
`shadowsocks` = OpenVPN over SS, `ipsec`, `dns`, `sftp`, `torwebsite`, `socks5proxy`, `mtproxy`,
`telemt`, `tproxy`) -> `UnsupportedProtocol(<AmneziaVPN's name>)`; a container without a client
config (an administrator export: its `userName` / `password` are SSH credentials and are never
read) -> `Invalid`; Amnezia Premium / Free keys (`api_key`, `auth_data`, `apiConfig`) ->
`UnsupportedProtocol`. Excerpts are `vpn://…`.

## text (`vpnte_profiles::text`, pure and linear)

```rust
pub const MAX_INPUT_BYTES: usize = 1 << 20;  pub const MAX_BODY_BYTES: usize = 16 << 20;
pub const MAX_BASE64_DEPTH: usize = 3;       pub const MAX_JSON_SPANS: usize = 64;
pub fn prepare(input: &str, max_bytes: usize) -> Result<&str, TooLarge>;
pub fn decode_body(raw: &[u8], cap: usize) -> Result<String, TooLarge>;
pub fn decode_base64_layer(text: &str) -> Option<String>;     // strict whole-text base64 -> UTF-8
pub fn layers(text: &str) -> Vec<Cow<'_, str>>;               // [text, layer1, ...]
pub fn json_spans(text: &str, max: usize) -> Vec<Range<usize>>;
pub fn blank_spans(text: &str, spans: &[Range<usize>]) -> String;
pub const URI_SCHEMES: &[&str];                               // + `ssr`, `hysteria` (reported as unknown)
pub fn is_uri_line(line: &str) -> bool;
pub fn uri_candidates(text: &str) -> Vec<&str>;               // document order, not deduplicated
pub fn body_meta(text: &str) -> (SubscriptionMeta, &str);
pub fn apply_meta(meta: &mut SubscriptionMeta, key: &str, value: &str);
pub fn header_meta<'a>(headers: impl IntoIterator<Item = (&'a str, &'a str)>, body: SubscriptionMeta)
    -> SubscriptionMeta;                                      // headers win, body fills gaps
// provider controls (Happ app-management keys that steer the client)
pub enum AutoconnectPick { LastUsed, LowestDelay, Random }   // serde "lastused" | "lowestdelay" | "random"
pub struct Controls { pub routing: Option<String>, pub hide_settings: Option<bool>,
    pub autoconnect: Option<bool>, pub autoconnect_pick: Option<AutoconnectPick>,  // serde camelCase
    pub tls_tricks: Option<TlsTricks> }  // `fragmentation-enable|packets|length|interval` (Happ, limcore):
    // enable 0/false = Off; on: packets (default tlshello), length / pause (default the preset);
    // no enable = None. Servers put it on a provider's new rows once (afterwards the user's).
impl Controls { pub fn hides_settings(&self) -> bool }
pub struct Relocation { pub fallback_url: Option<String>, pub new_url: Option<String>,
    pub new_domain: Option<String> }                          // tokens: Debug prints only presence
pub struct ProviderKeys { pub controls: Controls, pub relocation: Relocation, /* private */ }
impl ProviderKeys { pub fn apply(&mut self, key: &str, value: &str); pub fn or(self, other: Self) -> Self }
pub fn body_keys(text: &str) -> ProviderKeys;                 // top comment block + a happ://routing/ line
pub fn header_keys<'a>(headers: impl IntoIterator<Item = (&'a str, &'a str)>, body: ProviderKeys)
    -> ProviderKeys;                                          // headers win field by field
// Happ routing profiles (p-provider-routing): read only, for a preview; nothing is applied here
pub const MAX_PROFILE_BYTES: usize = 64 * 1024;
pub fn parse_routing(value: &str) -> Result<RoutingValue, RoutingError>;  // link, its base64 or JSON
pub enum RoutingValue { Profile(RoutingProfile), Off /* happ://routing/off */ }
pub struct RoutingProfile { pub name: Option<String>, pub global_proxy: bool /* default true */,
    pub entries: Vec<RouteEntry> /* RouteOrder (default block-proxy-direct), sites before IPs */,
    pub dns: Vec<String> /* remote, domestic; DoH URL else address */, pub dns_hosts: usize,
    pub fake_dns: bool }
pub struct RouteEntry { pub route: Route, pub entry: Entry, pub raw: String /* as written */ }
pub enum Route { Block, Proxy, Direct }
pub enum Entry { Domain(String), Full(String), Keyword(String), Plain(String), Regexp(String),
    Geosite(String), Geoip(String), Ip(IpNet), External(String), Unknown(String) } // Xray syntax
pub enum RoutingError { NotRouting, Damaged, TooLarge }      // .msg(): profiles.routing.*
```
Routing profiles (Happ's public docs, `happ.su/main/dev-docs/routing`): `happ://routing/add|onadd/
<base64 JSON>` (either alphabet, padding optional or `%3D`, or percent-encoded JSON), `happ://routing/off`,
or the base64 / JSON alone (a provider's stored `Controls::routing`). A JSON object needs one of
`GlobalProxy`, `*Sites`, `*Ip`, `RouteOrder` to count; single values are strings (`"true"`), a JSON bool
reads the same. Every non-blank list item becomes an entry (a non-string as `Unknown`, a list sent as one
string as one entry, entries over 512 bytes cut for display), so nothing a provider sent goes unseen.
The app maps entries to the user's own rules (`app::api_lists::split::routing`).
Comment blocks: `#key: value` and (Hiddify) `//key: value` lines; a `//` line made only of base64
characters is body, not a comment. Keys: `routing` (kept as sent, at most 64 KiB, no control
characters; a `happ://routing/…` body line counts when no key names one), `hide-settings` and
`subscription-autoconnect` (`true` / `1` on, any other non-blank value off),
`subscription-autoconnect-type`, `fallback-url`, `new-url` = `moved-permanently-to` (`http(s)` URLs),
`new-domain` (`host[:port]` only).
`http(s)://` lines are never link candidates (a support link must not become a broken key).
Per-line base64 is not decoded (a MIME-wrapped body would yield truncated keys). The
`Content-Disposition` file name is the last title fallback; `filename*` wins over `filename`.

## device, countries

```rust
// device
pub const HAPP_VERSION: &str = "3.22.1";  pub const HWID_ENV: &str = "VPNTE_SUBSCRIPTION_HWID";
pub struct DeviceProfile { pub os: &'static str, pub os_version: &'static str, pub model: &'static str }
pub fn device_profile(device: ClientDevice) -> DeviceProfile;
pub fn utls_fingerprint(device: ClientDevice) -> &'static str;   // chrome / android / ios / safari
pub fn user_agents(device: ClientDevice, hwid: Option<&str>) -> Vec<String>; // Happ UA first; None:
                                                                         // `Happ/<v>/<os>` without HWID
pub fn device_headers(device: ClientDevice, hwid: &str) -> [(&'static str, String); 4];
pub struct MachineIdentity { pub host_name: String, pub user_name: String, pub user_domain: String }
impl MachineIdentity { pub fn current() -> Self }
pub fn legacy_hwid(device: ClientDevice, id: &MachineIdentity) -> String;  // Electron HWID, bit-exact
pub fn is_valid_hwid(hwid: &str) -> bool;   // Remnawave v3.0.0: 10-64 of [a-zA-Z0-9=-]
pub fn random_hwid() -> String;             // a reset ID: 16 random lowercase hex digits
pub fn hwid_override() -> Option<String>;                        // env VPNTE_SUBSCRIPTION_HWID
// countries
pub struct Iso2;                 // Copy + Ord + Hash + Display; serde as "DE"
impl Iso2 { pub fn new(code: &str) -> Option<Self>; pub fn as_str(self) -> &'static str }
impl TryFrom<String> for Iso2 { type Error = UnknownCountry; }   // and From<Iso2> for &'static str
pub fn infer(name: &str) -> Option<Iso2>;   // flag (England / Scotland / Wales -> GB), code,
                                            // EN/RU/native alias; "Fastest" -> None
pub fn flag(code: Iso2) -> String;
pub fn name(code: Iso2, lang: Lang) -> &'static str;  // also name_en / name_ru
```

## caps, identity

```rust
// caps
pub enum Stealth { Reality, Ech, Naive, Obfs, Utls, Tls, Plain }   // serde kebab-case
impl Stealth { pub fn msg(self) -> Msg }                            // profiles.caps.stealth.*
pub struct Capabilities { pub protocol: &'static str, pub stealth: Stealth, pub tls: bool,
                          pub ech: bool, pub notes: Vec<Msg> }
pub fn capabilities(p: &Profile) -> Capabilities;
pub fn note_msg(note: &Note) -> Msg;           // every Note; Note::Other carries its own key
pub fn skip_msg(reason: &SkipReason) -> Msg;   // every SkipReason (profiles.caps.skip.*)
// identity (inherent method)
impl Profile {
    pub fn identity(&self) -> [u8; 16];        // stable key identity (golden-tested, version "v1")
}
```
`identity` hashes protocol, lower-case host, port, credential, SNI, TLS mode, Reality public key,
transport kind + path / service, HY2 ports, SS method, VLESS encryption, ShadowTLS password, WG
peers (AmneziaWG: the same under its own label, its obfuscation values excluded so that rotated
values keep the row), native graph; it ignores name, notes, mux, dial options and fingerprint. Use it for
de-duplication and to match rows across subscription refreshes; never change its inputs.
Which engine runs a profile is decided by `vpnte_engine::select_engine` only (this crate keeps
no second copy of that table). `capabilities` of AmneziaWG: stealth `Obfs`, no TLS, first note
`profiles.awg.noEngine` (sing-box and Xray cannot run it; mihomo is a lab function of this
build), then `profiles.awg.invalid` when `awg::validate` fails. `udpOnTcpOnly` is not shown for
Hysteria2 (the emitter drops a stored tcp-only `network` there).

## emit_singbox (sing-box 1.14 JSON; the only place outbound normalisation happens)

```rust
pub struct EmitPolicy {
    pub device: Option<ClientDevice>,     // default uTLS fp of TCP-TLS when the provider named none
    pub tls_compat: bool,                 // stealth / adaptive TLS compat: default tricks STRONG + fp rotation
    pub allow_mux: bool,                  // false: the profile's multiplex is not emitted
    pub domain_resolver: Option<String>,  // DNS server tag for hostname servers ("dns-bootstrap")
}                                         // Default: { None, false, true, None }
pub enum SingBoxFragment { Outbound(Value), Endpoint(Value), Chain(Vec<Value>) }
impl SingBoxFragment {
    pub fn outbounds(&self) -> &[Value];  // for `outbounds` (the tagged one first); empty for Endpoint
    pub fn endpoints(&self) -> &[Value];  // for `endpoints` (WireGuard)
    pub fn needs_bootstrap_dns(&self) -> bool;  // a dialed server / WG peer is a host name
    pub fn endpoint_ips(&self) -> Vec<IpAddr>;  // dialed IP literals (route_exclude_address)
}
pub enum EmitError { XrayOnly(&'static str), MuxUnsupported(&'static str), TlsUnsupported(&'static str),
    TransportUnsupported(&'static str), RealityWithEch, RealityOverQuic, PinWithCertificate,
    CertPinUnenforced, EchConfig, SsPlugin(String), Hy2Obfs(String), WireGuard(WgProblem),
    Amneziawg /* sing-box has no AmneziaWG: never emitted as plain WireGuard */ }
pub enum WgProblem { NoAddress, NoPeer, NoPrivateKey, NoPeerAddress, BadPeerPort, NoPublicKey, AllowedIpsRequired }
impl From<EmitError> for AppError;        // Validation + profiles.emit.*
pub fn emit_singbox(p: &Profile, tag: &str, policy: &EmitPolicy) -> Result<SingBoxFragment, EmitError>;
pub fn udp_capable(p: &Profile) -> bool;  // false -> the engine adds an all-UDP reject rule
pub fn block_quic(p: &Profile) -> bool;   // true -> reject UDP/443 (incl. a native graph's Xray mux)
pub fn effective_fingerprint(p: &Profile, policy: &EmitPolicy) -> Option<&'static str>;  // for the UI
pub fn stealth_fingerprint(seed: &str) -> &'static str;   // chrome / firefox / edge rotation
```
Engine use (engine-config / tunnel): `let f = emit_singbox(&p, "proxy-out", &policy)?;` put
`f.outbounds()` into `outbounds` and `f.endpoints()` into `endpoints`; with
`domain_resolver: Some("dns-bootstrap")` add that DNS server when `f.needs_bootstrap_dns()`; add
`f.endpoint_ips()` as /32 or /128 to `route_exclude_address`; `udp_capable` / `block_quic` drive
the UDP reject rules. A Chain is `[shadowsocks(tag, detour), shadowtls("<tag>-shadowtls")]`. The
fragment never carries `domain_strategy`, `detour` (except inside the chain), bind keys or
`*_path` keys. `XrayOnly(feature)`: native graph, XHTTP, gRPC multi mode (`multi_mode: Some(true)`;
explicit gun is emitted as sing-box gRPC), TCP HTTP header, VLESS
encryption, `verifyPeerCertByName` (`Tls::cert_names`), `mldsa65Verify` (`Reality::mldsa65_key`;
sing-box has neither check) — run those on Xray. Provider uTLS names sing-box does not know fall back to the default.
Default uTLS when the provider names none: REALITY always `chrome` (servers since Xray 26.9.8 refuse
the device defaults `android` / `ios`); other TCP TLS the device default, else the stealth rotation,
else `chrome`. Pins: `spki_pin_sha256` goes out as `certificate_public_key_sha256`, which sing-box
checks even next to `insecure: true`; `insecure` with a non-blank `cert_pin_sha256` (whole-certificate
hash, which sing-box 1.14 cannot check) and no SPKI pin is refused with `CertPinUnenforced` on every
kind (route such keys to Xray, which enforces `pinnedPeerCertSha256`); without `insecure` the
certificate pin is not emitted and the CA check runs (`Note::CertPinNotEnforced` stays true).

TLS tricks (TCP TLS without REALITY only; never the ShadowTLS dialer, naive or QUIC):
`p.tls_tricks_for(policy.tls_compat)` -> `record_fragment` (record),
`fragment` + `fragment_fallback_delay` = the split's longest pause, at least 1 ms (hello; sing-box
has no length knob, cuts inside the SNI and waits for the ACK where it can see it). Pasted
`tls.fragment*` keys are never re-emitted raw: they add to the default, a typed value overrides
them.

## xray_native (provider Xray graphs; Xray JSON itself is `vpnte_engine::xray_config`'s job)

```rust
pub const FIELD: &str = "vpnte_xray";             // key of the graph in a legacy outbound row
pub const EXPORT_BLOCK_TAG: &str = "vpnte-block"; // reserved blackhole tag of exported documents
pub enum NativeError { InvalidProfile, MissingSelected, DuplicateTag, BadBalancerTag, MissingBalancer,
    EmptyBalancer, MissingDependency, ApplicationBypass, Cyclic, MissingLoopbackRoute,
    LoopbackRouteNoDestination, UnsupportedProtocol, NoEntry, SelectedOutsideGraph, LocalFileReference,
    MultipleEndpoints, InsecureWithoutPin, ReservedTag, TooDeep, GeoData, RemovedTransport }
impl NativeError { pub fn msg(&self) -> Msg }      // profiles.xrayNative.*
impl From<NativeError> for AppError;               // Validation
pub struct CompiledGraph { pub outbounds: Vec<Value>, pub rules: Vec<Value>, pub balancers: Vec<Value>,
    pub entry: Value, pub observatory: Option<Value>, pub burst_observatory: Option<Value>,
    pub policy: Option<Value> }                    // Debug shows only the shape
pub fn decode(value: &Value) -> Result<NativeXray, NativeError>;   // stored graph -> validated
pub fn validate(graph: &NativeXray) -> Result<(), NativeError>;
pub fn selected_outbound(graph: &NativeXray) -> Result<&Value, NativeError>;
pub fn document_entry(doc: &Value) -> Option<NativeEntry>;
pub fn document_selected<'a>(doc: &'a Value, entry: &NativeEntry) -> Option<&'a Value>;
pub fn preserve(selected: &Value, doc: Option<&Value>, entry: Option<NativeEntry>) -> Result<NativeXray, NativeError>;
pub fn compile(graph: &NativeXray, primary: &Value) -> Result<CompiledGraph, NativeError>;
pub fn export_document(graph: &NativeXray, name: &str) -> Result<Value, NativeError>;
pub fn mux_rejects_udp443(graph: &NativeXray) -> bool;
```
Engine use: `let primary = selected_outbound(&g)?` (substitute a resolved address if needed),
`let c = compile(&g, &primary)?`; config = outbounds `c.outbounds` + `direct` + `block`; routing
rules = `{"type":"field","inboundTag":["in"], ..c.entry}`, then `c.rules` (ends with the guard to
`block`), then the app's catch-all block; `balancers`, observatories and `policy` as returned.
Compiled tags: selected -> `proxy`, other -> `vpnte-source:T`, balancer -> `vpnte-balancer:B`,
loopback -> `vpnte-loop:L`. `compile` re-runs every import check (file references, insecure TLS
without pin, exactly one server and one user per outbound, bypass protocols, cycles, depth > 64,
copied loop rules that match by `geoip:` / `geosite:` / `ext:` data, which the bundled Xray does
not ship -> `GeoData`, a reachable outbound streaming over `h2` / `h3` / `http` / `quic`, which
Xray 26 refuses to load -> `RemovedTransport`; `export_document` refuses those graphs too);
`allowInsecure` next to a pin is dropped (Xray 26 refuses the flag).

## export

```rust
pub enum Shared { Uri(String), Json(Value), Conf(String) /* AmneziaWG */ }
impl Shared {
    pub fn text(&self) -> String;          // the link, the JSON document on one line, the .conf
    pub fn notice(&self) -> Option<Msg>;   // Json -> profiles.export.sharedAsJson,
}                                          // Conf -> profiles.export.sharedAsConf
pub fn export_uri(p: &Profile) -> Option<String>;      // only lossless links; imported line kept verbatim
pub fn export_share(p: &Profile) -> Option<Shared>;    // link, else native graph's Xray document,
                                                       // else {"remarks", "outbounds"|"endpoints"}
pub fn export_proxy_line(p: &Profile) -> Option<String>;  // socks5:// http:// https:// (naive h2)
pub fn export_conf(p: &Profile) -> Option<String>;     // WireGuard / AmneziaWG `.conf`
pub fn export_mihomo(p: &Profile) -> Option<String>;   // WireGuard / AmneziaWG mihomo `proxies:` doc
```
AmneziaWG has no link (`export_uri` -> `None` unless the imported line reads back unchanged);
`export_share` gives its `.conf` (`Shared::Conf`), which AmneziaVPN and the AmneziaWG apps import.
`export_conf` / `export_mihomo` return `None` for other kinds and for profiles with TLS, a
transport, mux, dial options or raw sing-box keys. Round trips (`wg_ini` / `clash` reading the
export) keep every parameter, with two documented exceptions: a lone peer without AllowedIPs is
written as `0.0.0.0/0, ::/0` (what it carries here, K21; other clients route nothing without
it), and mihomo has no keepalive range, so an AmneziaWG 3.x range goes out as its lower bound.
`export_mihomo` also refuses two local addresses of one family and peers with different
keepalives (mihomo keeps one of each per entry); it writes `version: 3` for 3.x.
A link is returned only when re-importing it yields the same profile (mux, dial options,
`singbox_extra`, pins, multi-peer WireGuard, ShadowTLS, … -> no link). V2Ray-family links write
`vcn` / `pqv` (another scheme cannot carry them -> no link); VMess JSON writes `vcn`, `pqv` there
-> no VMess link. TLS tricks go back as `fragment=` in Xray's order (`tlshello,100-200,10-20`,
`1,40-60,30-50`) on VLESS / Trojan links; other schemes and VMess JSON have no reader for them
(-> no link, the JSON share keeps them). A key stored before item 18 (`fragment=` only noted,
`Tls::tricks` absent) still gets its imported line back. The JSON share is
`emit_singbox(p, "proxy", &EmitPolicy::default())`, so it carries the emitter's defaults (uTLS
`chrome`, TUIC `alpn: ["h3"]`): runnable on any sing-box client, read back as provider values on
re-import. `None` = neither form can carry the key (e.g.
an Xray-only transport with dial options). Exports are NOT redacted: show the secret-export
warning and use the clipboard / file helpers of the app.

## Errors, i18n and secrets

- Error enums convert to `AppError` with `ErrorKind::Validation` and a `Msg`: `EmitError`
  (`profiles.emit.*`, WireGuard problems under `profiles.emit.wireguard.*`), `NativeError`
  (`profiles.xrayNative.*`), `LegacyError` (`profiles.legacy.*`). `DeepLinkError::msg()` gives
  `profiles.deeplink.*` (`encryptedHapp`, `encryptedMantaray`, `encrypted`, `routingProfile`,
  `addPayloadUnrecognised`, `unknownHost`, `amneziaDamaged`, `amneziaUnsupported`, `localTarget`).
  `RoutingError::msg()` gives `profiles.routing.{notRouting, damaged, tooLarge}`.
  `awg::AwgInvalid` (`profiles.awg.invalid`, arg `fields`).
- What the UI must render with this crate's keys: `caps::note_msg(&note)` for every `Profile.notes`
  entry (`profiles.caps.note.*`; `Note::Other` keys: `profiles.import.realityFingerprint`,
  `profiles.import.xrayTransportRemoved`, `profiles.import.naivePinNotEnforced`, and on rows
  stored by older builds `profiles.wgIni.amneziaIncompatible` / `amneziaJunkDropped`, which now
  ask to import the key again), `caps::skip_msg(&skipped.reason)` for every skipped entry
  (`profiles.caps.skip.*`, `profiles.awg.invalid`), `Stealth::msg()` (`profiles.caps.stealth.*`),
  `Capabilities.notes` (also `profiles.awg.noEngine`), `Shared::notice()`
  (`profiles.export.sharedAsJson`, `profiles.export.sharedAsConf`).
- Register the strings at start: `for (ru, en) in vpnte_profiles::LOCALES { … }` (one pair per work
  package, file-name order; all keys under `profiles`). A test keeps `LOCALES` equal to `locales/`
  and checks that every `"profiles.…"` key written in the sources exists in both languages.
- No events, no async, no global state. Log lines of this crate are English (`tracing::debug!` in
  the Clash reader only).
- `Debug` of `Profile` and its parts hides credentials (UUIDs, passwords, private / pre-shared keys,
  the imported link, graph outbounds print as `<hidden>` or counts; the verbatim option maps
  `singbox_extra` and XHTTP `extra` print their keys only), so `?profile` is safe in logs;
  still prefer `name`, `kind.label()`, `server`. `serde` output and exports are NOT redacted.

## Not implemented here (by design)

- `parse_text`, `resolve`, subscription fetching, dedup / reconcile: `vpnte-servers` (above flow).
- Xray JSON for typed profiles and engine selection: `vpnte-engine` (`xray_config`, `select_engine`).
- Running AmneziaWG (WP-12, lab gate): this crate models, imports, checks and exports AmneziaWG
  keys only; no bundled engine runs them (`EmitError::Amneziawg`, engine `Reject::Amneziawg`).
  The mihomo runner is the next package and must call `awg::validate` before any start.
- Clash `proxy-providers` (remote lists), mihomo-only protocols / plugins (TUIC v4, restls, jls,
  kcptun, SOCKS over TLS, …): skipped with a reason.
- Whole-certificate pins (`cert_pin_sha256`) on sing-box 1.14: not emitted (`Note::CertPinNotEnforced`);
  next to `insecure` the emitter refuses the key (`CertPinUnenforced`), Xray enforces it.
- Typed mapping of Xray `mux` (kept inside a native graph only).
- Xray geo data: provider graphs whose copied loop rules need `geoip.dat` / `geosite.dat` / an
  `ext:` file are refused (`NativeError::GeoData`); no `.dat` file is shipped or read.
- Provider Xray documents whose entry rule targets a non-selectable outbound (e.g. a loopback in
  front of the balancer) are not imported as one graph.

## Tests that touch the outside

- `emit_singbox` `check` tests pipe the emitter's whole shape matrix (every protocol / transport /
  TLS combination and protocol knob) through `resources/sing-box.exe check`; `clash::check` does
  the same for what the Clash and WireGuard INI importers produce (20 profiles, default and
  stealth policy), `json::xray_tests` for the typed profiles the Xray-format importer produces
  (SOCKS / HTTP / WireGuard, plain outbounds, h2 / QUIC conversions); `xray_native` tests run
  `resources/xray.exe run -test` (all skipped quietly
  when the binary is absent). Two `emit_singbox::dial` tests (`#[ignore]`, they start two
  sing-box processes on loopback) dial a real Hysteria2 and a ShadowTLS v3 server.
- Nothing needs elevation; `MachineIdentity::current()` is read-only.
