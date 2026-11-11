# vpnte-profiles — API for dependent crates

Typed VPN profiles: the model every crate stores and passes, importers (share links, JSON,
Clash YAML, WireGuard `.conf`, app deep links, Electron rows), the text pipeline building blocks,
the sing-box emitter, the native Xray graph, exporters, identity and capability summaries.
Depends only on `vpnte-base`. Pure code: no I/O, no network, no async, nothing needs elevation
(the one Win32 call, `device::MachineIdentity::current`, reads host and user names).

```toml
vpnte-profiles.workspace = true
```

| module | what |
| --- | --- |
| `model` | `Profile` and its parts, `ParseReport`, `Skipped`/`SkipReason`, `SubscriptionMeta`, `EngineNeed`, `TooLarge` |
| `uri` | one share link -> `Profile` |
| `json` | sing-box / Xray / wrapped JSON -> `ParseReport` |
| `clash`, `wg_ini` | Clash (mihomo) YAML, WireGuard `.conf` |
| `deeplink` | `happ://` / `mantaray://` / `v2raytun://` / `incy://` -> carried text or URL |
| `legacy` | one stored Electron row -> `Profile` |
| `text` | limits, body decoding, base64 layers, JSON spans, link candidates, subscription metadata |
| `device`, `countries` | subscription UA / HWID headers, uTLS default per device; ISO country guess |
| `caps` | capability summary + i18n of `Note` / `SkipReason` |
| `identity` | `Profile::identity()`, `Profile::engine_need()` |
| `emit_singbox` | the only producer of sing-box JSON (`Profile` -> outbound / endpoint / chain) |
| `xray_native` | provider Xray graphs: import, validate, compile for the engine, export |
| `export` | share link, share document (link or JSON), proxy-list line |
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
    Socks{username, password}, Http{username, password} }
impl Kind { pub fn label(&self) -> &'static str; pub fn is_udp_transport(&self) -> bool }
pub enum Transport { Ws{..}, Grpc{service_name, multi_mode}, Http{hosts, path}, HttpUpgrade{host, path},
    Quic, Xhttp{host, path, mode, extra} /* Xray only */, TcpHttpHeader{host, path} /* Xray only */ }
pub enum Note { NaiveInsecureIgnored, CertPinNotEnforced, AlterIdNormalized(u32), ProviderFpDroppedOnQuic,
    UnsupportedField(String), FileReferenceDropped(String), DialFieldDropped(String), Unencrypted,
    MuxSingBoxOnly, Other(String /* an i18n key */) }
pub struct ParseReport { pub profiles: Vec<Profile>, pub skipped: Vec<Skipped>, pub meta: SubscriptionMeta }
pub struct Skipped { pub excerpt: String /* redacted, <= 80 chars */, pub reason: SkipReason }
pub enum SkipReason { UnknownScheme(String), Invalid{scheme, detail /* English */}, MissingCredential,
    ShadowTlsNeedsInner, UnsupportedPlugin(String), UnsupportedTransport(String), Duplicate,
    NativeGraphRejected(String) }
pub struct SubscriptionMeta { upload, download, total: Option<u64>, expires_at: Option<UnixMs>,
    refresh_hours: Option<u32>, title, web_page_url, support_url, announce: Option<String> }
pub enum EngineNeed { Any, PreferXray(&'static str), XrayOnly(&'static str), SingBoxOnly(&'static str) }
pub struct TooLarge;                      // input over a limit
```
`Profile` is `Serialize + Deserialize` (the stored form; serde shapes are part of the stored data —
change them only additively). Provider values are kept as given: uTLS / ALPN / mux defaults are
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
`text::header_meta(headers, meta_from_body)`. Fetch headers: `device::user_agents(device, hwid)` and
`device::device_headers(device, hwid)` with one `hwid` = `device::hwid_override()` or the frozen
`device::legacy_hwid(device, &MachineIdentity::current())` (compute once, persist).

## Importers

```rust
// uri
pub fn parse_uri(line: &str) -> Result<Profile, SkipReason>;  // Source::Uri(trimmed line)
pub fn excerpt(line: &str) -> String;                         // redacted `scheme://host:port` for Skipped
// json
pub fn parse_json(value: &serde_json::Value) -> ParseReport;  // never fails; `meta` stays default
// clash / wg_ini
pub fn parse_clash(text: &str) -> Option<ParseReport>;        // None: not a Clash document
pub fn parse_wg_ini(text: &str) -> Option<Result<Profile, SkipReason>>;  // None: not a WireGuard config
// deeplink
pub enum DeepLinkError { Encrypted { app: &'static str, variant: String }, RoutingProfile,
                         AddPayloadUnrecognised, UnknownHost(String) }
impl DeepLinkError { pub fn msg(&self) -> Msg }               // profiles.deeplink.*; never the payload
pub fn unwrap_deeplink(input: &str) -> Result<Option<String>, DeepLinkError>;  // Ok(None): not a deep link
// legacy (one-time Electron import, the app orchestrates; see CONTRACT §3.5)
pub enum LegacyError { NotAnObject, UnsupportedProtocol(String), Unusable(String), InvalidNativeGraph }
impl From<LegacyError> for AppError;                          // Validation + profiles.legacy.*
pub fn from_legacy(name: &str, protocol: &str, outbound: &Value, source_uri: Option<&str>)
    -> Result<Profile, LegacyError>;                          // a share-link row is re-read from its link
```
- `parse_uri` schemes (any case): `vless vmess trojan ss hysteria2|hy2 tuic naive|naive+https|naive+quic
  anytls wireguard|wg socks|socks5|socks5h http|https` (proxy links need a root path and a port);
  `shadowtls` -> `ShadowTlsNeedsInner`, others -> `UnknownScheme(scheme)` (`""`: no `scheme://`).
- `parse_json` reads sing-box outbounds / endpoints (incl. the SS + ShadowTLS chain), Xray outbounds
  and whole provider documents (one document with a native graph = one profile, rejected graph =
  `NativeGraphRejected`), wrappers up to depth 6, JSON strings (nested JSON, <= 2 base64 layers,
  share links, Clash text). Never walks `inbounds dns route routing log ...`. Xray 26 Hysteria
  `finalmask` maps Salamander / Gecko, `udpHop` and the Brutal rates (`brutalUp` / `brutalDown`
  -> `up_mbps` / `down_mbps` as Xray's client applies them); other masks / QUIC knobs are Notes.
- `parse_clash` streams only the first root `proxies` list (limits: 5000 entries, nesting 32,
  64 MiB of approximate materialised bytes, alias copies included); every unread key becomes
  `Note::UnsupportedField`, so do unread sub-keys of the transport's `*-opts` map and of
  `reality-opts` (`"grpc-opts.ping-interval"`).
- `unwrap_deeplink`: Happ / MantaRay / v2RayTun / INCY `add` / `import` payloads (URL, key, base64,
  `{"url"|"link": …}`) -> `Some(text)`; `crypt*` hosts -> `Encrypted`; multi-line input -> `None`.
- Every importer keeps provider values verbatim and records what it dropped as `Note`s; secrets
  never appear in `Skipped.excerpt`, `SkipReason` or error texts.
- Keys no engine can run are skipped at import as `Invalid` (the same predicates the emitter
  refuses with, so a stored key does not fail only at connect): REALITY over QUIC (Hysteria2,
  TUIC, QUIC transport) or with ECH (`uri`, `json`, `clash`); several WireGuard peers where one
  names no AllowedIPs (`json`, `clash`, `wg_ini`). `from_legacy` keeps old REALITY rows of that
  kind (the user's data is not dropped); the emitter refuses them at connect.

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
```
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
pub fn user_agents(device: ClientDevice, hwid: &str) -> Vec<String>;   // Happ UA first
pub fn device_headers(device: ClientDevice, hwid: &str) -> [(&'static str, String); 4];
pub struct MachineIdentity { pub host_name: String, pub user_name: String, pub user_domain: String }
impl MachineIdentity { pub fn current() -> Self }
pub fn legacy_hwid(device: ClientDevice, id: &MachineIdentity) -> String;  // Electron HWID, bit-exact
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
// identity (inherent methods)
impl Profile {
    pub fn identity(&self) -> [u8; 16];        // stable key identity (golden-tested, version "v1")
    pub fn engine_need(&self) -> EngineNeed;
}
```
`identity` hashes protocol, lower-case host, port, credential, SNI, TLS mode, Reality public key,
transport kind + path / service, HY2 ports, SS method, VLESS encryption, ShadowTLS password, WG
peers, native graph; it ignores name, notes, mux, dial options and fingerprint. Use it for
de-duplication and to match rows across subscription refreshes; never change its inputs.
`engine_need` reasons: `XrayOnly`: `native-graph xhttp grpc-multi tcp-http-header vless-encryption`;
`SingBoxOnly`: `hysteria2 tuic naive anytls wireguard socks http h2-transport quic-transport
insecure-without-pin ech shadowtls shadowsocks-plugin shadowsocks-uot reality-transport plaintext`;
`PreferXray`: `grpc-gun reality`. The engine crate makes the choice (`select_engine`).

## emit_singbox (sing-box 1.14 JSON; the only place outbound normalisation happens)

```rust
pub struct EmitPolicy {
    pub device: Option<ClientDevice>,     // default uTLS fp of TCP-TLS when the provider named none
    pub tls_compat: bool,                 // stealth / adaptive TLS compat: record_fragment + fp rotation
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
    TransportUnsupported(&'static str), RealityWithEch, RealityOverQuic, PinWithCertificate, EchConfig,
    SsPlugin(String), Hy2Obfs(String), WireGuard(WgProblem) }
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
encryption — run those on Xray. Provider uTLS names sing-box does not know fall back to the default.

## xray_native (provider Xray graphs; Xray JSON itself is `vpnte_engine::xray_config`'s job)

```rust
pub const FIELD: &str = "vpnte_xray";             // key of the graph in a legacy outbound row
pub const EXPORT_BLOCK_TAG: &str = "vpnte-block"; // reserved blackhole tag of exported documents
pub enum NativeError { InvalidProfile, MissingSelected, DuplicateTag, BadBalancerTag, MissingBalancer,
    EmptyBalancer, MissingDependency, ApplicationBypass, Cyclic, MissingLoopbackRoute,
    LoopbackRouteNoDestination, UnsupportedProtocol, NoEntry, SelectedOutsideGraph, LocalFileReference,
    MultipleEndpoints, InsecureWithoutPin, ReservedTag, TooDeep, GeoData }
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
not ship -> `GeoData`); `allowInsecure` next to a pin is dropped (Xray 26 refuses the flag).

## export

```rust
pub enum Shared { Uri(String), Json(Value) }
impl Shared {
    pub fn text(&self) -> String;          // the link, or the JSON document on one line
    pub fn notice(&self) -> Option<Msg>;   // Json -> profiles.export.sharedAsJson
}
pub fn export_uri(p: &Profile) -> Option<String>;      // only lossless links; imported line kept verbatim
pub fn export_share(p: &Profile) -> Option<Shared>;    // link, else native graph's Xray document,
                                                       // else {"remarks", "outbounds"|"endpoints"}
pub fn export_proxy_line(p: &Profile) -> Option<String>;  // socks5:// http:// https:// (naive h2)
```
A link is returned only when re-importing it yields the same profile (mux, dial options,
`singbox_extra`, pins, multi-peer WireGuard, ShadowTLS, … -> no link). The JSON share is
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
  `addPayloadUnrecognised`, `unknownHost`).
- What the UI must render with this crate's keys: `caps::note_msg(&note)` for every `Profile.notes`
  entry (`profiles.caps.note.*`; `Note::Other` keys: `profiles.wgIni.amneziaIncompatible`,
  `profiles.wgIni.amneziaJunkDropped`), `caps::skip_msg(&skipped.reason)` for every skipped entry
  (`profiles.caps.skip.*`), `Stealth::msg()` (`profiles.caps.stealth.*`), `Capabilities.notes`,
  `Shared::notice()` (`profiles.export.sharedAsJson`).
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
- AmneziaWG (planned WP-12): parameters are classified into Notes, never applied.
- Clash `proxy-providers` (remote lists), mihomo-only protocols / plugins (TUIC v4, restls, jls,
  kcptun, SOCKS over TLS, …), Xray `socks` / `http` outbounds: skipped with a reason.
- Certificate pins: stored and exported, not enforced by sing-box 1.14 (`Note::CertPinNotEnforced`).
- Typed mapping of Xray `mux` (kept inside a native graph only).
- Xray geo data: provider graphs whose copied loop rules need `geoip.dat` / `geosite.dat` / an
  `ext:` file are refused (`NativeError::GeoData`); no `.dat` file is shipped or read.
- Provider Xray documents whose entry rule targets a non-selectable outbound (e.g. a loopback in
  front of the balancer) are not imported as one graph.

## Tests that touch the outside

- `emit_singbox` `check` tests pipe the emitter's whole shape matrix (every protocol / transport /
  TLS combination and protocol knob) through `resources/sing-box.exe check`; `clash::check` does
  the same for what the Clash and WireGuard INI importers produce (20 profiles, default and
  stealth policy); `xray_native` tests run `resources/xray.exe run -test` (all skipped quietly
  when the binary is absent). Two `emit_singbox::dial` tests (`#[ignore]`, they start two
  sing-box processes on loopback) dial a real Hysteria2 and a ShadowTLS v3 server.
- Nothing needs elevation; `MachineIdentity::current()` is read-only.
