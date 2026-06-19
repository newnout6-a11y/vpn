## VLESS QUIC Fallback Investigation

Date: 2026-06-18

### Symptom

- The same server works normally in Happ.
- In VPN Tunnel Enforcer, YouTube stalls, sometimes shows "возникли неполадки", then suddenly recovers.
- Browser-based Speedtest also behaves poorly.
- DNS was already fixed separately; the remaining problem is transport-level.

### Evidence

From the diagnostic bundle `vpn-tunnel-enforcer-diagnostics-2026-06-18T07-55-29-785Z.zip`:

- `runtime-sing-box.json` showed a `vless` `proxy-out` with `network: "tcp"`.
- `runtime-sing-box.log` showed repeated:
  - `blocked packet connection to ...:443`
  - `outbound/block[block-out]: operation not permitted`
- The same log also showed YouTube domains correctly routed to `proxy-out`, so the problem was not Smart RU misrouting or DNS.

### Root Cause

Our profile import path was force-setting `network: "tcp"` for imported `vless` and `vmess` outbounds even when the source profile did not request a tcp-only restriction.

That made `generateSingboxConfig()` classify the outbound as tcp-only and install UDP blocking rules for `directVpn`, which caused Chromium QUIC attempts to fail before browser fallback to TCP completed.

### Why Happ Behaves Better

The most likely difference is that Happ does not artificially narrow imported VLESS profiles to tcp-only mode. That leaves sing-box free to accept UDP traffic for the outbound when supported by the protocol/runtime, avoiding the blackhole-like QUIC stall pattern seen in our logs.

### Fix

1. Stop hardcoding `network: "tcp"` in imported `vless` / `vmess` profiles.
2. Keep the explicit tcp-only path only for outbounds that are genuinely tcp-only by definition or by explicit profile data.
3. Add regression tests so imported VLESS/VMess profiles remain transport-flexible and `generateSingboxConfig()` no longer inserts QUIC/blanket UDP blocks for them by accident.

### Expected Outcome

- YouTube should stop hitting the long QUIC timeout stall.
- Browser traffic should behave much closer to Happ on the same server.
- DNS fix remains intact because it was handled separately in route rule ordering.
