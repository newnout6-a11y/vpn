# Native adapter lockdown

This worker replaces the per-interface PowerShell mutations with Windows APIs.
It changes the `ms_tcpip6` binding through `INetCfgBindingPath::Enable` and
`INetCfg::Apply`, and IPv4 DNS through `SetInterfaceDnsSettings`. It never disables
a NIC. Cellular/CLAT IPv6 and public-Wi-Fi DNS exceptions remain in the controller.
Discovery, transition technologies, global DNS policies, and the durable trusted
recovery manifest keep their existing implementations.

## Build and test without Electron

From `vpn-tunnel-enforcer` on Windows x64 with MinGW-w64 or MSVC:

```powershell
npm run bench:adapter-lockdown
# Administrator terminal; real changes only on a newly created disposable NIC:
npm run bench:adapter-lockdown -- --isolated
```

Both commands build the production worker and the standalone benchmark and run
their self-tests. Only `--isolated` creates a Wintun adapter. No Wintun session,
IP, default route, VPN profile, or Electron process is created. The benchmark
checks apply/readback, original DNS reset, independent recovery after a missing
NIC, ordered static-DNS restoration, final reset, adapter removal, and unchanged
default routes. Its numeric JSON contains timings and verification results.
The fixture baseline is flushed to an owned `.tmp` file and removed afterwards.
The benchmark executable stays in `.tmp`; only the worker ships with the app.

The worker accepts a bounded fixed stdin protocol, not shell commands. `--batch`
preflights all target interfaces before effects and applies bindings once.
`--restore` attempts each field independently; one missing adapter must not
prevent DNS/IPv6 restoration on another. Every effect requires fresh readback.
An admitted application batch drains until process close; cancellation cannot
replay it or release its recovery owner early. A complete exit-1 error receipt
preserves independently successful restore outcomes. Unknown outcomes retain the
existing journal. Unsupported/pre-dispatch capability uses the legacy path;
post-dispatch failure never replays PowerShell interface mutations.

Component timings on a disposable virtual NIC do not prove physical-NIC rebind
latency, whole-connection speed, or packet-level leak acceptance. Windows can
still spend time inside the binding apply. The isolated benchmark's bounded
child timeout settles the child before deleting its own NIC; production never
force-kills a mutating child to report a fast cancellation.

## Official API references

- [Binding sample](https://github.com/microsoft/Windows-driver-samples/blob/main/network/config/bindview/BINDING.CPP)
- [INetCfg lock and initialization sample](https://github.com/microsoft/Windows-driver-samples/blob/main/network/config/bindview/NetCfgAPI.cpp)
- [SetInterfaceDnsSettings](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings)
- [DNS_INTERFACE_SETTINGS](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-dns_interface_settings)
- [Wintun API and created-adapter lifetime](https://git.zx2c4.com/wintun/plain/api/wintun.h)
