# Resources

Place the following binaries here before building:

- **sing-box.exe** — Download from https://github.com/SagerNet/sing-box/releases (Windows amd64)
- **libcronet.dll** — From the same sing-box Windows amd64 archive; keep next
  to `sing-box.exe`.
- **wintun.dll** — Download from https://www.wintun.net/ (Windows amd64)
- **xray.exe** — Download from https://github.com/XTLS/Xray-core/releases (Windows 64-bit, v26.7.x or later). Used as secondary proxy engine for modern REALITY inbounds.

These will be bundled into the installer via `extraResources` in electron-builder.
