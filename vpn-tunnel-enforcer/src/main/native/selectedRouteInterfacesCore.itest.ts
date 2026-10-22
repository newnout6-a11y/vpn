// AT-06-003 / AT-00-003 / AT-02-002: read-only route-selection equivalence on Windows.
// No route writes, packets, VPN starts/stops or firewall changes are performed.
import { execFileSync } from 'node:child_process'
import { performance } from 'node:perf_hooks'
import { expect, it } from 'vitest'
import { readSelectedIpv4InterfacesInProcess } from './selectedRouteInterfacesCore'

it.runIf(process.platform === 'win32' && ['x64', 'arm64'].includes(process.arch))('agrees with unrestricted MSFT_NetRoute.Find for all three destinations', () => {
  const start = performance.now(), native = readSelectedIpv4InterfacesInProcess(), nativeMs = performance.now() - start
  const script = `
$ErrorActionPreference = 'Stop'
$indexes = @(foreach ($destination in @('1.1.1.1', '8.8.8.8', '208.67.222.222')) {
  $found = Invoke-CimMethod -Namespace root/StandardCimv2 -ClassName MSFT_NetRoute -MethodName Find -Arguments @{RemoteIPAddress=$destination}
  $routes = @($found.CmdletOutput | Where-Object { $_.DestinationPrefix })
  if ($found.ReturnValue -ne 0 -or $routes.Count -ne 1 -or $routes[0].InterfaceIndex -le 0) { throw 'Selected route unavailable' }
  [uint32]$routes[0].InterfaceIndex
})
ConvertTo-Json -InputObject $indexes -Compress
`
  const psStart = performance.now()
  const legacy = JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
    { windowsHide: true, timeout: 10000, encoding: 'utf8', stdio: 'pipe' }).trim())
  const powershellMs = performance.now() - psStart
  expect(native).toHaveLength(3)
  expect(native).toEqual(legacy)
  expect(readSelectedIpv4InterfacesInProcess()).toEqual(legacy) // Independent fresh read, no result cache.
  console.log(JSON.stringify({ fixture: 'selected-routes-read-only', nativeMs, powershellMs }))
}, 15000)
