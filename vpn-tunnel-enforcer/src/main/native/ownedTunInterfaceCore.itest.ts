// AT-02-002 / AT-06-003: read-only equivalence; never creates/stops VPNs or changes the network.
import { execFileSync } from 'node:child_process'
import { expect, it } from 'vitest'
import { readOwnedTunIndexInProcess } from './ownedTunInterfaceCore'

it.runIf(process.platform === 'win32')('agrees with fresh CIM Wintun ownership', context => {
  const script = `
$ErrorActionPreference='Stop'
$rows = @(Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetAdapter | Where-Object { $_.DriverDescription -match '^Wintun\\b' } | ForEach-Object {
  $adapter = $_
  $addresses = @(Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_NetIPAddress -Filter "InterfaceIndex = $($adapter.InterfaceIndex)" |
    Where-Object { $_.IPAddress -eq '192.168.250.253' -and $_.PrefixLength -eq 30 })
  $owned = $adapter.InterfaceOperationalStatus -eq 1 -and $adapter.PnPDeviceID -like 'SWD\\Wintun\\*' -and $addresses.Count -eq 1
  [pscustomobject]@{ alias=$adapter.Name; guid=[string]$adapter.InterfaceGuid; expected=$(if ($owned) { [uint32]$adapter.InterfaceIndex } else { $null }) }
})
ConvertTo-Json -InputObject $rows -Compress
`
  const legacy = JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
    { windowsHide: true, timeout: 15000, encoding: 'utf8', stdio: 'pipe' }).trim()) as { alias: string; guid: string; expected: number | null }[]
  const start = performance.now()
  const positive = legacy.filter(row => row.expected !== null).length
  if (process.env.VPNTE_REQUIRE_TUN_OWNERSHIP_COMPARISON === '1') expect(positive, 'a live VPNTE TUN is required for positive CIM equivalence').toBeGreaterThan(0)
  else if (!positive) context.skip('No active VPNTE Wintun; positive equivalence was not checked')
  for (const row of legacy) {
    expect(readOwnedTunIndexInProcess(row.alias, row.guid)).toBe(row.expected)
    expect(readOwnedTunIndexInProcess(row.alias, row.guid)).toBe(row.expected)
    expect(readOwnedTunIndexInProcess(row.alias, '{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}')).toBeNull()
  }
  console.log(JSON.stringify({ fixture: 'owned-tun-read-only', comparisons: legacy.length, positive,
    nativeMs: performance.now() - start }))
}, 20000)

it.runIf(process.platform === 'win32')('rejects an absent alias', () => {
  expect(readOwnedTunIndexInProcess('VPNTE-absent-equivalence', '{11111111-2222-3333-4444-555555555555}')).toBeNull()
})
