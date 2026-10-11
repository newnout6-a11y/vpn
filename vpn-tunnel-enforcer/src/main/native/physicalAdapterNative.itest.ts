// AT-03-005/006/010: real-machine comparison of the native adapter snapshot with the PowerShell script.
// Integration only (spawns powershell.exe): npm run test:native-itest. Skip with VPNTE_SKIP_REAL_ADAPTER_TEST=1.
import { describe, expect, it } from 'vitest'
import { execFileSync } from 'child_process'
import { parseNetworkProfiles } from './networkProfiles'
import { createKoffiSource, readPhysicalAdaptersNative } from './physicalAdapterNative'
import { PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT } from '../physicalAdapterSnapshot'

const KEYS = ['ifIndex', 'interfaceGuid', 'alias', 'description', 'ipv6Enabled', 'ipv4Dns', 'gateways', 'networkProfiles', 'ipv4DnsSource', 'isCellularOrTethering']

function psSnapshot(): any[] {
  const ps = `[Console]::OutputEncoding=[Text.Encoding]::UTF8\n${PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT}`
  const out = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(ps, 'utf16le').toString('base64')], { encoding: 'utf8', timeout: 60000 }).trim()
  if (!out) return []
  const parsed = JSON.parse(out)
  return Array.isArray(parsed) ? parsed : [parsed]
}

// The real helper is not running under vitest: profiles are read from PowerShell here (same cmdlet the helper runs).
function psProfiles(): Map<number, string[]> {
  const out = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', "ConvertTo-Json -Compress -InputObject @(Get-NetConnectionProfile | ForEach-Object { [pscustomobject]@{ ifIndex = [int]$_.InterfaceIndex; name = [string]$_.Name } })"], { encoding: 'utf8', timeout: 60000 })
  return parseNetworkProfiles(out)
}

describe.skipIf(process.platform !== 'win32' || process.env.VPNTE_SKIP_REAL_ADAPTER_TEST === '1')('native vs PowerShell on this machine', () => {
  // Regression: koffi rejects re-declaring a named struct, so bindings must be built once per process.
  it('can be read repeatedly in one process without falling back', async () => {
    const profiles = psProfiles()
    const first = await readPhysicalAdaptersNative(createKoffiSource(profiles))
    const second = await readPhysicalAdaptersNative(createKoffiSource(profiles))
    expect(JSON.parse(second)).toEqual(JSON.parse(first))
  }, 90000)

  it('returns the same adapters and fields as the PowerShell snapshot', async () => {
    const native = JSON.parse(await readPhysicalAdaptersNative(createKoffiSource(psProfiles())))
    const nativeRows: any[] = Array.isArray(native) ? native : [native]
    for (const r of nativeRows) expect(Object.keys(r)).toEqual(KEYS)
    const ps = psSnapshot()
    const byIdx = (rows: any[]) => Object.fromEntries(rows.map(r => [r.ifIndex, r]))
    const norm = (r: any) => ({ ...r, ipv4Dns: [...r.ipv4Dns].sort(), gateways: [...r.gateways].sort() })
    expect(Object.keys(byIdx(nativeRows)).sort()).toEqual(Object.keys(byIdx(ps)).sort())
    for (const row of ps) expect(norm(byIdx(nativeRows)[row.ifIndex])).toEqual(norm(row))
  }, 90000)
})
