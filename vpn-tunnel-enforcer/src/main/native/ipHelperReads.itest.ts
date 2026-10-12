// AT-07-002 / AT-07-012 / AT-08-007: native iphlpapi reads must agree with the legacy PowerShell reads.
// Real-machine comparison: skipped off Windows and when VPNTE_SKIP_NATIVE_COMPARE=1 (CI without PowerShell).
import { spawnSync } from 'node:child_process'
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { readRawAdapters, readRawIfConfigs, readRawRoutes } from './ipHelperReads'
import { toActiveTunnels, toAdapterRows, toIpConfigRows, toPhysicalIpv4Sources, toRouteRows } from './ipHelperTransforms'

const enabled = process.platform === 'win32' && process.env.VPNTE_SKIP_NATIVE_COMPARE !== '1'

function ps(script: string): any[] {
  const prelude = '$ProgressPreference="SilentlyContinue";$ErrorActionPreference="SilentlyContinue";' +
    '$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();'
  const r = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand',
    Buffer.from(prelude + script, 'utf16le').toString('base64')], { encoding: 'buffer', windowsHide: true, timeout: 60000 })
  expect(r.error).toBeUndefined()
  const text = r.stdout.toString('utf8').trim()
  if (!text || text === 'null') return []
  const parsed = JSON.parse(text)
  return Array.isArray(parsed) ? parsed : [parsed]
}

const split = (s: string) => String(s || '').split(',').map(x => x.trim()).filter(Boolean).sort()

describe.skipIf(!enabled)('native iphlpapi reads vs PowerShell (real machine)', () => {
  // Each comparison spawns a cold powershell.exe, which can exceed the default 5 s.
  vi.setConfig({ testTimeout: 60000, hookTimeout: 60000 })
  // Read in a hook: a koffi load failure must be a failing test, not a collection error.
  let adapters: ReturnType<typeof readRawAdapters> = []
  let configs: ReturnType<typeof readRawIfConfigs> = []
  beforeAll(() => { adapters = readRawAdapters(); configs = readRawIfConfigs() })

  it('lists the same visible adapters as Get-NetAdapter', () => {
    const native = toAdapterRows(adapters)
    const legacy = ps('Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed,ifIndex | ConvertTo-Json -Compress')
    // GetIfTable2 keeps the uniqueness suffix of duplicate descriptions ("sing-tun Tunnel #2"); Get-NetAdapter drops it.
    const key = (r: any) => `${r.ifIndex}|${r.Name}|${String(r.InterfaceDescription).replace(/\s+#\d+$/, '')}`
    // Known, deliberate divergence: GetIfTable2 also lists stale non-Up interfaces (e.g. a
    // disconnected Bluetooth PAN, a removed Wintun) that the NetAdapter WMI provider omits.
    // Native must be a SUPERSET of Get-NetAdapter and must agree on every adapter that is Up.
    const nativeKeys = new Set(native.map(key))
    for (const k of legacy.map(key)) expect(nativeKeys.has(k), k).toBe(true)
    const extras = native.filter(r => !legacy.some(l => key(l) === key(r)))
    expect(extras.every(r => r.Status !== 'Up'), JSON.stringify(extras)).toBe(true)
    const statusUp = (rows: any[]) => rows.filter(r => r.Status === 'Up').map(r => r.ifIndex).sort()
    expect(statusUp(native)).toEqual(statusUp(legacy))
  })

  it('matches Get-NetIPConfiguration for IPv4, gateway and DNS', () => {
    const native = toIpConfigRows(adapters, configs)
    const legacy = ps(`Get-NetIPConfiguration | ForEach-Object { [pscustomobject]@{
      InterfaceAlias=$_.InterfaceAlias; IPv4=($_.IPv4Address.IPAddress -join ','); IPv6=($_.IPv6Address.IPAddress -join ',');
      Gateway=($_.IPv4DefaultGateway.NextHop -join ','); DNS=($_.DNSServer.ServerAddresses -join ',') } } | ConvertTo-Json -Compress`)
    const meaningful = (r: any) => r.IPv4 || r.IPv6 || r.Gateway || r.DNS
    const n = new Map(native.filter(meaningful).map(r => [r.InterfaceAlias, r]))
    const l = new Map(legacy.filter(meaningful).map(r => [r.InterfaceAlias, r]))
    expect([...n.keys()].sort()).toEqual([...l.keys()].sort())
    for (const [alias, row] of l) {
      const got = n.get(alias)!
      expect(split(got.IPv4), alias).toEqual(split(row.IPv4))
      expect(split(got.IPv6), alias).toEqual(split(row.IPv6))
      expect(split(got.Gateway), alias).toEqual(split(row.Gateway))
      expect(split(got.DNS), alias).toEqual(split(row.DNS))
    }
  })

  it('matches Get-NetRoute for default and split-default prefixes', () => {
    const prefixes = ['0.0.0.0/0', '::/0', '0.0.0.0/1', '128.0.0.0/1', '::/1', '8000::/1']
    const native = toRouteRows(adapters, [...readRawRoutes(4), ...readRawRoutes(6)], prefixes)
    const legacy = ps(`$p=@('0.0.0.0/0','::/0','0.0.0.0/1','128.0.0.0/1','::/1','8000::/1');
      Get-NetRoute | Where-Object { $p -contains $_.DestinationPrefix -and $_.Store -ne 'PersistentStore' } |
      Select-Object DestinationPrefix,InterfaceAlias,NextHop,RouteMetric,Protocol | ConvertTo-Json -Compress`)
    const key = (r: any) => `${r.DestinationPrefix}|${r.InterfaceAlias}|${r.NextHop}|${r.RouteMetric}`
    expect(native.map(key).sort()).toEqual(legacy.map(key).sort())
  })

  it('matches the legacy physical-adapter IPv4 source script', () => {
    const native = toPhysicalIpv4Sources(adapters, configs)
    const legacy = ps(`$rows=@(); $adapters = Get-NetAdapter | Where-Object {
      $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Wintun|TAP-Windows|Tailscale|WireGuard|Hyper-V|Loopback|vEthernet|VPN|VirtualBox|VMware|Bluetooth' -and
      $_.MacAddress -and $_.MacAddress -ne '00-00-00-00-00-00' }
      foreach ($a in $adapters) { $cfg = Get-NetIPConfiguration -InterfaceIndex $a.ifIndex
        if ($cfg -and $cfg.IPv4Address) { foreach ($ip in $cfg.IPv4Address) { if ($ip.IPAddress -and $ip.IPAddress -notlike '169.254.*') {
          $rows += [pscustomobject]@{ Alias = $a.Name; Ipv4 = $ip.IPAddress } } } } }
      $rows | ConvertTo-Json -Compress`)
    const key = (r: any) => `${r.alias ?? r.Alias}|${r.ipv4 ?? r.Ipv4}`
    expect(native.map(key).sort()).toEqual(legacy.map(key).sort())
  })

  it('matches the legacy active-tunnel probe', () => {
    const opts = { vpnteAlias: 'VPNTE-TUN', vpnteIpv4Prefix: '198.18.' }
    const native = toActiveTunnels(adapters, configs, opts)
    const legacy = ps(`$rx='(?i)wintun|\\btun\\b|wireguard|openvpn|tap-windows|happ|hiddify|singbox|sing-tun|v2ray|xray|vpn';
      Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and ($_.Name -match $rx -or $_.InterfaceDescription -match $rx) } | ForEach-Object {
        $a=$_; $ips=Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 | Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress
        [pscustomobject]@{ Name=$a.Name; Description=$a.InterfaceDescription; Address=($ips -join ', ') } } | ConvertTo-Json -Compress`)
    const key = (name: string, addr: string) => `${name}|${split(addr).join(',')}`
    expect(native.map(r => key(r.name, r.address)).sort()).toEqual(legacy.map(r => key(r.Name, r.Address)).sort())
  })
})
