import { app } from 'electron'
import { readFile } from 'fs/promises'
import { join } from 'path'
import { createHash, randomUUID } from 'crypto'
import { Address6 } from 'ip-address'
import { isIP } from 'net'
import { readRecoveryManifest } from './recoveryManifest'

export const WFP_SOURCE_SHA256 = '99382d8ef48069fa80ca8cb5811e7dec708e4440f98a04e74eed2a742d69997e'
export interface Ipv6Rule {
  id: string
  role: 'block' | 'lan' | 'tun' | 'vpn' | 'exception-app' | 'exception-ip'
  appId: string
  remote: string
  luid: string
  originalApp: boolean
  inbound: boolean
  boot: boolean
}
export interface WfpIpv6Policy { schemaVersion: 1; rules: Ipv6Rule[] }
type Run = (script: string) => Promise<{ stdout: string }>
const quote = (value: string) => `'${value.replace(/'/g, "''")}'`
const guid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i
const localCidrs = ['::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8']
export function validateWfpIpv6Policy(value: unknown): WfpIpv6Policy {
  const v = value as WfpIpv6Policy
  if (!v || v.schemaVersion !== 1 || !Array.isArray(v.rules) || v.rules.length < 2 || v.rules.length > 2048 ||
      new Set(v.rules.map(r => r?.id)).size !== v.rules.length) throw new Error('Invalid IPv6 policy set')
  for (const r of v.rules) {
    if (!r || !guid.test(r.id) || !/^(?:[a-f0-9]{2}){0,16384}$/i.test(r.appId) ||
        !(r.luid === '' || (/^[1-9][0-9]{0,19}$/.test(r.luid) && BigInt(r.luid) <= 0xffffffffffffffffn)) ||
        typeof r.inbound !== 'boolean' || typeof r.boot !== 'boolean' || typeof r.originalApp !== 'boolean' || typeof r.remote !== 'string') throw new Error('Invalid IPv6 scope')
    if (r.boot && (r.inbound || !['block','lan'].includes(r.role))) throw new Error('Invalid IPv6 boot scope')
    if (r.remote && (!r.remote.includes('/') || r.remote.includes('%') || !Address6.isValid(r.remote))) throw new Error('Invalid IPv6 remote scope')
    switch (r.role) {
      case 'block': if (r.appId || r.remote || r.luid || r.originalApp) throw new Error('Invalid IPv6 block'); break
      case 'lan': if (r.appId || r.luid || r.originalApp || !localCidrs.includes(r.remote)) throw new Error('Invalid IPv6 LAN scope'); break
      case 'tun': if (r.appId || r.remote || !r.luid || r.originalApp) throw new Error('Invalid IPv6 TUN scope'); break
      case 'vpn': if (!r.appId || !r.remote.endsWith('/128') || !r.luid || r.originalApp) throw new Error('VPN permit requires app, exact address and interface'); break
      case 'exception-app': if (!r.appId || r.remote || r.luid || r.originalApp) throw new Error('Invalid IPv6 app exception'); break
      case 'exception-ip': if (r.appId || !r.remote || r.luid || r.originalApp) throw new Error('Invalid IPv6 IP exception'); break
      default: throw new Error('Invalid IPv6 rule role')
    }
  }
  if ([false, true].some(inbound => v.rules.filter(r => r.role === 'block' && r.inbound === inbound && !r.boot).length !== 1) || v.rules.filter(r => r.role === 'block' && r.boot).length !== 1) throw new Error('IPv6 block must cover both flow directions and boot')
  return v
}
export async function wfpPrelude(): Promise<string> {
  const path = app.isPackaged ? join(process.resourcesPath, 'vpnte-wfp-ipv6.cs') : join(process.cwd(), 'resources', 'vpnte-wfp-ipv6.cs')
  const source = (await readFile(path, 'utf8')).replace(/\r\n/g, '\n')
  if (source.length > 131072 || createHash('sha256').update(source, 'utf8').digest('hex') !== WFP_SOURCE_SHA256) throw new Error('WFP helper source integrity mismatch')
  return `$ErrorActionPreference='Stop'\nif (-not ('VPNTE.IPv6.Policy' -as [type])) { Add-Type -TypeDefinition ${quote(source)} -ErrorAction Stop }\n`
}
function ruleScopes(role: Ipv6Rule['role'], scope: Partial<Ipv6Rule> = {}): Ipv6Rule[] {
  const layers = role === 'block' || role === 'lan' ? ['connect','accept','boot'] : ['connect','accept']
  return layers.map(layer => ({ id: randomUUID(), role, appId: '', remote: '', luid: '', originalApp: false, inbound: layer === 'accept', boot: layer === 'boot', ...scope }))
}
function parseMarker(stdout: string, marker: string): unknown {
  const lines = String(stdout).split(/\r?\n/).filter(line => line.startsWith(marker))
  if (lines.length !== 1) throw new Error('WFP native read-back marker missing or ambiguous')
  return JSON.parse(lines[0].slice(marker.length))
}
// RFC 6052/7050: infer only prefixes proven by both ipv4only.arpa addresses.
// A whole NAT64 prefix is never installed as a transport exception.
export function synthesizeNat64Endpoint(ipv4: string, discovery: string[]): string[] {
  if (isIP(ipv4) !== 4) throw new Error('Invalid NAT64 IPv4 endpoint')
  const bytes = (address: string) => new Address6(address).bigInt().toString(16).padStart(32, '0').match(/../g)!.map(b => parseInt(b, 16))
  const discovered = discovery.filter(ip => isIP(ip) === 6 && !ip.includes('%')).map(bytes)
  const key = (value: number[]) => Buffer.from(value).toString('hex')
  const synthesize = (prefix: number[], length: number, address: number[]) => {
    const result = Array(16).fill(0) as number[]
    prefix.slice(0, length / 8).forEach((b, i) => { result[i] = b })
    let index = length / 8
    for (const b of address) { if (index === 8) index++; result[index++] = b }
    return result
  }
  const answers = new Set(discovered.map(key)), endpoints = new Set<string>()
  for (const length of [32, 40, 48, 56, 64, 96]) for (const prefix of discovered) {
    if (answers.has(key(synthesize(prefix, length, [192, 0, 0, 170]))) && answers.has(key(synthesize(prefix, length, [192, 0, 0, 171])))) {
      endpoints.add(Address6.fromBigInt(BigInt('0x' + key(synthesize(prefix, length, ipv4.split('.').map(Number))))).correctForm())
    }
  }
  return [...endpoints]
}
async function resolveTransportIpv6(host: string, run: Run): Promise<string[]> {
  if (isIP(host) === 6 && !host.includes('%')) return [new Address6(host).correctForm()]
  const ipv4 = isIP(host) === 4
  const { stdout } = await run(`$ErrorActionPreference='Stop'
$answers=@(Resolve-DnsName -Name ${quote(ipv4 ? 'ipv4only.arpa' : host)} -Type AAAA -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.Type -eq 'AAAA' } | Select-Object -ExpandProperty IPAddress)
Write-Output ('WFP_DNS:'+ (ConvertTo-Json -InputObject @($answers) -Compress))`)
  const answers = parseMarker(stdout, 'WFP_DNS:')
  if (!Array.isArray(answers) || answers.length > 64 || answers.some(ip => typeof ip !== 'string' || isIP(ip) !== 6 || ip.includes('%'))) throw new Error('Unverified IPv6 DNS response')
  return ipv4 ? synthesizeNat64Endpoint(host, answers) : [...new Set(answers)]
}
export async function prepareWfpIpv6Policy(opts: { corePrograms: string[]; serverHost?: string; tunAlias: string; apps: string[]; cidrs: string[] }, run: Run): Promise<WfpIpv6Policy> {
  const owner = await readRecoveryManifest('tun-owner.json', (v: any) => {
    if (!v || v.schemaVersion !== 1 || v.owner !== 'VPNTE' || typeof v.interfaceGuid !== 'string' || !guid.test(v.interfaceGuid.replace(/[{}]/g, ''))) throw new Error('Invalid owned TUN identity')
    return v as { interfaceGuid: string }
  })
  if (!owner) throw new Error('Owned TUN identity is required for IPv6 policy')
  const addresses = opts.serverHost ? await resolveTransportIpv6(opts.serverHost, run) : []
  const { stdout } = await run(`${await wfpPrelude()}
$owned=@(Get-NetAdapter -ErrorAction Stop | Where-Object { [string]$_.InterfaceGuid -eq ${quote(owner.interfaceGuid)} })
if ($owned.Count -ne 1 -or $owned[0].Status -ne 'Up' -or $owned[0].Name -ne ${quote(opts.tunAlias)} -or $owned[0].DriverDescription -notmatch '^Wintun\\b' -or $owned[0].PnPDeviceID -notlike 'SWD\\Wintun\\*') { throw 'Owned TUN not verified for WFP' }
if (-not @(Get-NetIPAddress -InterfaceIndex $owned[0].ifIndex -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -eq '192.168.250.253' -and $_.PrefixLength -eq 30 }).Count) { throw 'Owned TUN subnet mismatch' }
$tunLuid=[VPNTE.IPv6.NativeEngine]::InterfaceLuid([string]$owned[0].InterfaceGuid)
$appIds=@(${opts.apps.map(path => `[VPNTE.IPv6.NativeEngine]::AppId(${quote(path)})`).join(';')})
$vpn=@()
${opts.serverHost || opts.corePrograms.length > 1 ? `
$addresses=@(${addresses.map(quote).join(',')})
${!opts.serverHost ? `$proxyPrograms=@(${opts.corePrograms.slice(1).map(quote).join(',')})
$proxyPids=@(Get-Process -ErrorAction Stop | Where-Object { $_.Path -and $_.Path -in $proxyPrograms } | Select-Object -ExpandProperty Id)
foreach($pidValue in $proxyPids){ $addresses+=@(Get-NetTCPConnection -OwningProcess $pidValue -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Established' -and $_.RemoteAddress -match ':' } | Select-Object -ExpandProperty RemoteAddress) }` : ''}
foreach($ip in @($addresses | Select-Object -Unique)) {
  $routes=@(Find-NetRoute -RemoteIPAddress $ip -ErrorAction Stop | Where-Object { $_.InterfaceIndex } | Select-Object -ExpandProperty InterfaceIndex -Unique)
  if($routes.Count -ne 1){throw 'VPN IPv6 route is ambiguous'}
  $physical=@(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.ifIndex -eq $routes[0] -and $_.Status -eq 'Up' -and $_.MacAddress -and $_.InterfaceDescription -notmatch 'Wintun|TAP-Windows|Tailscale|WireGuard|Hyper-V|Loopback|vEthernet|VPN|VirtualBox|VMware' })
  if($physical.Count -ne 1){throw 'VPN IPv6 physical interface not verified'}
  $luid=[VPNTE.IPv6.NativeEngine]::InterfaceLuid([string]$physical[0].InterfaceGuid)
  foreach($program in @(${opts.corePrograms.map(quote).join(',')})) { $vpn += [pscustomobject]@{appId=[VPNTE.IPv6.NativeEngine]::AppId($program);remote=([string]$ip+'/128');luid=$luid} }
}` : ''}
Write-Output ('WFP_PREPARED:'+([pscustomobject]@{tunLuid=$tunLuid;appIds=@($appIds);vpn=@($vpn)} | ConvertTo-Json -Depth 5 -Compress))`)
  const native = parseMarker(stdout, 'WFP_PREPARED:') as { tunLuid: string; appIds: string[]; vpn: Array<{ appId: string; remote: string; luid: string }> }
  if (!native || !Array.isArray(native.appIds) || native.appIds.length !== opts.apps.length || !Array.isArray(native.vpn)) throw new Error('Incomplete IPv6 preparation')
  if (opts.serverHost && (native.vpn.length !== addresses.length * opts.corePrograms.length ||
      addresses.some(address => native.vpn.filter(scope => scope.remote === `${new Address6(address).correctForm()}/128`).length !== opts.corePrograms.length))) throw new Error('Incomplete IPv6 transport scopes')
  const rules = [...ruleScopes('block'), ...localCidrs.flatMap(remote => ruleScopes('lan', { remote })), ...ruleScopes('tun', { luid: native.tunLuid }),
    ...native.vpn.flatMap(scope => ruleScopes('vpn', scope)),
    ...native.appIds.flatMap(appId => ruleScopes('exception-app', { appId })),
    ...opts.cidrs.filter(c => c.includes(':')).flatMap(remote => ruleScopes('exception-ip', { remote: new Address6(remote.includes('/') ? remote : `${remote}/128`).correctForm() + '/' + new Address6(remote).subnetMask }))]
  return validateWfpIpv6Policy({ schemaVersion: 1, rules })
}
function policyScript(policy: WfpIpv6Policy): string {
  validateWfpIpv6Policy(policy)
  return `$rules=[VPNTE.IPv6.Rule[]]@(${quote(JSON.stringify(policy.rules))} | ConvertFrom-Json | ForEach-Object {
  $r=New-Object VPNTE.IPv6.Rule; $r.Id=[Guid]$_.id; $r.Role=$_.role; $r.AppId=$_.appId; $r.Remote=$_.remote; $r.Luid=$_.luid; $r.OriginalApp=$_.originalApp; $r.Inbound=$_.inbound; $r.Boot=$_.boot; $r
})\n`
}
export async function applyWfpIpv6Policy(policy: WfpIpv6Policy, run: Run): Promise<void> {
  const { stdout } = await run(`${await wfpPrelude()}${policyScript(policy)}
$engine=New-Object VPNTE.IPv6.NativeEngine
try { [VPNTE.IPv6.Policy]::Apply($engine,$rules); Write-Output 'WFP_IPV6_VERIFIED' } finally { $engine.Dispose() }`)
  if (!String(stdout).split(/\r?\n/).includes('WFP_IPV6_VERIFIED')) throw new Error('IPv6 WFP apply not verified')
}
export async function prepareWfpIpv6Exceptions(previous: WfpIpv6Policy, apps: string[], cidrs: string[], run: Run): Promise<WfpIpv6Policy> {
  validateWfpIpv6Policy(previous)
  const { stdout } = await run(`${await wfpPrelude()}
$appIds=@(${apps.map(path => `[VPNTE.IPv6.NativeEngine]::AppId(${quote(path)})`).join(';')})
Write-Output ('WFP_APPS:'+ (ConvertTo-Json -InputObject @($appIds) -Compress))`)
  const appIds = parseMarker(stdout, 'WFP_APPS:')
  if (!Array.isArray(appIds) || appIds.length !== apps.length) throw new Error('IPv6 app exceptions not verified')
  return validateWfpIpv6Policy({ schemaVersion: 1, rules: [
    ...previous.rules.filter(r => !r.role.startsWith('exception-')),
    ...appIds.flatMap(appId => ruleScopes('exception-app', { appId })),
    ...cidrs.filter(c => c.includes(':')).flatMap(remote => ruleScopes('exception-ip', { remote: new Address6(remote).correctForm() + '/' + new Address6(remote).subnetMask }))
  ] })
}
export function sameWfpCoreScopes(a: WfpIpv6Policy, b: WfpIpv6Policy): boolean {
  const scopes = (policy: WfpIpv6Policy) => policy.rules.filter(r => !r.role.startsWith('exception-')).map(({ id: _id, ...r }) => JSON.stringify(r)).sort()
  return JSON.stringify(scopes(a)) === JSON.stringify(scopes(b))
}
export async function hasWfpIpv6Protection(run: Run): Promise<boolean> {
  const { stdout } = await run(`${await wfpPrelude()}
$engine=New-Object VPNTE.IPv6.NativeEngine
try { Write-Output ('WFP_COUNT:'+ $engine.ReadOwned().Length) } finally { $engine.Dispose() }`)
  const count = parseMarker(stdout, 'WFP_COUNT:')
  if (!Number.isSafeInteger(count) || (count as number) < 0) throw new Error('IPv6 WFP state unknown')
  return (count as number) > 0
}
export async function verifyWfpIpv6Policy(policy: WfpIpv6Policy, run: Run): Promise<void> {
  const { stdout } = await run(`${await wfpPrelude()}${policyScript(policy)}
$engine=New-Object VPNTE.IPv6.NativeEngine
try { [VPNTE.IPv6.Policy]::Validate($rules); [VPNTE.IPv6.Policy]::AssertSame($engine.ReadOwned(),$rules); Write-Output 'WFP_IPV6_VERIFIED' } finally { $engine.Dispose() }`)
  if (!String(stdout).split(/\r?\n/).includes('WFP_IPV6_VERIFIED')) throw new Error('IPv6 WFP coverage not verified')
}
export async function removeWfpIpv6Protection(run: Run): Promise<void> {
  const { stdout } = await run(`${await wfpPrelude()}
$engine=New-Object VPNTE.IPv6.NativeEngine
try { [VPNTE.IPv6.Policy]::Remove($engine); Write-Output 'WFP_IPV6_REMOVED' } finally { $engine.Dispose() }`)
  if (!String(stdout).split(/\r?\n/).includes('WFP_IPV6_REMOVED')) throw new Error('IPv6 WFP cleanup not verified')
}
