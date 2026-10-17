import type { FirewallManifest } from './firewallKillSwitch'
import { createHash } from 'crypto'
import { isIP } from 'net'
import { Address4, Address6 } from 'ip-address'

const prefix = 'VPNTE-killswitch-'
const coreNames = ['singbox', 'app', 'tun-interface', 'loopback-out', 'loopback-in', 'lan', 'tun', 'dhcp', 'ntp'].map(n => prefix + 'allow-' + n)

/** Query effective policy, not merely the local PersistentStore. No writes/UAC. */
export const FIREWALL_STATUS_PS = `
$ErrorActionPreference='Stop'
$services=@(Get-Service -Name BFE,MpsSvc -ErrorAction Stop | ForEach-Object { [pscustomobject]@{name=[string]$_.Name;status=[string]$_.Status} })
$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -Profile Domain,Private,Public -ErrorAction Stop | ForEach-Object {
  $field=$_.PSObject.Properties['DisabledInterfaceAliases']
  if($null -eq $field){throw 'Incomplete firewall profile read-back'}
  # Native CIM null explicitly means no excluded interfaces; a missing field is unknown.
  $disabled=@()
  if($null -ne $field.Value){$disabled=@($field.Value)}
  [pscustomobject]@{name=[string]$_.Name;enabled=[string]$_.Enabled;outbound=[string]$_.DefaultOutboundAction;disabledInterfaces=$disabled}
})
$active=@(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop)
$stored=@(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.DisplayName -like 'VPNTE-killswitch*' } | ForEach-Object { [string]$_.DisplayName })
$foreign=@($active | Where-Object { $_.DisplayName -notlike 'VPNTE-killswitch*' -and [string]$_.Enabled -eq 'True' -and [string]$_.Direction -eq 'Outbound' -and [string]$_.Action -eq 'Allow' }).Count
function Get-VpnteStatusFilterIndex($filters) {
  $index=@{}
  foreach($filter in $filters){
    $key=[string]$filter.InstanceID
    if(-not $key){throw 'Incomplete firewall filter read-back'}
    if($index.ContainsKey($key)){$index[$key]=@($index[$key])+@($filter)}
    else{$index[$key]=@($filter)}
  }
  return $index
}
# One CIM read per type; never reuse indices across status requests.
$appIndex=Get-VpnteStatusFilterIndex @(Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore -ErrorAction Stop)
$addressIndex=Get-VpnteStatusFilterIndex @(Get-NetFirewallAddressFilter -All -PolicyStore ActiveStore -ErrorAction Stop)
$portIndex=Get-VpnteStatusFilterIndex @(Get-NetFirewallPortFilter -All -PolicyStore ActiveStore -ErrorAction Stop)
$interfaceIndex=Get-VpnteStatusFilterIndex @(Get-NetFirewallInterfaceFilter -All -PolicyStore ActiveStore -ErrorAction Stop)
$owned=@($active | Where-Object { $_.DisplayName -like 'VPNTE-killswitch*' } | ForEach-Object {
  $rule=$_
  $key=[string]$rule.Name
  if(-not $key -or -not $appIndex.ContainsKey($key) -or -not $addressIndex.ContainsKey($key) -or -not $portIndex.ContainsKey($key) -or -not $interfaceIndex.ContainsKey($key)){throw 'Incomplete firewall filter read-back'}
  $app=@($appIndex[$key])
  $address=@($addressIndex[$key])
  $port=@($portIndex[$key])
  $interface=@($interfaceIndex[$key])
  if($app.Count -ne 1 -or $address.Count -ne 1 -or $port.Count -ne 1 -or $interface.Count -ne 1){throw 'Incomplete firewall filter read-back'}
  [pscustomobject]@{name=[string]$rule.DisplayName;enabled=[string]$rule.Enabled;direction=[string]$rule.Direction;action=[string]$rule.Action;profile=[string]$rule.Profile;
    program=[string]$app[0].Program;remote=@($address[0].RemoteAddress);local=@($address[0].LocalAddress);
    interfaces=@($interface[0].InterfaceAlias);protocol=[string]$port[0].Protocol;remotePorts=@($port[0].RemotePort)}
})
[pscustomobject]@{services=$services;profiles=$profiles;storedNames=$stored;foreignAllows=$foreign;rules=$owned} | ConvertTo-Json -Depth 6 -Compress
`

export interface FirewallStatusSnapshot {
  services: Array<{ name: string; status: string }>
  profiles: Array<{ name: string; enabled: string; outbound: string; disabledInterfaces: string[] }>
  storedNames: string[]
  foreignAllows: number
  rules: Array<{ name: string; enabled: string; direction: string; action: string; profile: string;
    program: string; remote: string[]; local: string[]; interfaces: string[]; protocol: string; remotePorts: string[] }>
}

export function parseFirewallStatusSnapshot(stdout: string): FirewallStatusSnapshot {
  const v = JSON.parse(stdout) as FirewallStatusSnapshot
  const strings = (x: unknown): x is string[] => Array.isArray(x) && x.every(s => typeof s === 'string')
  if (!v || !Array.isArray(v.services) || !Array.isArray(v.profiles) || !Array.isArray(v.rules) || !strings(v.storedNames) ||
      !Number.isSafeInteger(v.foreignAllows) || v.foreignAllows < 0 ||
      v.services.some(s => !s || typeof s.name !== 'string' || typeof s.status !== 'string') ||
      v.profiles.some(p => !p || ['name', 'enabled', 'outbound'].some(k => typeof p[k as keyof typeof p] !== 'string') || !strings(p.disabledInterfaces)) ||
      v.rules.some(r => !r || ['name', 'enabled', 'direction', 'action', 'profile', 'program', 'protocol'].some(k => typeof r[k as keyof typeof r] !== 'string') ||
        ![r.remote, r.local, r.interfaces, r.remotePorts].every(strings))) throw new Error('Incomplete firewall status snapshot')
  return v
}

function addressScope(value: string): string | null {
  try {
    const [host, mask, ...rest] = value.split('/')
    if (rest.length) return null
    if (isIP(host) === 4) {
      let prefix = mask ?? '32'
      // NetSecurity emits dotted subnet masks in the effective store.
      if (isIP(prefix) === 4) {
        const bits = prefix.split('.').map(n => Number(n).toString(2).padStart(8, '0')).join('')
        if (!/^1*0*$/.test(bits)) return null
        prefix = String(bits.replace(/0/g, '').length)
      }
      if (!/^\d+$/.test(prefix)) return null
      const address = new Address4(host + '/' + prefix)
      return address.startAddress().correctForm() + '/' + address.subnetMask
    }
    if (isIP(host) === 6 && (mask === undefined || /^\d+$/.test(mask))) {
      const address = new Address6(value)
      return address.startAddress().correctForm() + '/' + address.subnetMask
    }
  } catch { /* Invalid scopes cannot establish coverage. */ }
  return null
}
function sameAddresses(actual: string[], expected: readonly string[]): boolean {
  const a = actual.map(addressScope), b = expected.map(addressScope)
  return a.length === b.length && !a.includes(null) && !b.includes(null) &&
    new Set(a).size === a.length && a.every(value => b.includes(value))
}

/** Conservative proof: unexpected permits (including foreign rules) remain unknown. */
export function matchesFirewallPolicy(snapshot: FirewallStatusSnapshot, manifest: FirewallManifest,
  programs: { app: string; proxy: string }, tunAlias: string, lan: readonly string[], tunCidr: string): boolean {
  const same = (a: string[], b: readonly string[]) => a.length === b.length && a.every(x => b.includes(x)) && new Set(a).size === a.length
  const pathEquals = (a: string, b: string | null) => !!b && a.toLowerCase() === b.toLowerCase()
  if (snapshot.foreignAllows !== 0 || !same(snapshot.services.map(s => s.name.toLowerCase()), ['bfe', 'mpssvc']) ||
      snapshot.services.some(s => s.status !== 'Running') || snapshot.profiles.length !== 3 ||
      !same(snapshot.profiles.map(p => p.name), ['Domain', 'Private', 'Public']) ||
      snapshot.profiles.some(p => p.enabled !== 'True' || p.outbound !== 'Block' || !Array.isArray(p.disabledInterfaces) ||
        !(p.disabledInterfaces.length === 0 || same(p.disabledInterfaces, ['NotConfigured']))) ||
      coreNames.some(n => !manifest.ruleNames.includes(n)) ||
      !same([...new Set(snapshot.storedNames)], manifest.ruleNames) ||
      !same([...new Set(snapshot.rules.map(r => r.name))], manifest.ruleNames)) return false
  const exceptions = manifest.exceptionPolicy ?? { apps: [], cidrs: [] }
  const exceptionNames = new Map([
    ...exceptions.apps.map(value => ['app:' + value.toLowerCase(), { program: value }] as const),
    ...exceptions.cidrs.map(value => ['ip:' + value, { remote: value }] as const)
  ].map(([key, scope]) => [prefix + 'user-' + createHash('sha256').update(key).digest('hex').slice(0, 24), scope]))
  if ([...exceptionNames.keys()].some(n => !manifest.ruleNames.includes(n))) return false
  return snapshot.rules.every(r => {
    if (r.enabled !== 'True' || r.action !== 'Allow' || r.profile !== 'Any' ||
        r.direction !== (r.name === prefix + 'allow-loopback-in' ? 'Inbound' : 'Outbound')) return false
    // Duplicate names are expected only for the two loopback address families.
    const peers = snapshot.rules.filter(p => p.name === r.name)
    if (peers.length !== 1 && (!r.name.startsWith(prefix + 'allow-loopback-') || peers.length !== 2 ||
        JSON.stringify(peers[0].remote) === JSON.stringify(peers[1].remote) && JSON.stringify(peers[0].local) === JSON.stringify(peers[1].local))) return false
    switch (r.name.slice(prefix.length)) {
      case 'allow-singbox': return pathEquals(r.program, manifest.singboxExePath)
      case 'allow-app': return pathEquals(r.program, programs.app)
      case 'allow-tun-interface': return same(r.interfaces, [tunAlias])
      case 'allow-loopback-out': return ['127.0.0.0/8', '::1/128'].some(scope => sameAddresses(r.remote, [scope]))
      case 'allow-loopback-in': return ['127.0.0.0/8', '::1/128'].some(scope => sameAddresses(r.local, [scope]))
      case 'allow-lan': return sameAddresses(r.remote, lan)
      case 'allow-tun': return sameAddresses(r.remote, [tunCidr])
      case 'allow-dhcp': return ['UDP', '17'].includes(r.protocol) && same(r.remotePorts, ['67', '68'])
      case 'allow-ntp': return ['UDP', '17'].includes(r.protocol) && same(r.remotePorts, ['123'])
      default:
        // Older journals do not record arbitrary proxy/helper program paths.
        // Never infer their approved scope from a display name alone.
        if (/^allow-proxy-\d+$/.test(r.name.slice(prefix.length))) return pathEquals(r.program, programs.proxy)
        const exception = exceptionNames.get(r.name)
        if (exception) return 'program' in exception ? pathEquals(r.program, exception.program) : sameAddresses(r.remote, [exception.remote])
        return false
    }
  })
}
