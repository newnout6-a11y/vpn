// AT-03-001/003/004/009/010: effective policy evidence, fail-closed status.
import { assert, describe, expect, it } from 'vitest'
import { FIREWALL_STATUS_PS, parseFirewallStatusSnapshot } from './firewallStatus'
import { execFileSync } from 'child_process'
import { mkdirSync, mkdtempSync, writeFileSync, rmSync } from 'fs'
import { join } from 'path'

import { firewallStatusFixture as fixture } from './testFixtures/firewallStatus'
const prefix = 'VPNTE-killswitch-allow-'
function requireRule(snapshot: ReturnType<typeof fixture>['snapshot'], name: string) {
  const rule = snapshot.rules.find(r => r.name === prefix + name)
  assert(rule, `Missing firewall fixture rule: ${name}`)
  return rule
}
describe('effective firewall evidence', () => {
  it.skipIf(process.platform !== 'win32').each(['small', 'large', 'no-owned', 'stored-only', 'no-owned-active-error', 'no-owned-stored-error', 'missing-rule-id', 'missing-filter-id',
    'profile-disabled-interface', 'profile-not-configured', 'profile-null', 'profile-missing-field', 'profile-invalid-value',
    ...['Application', 'Address', 'Port', 'Interface'].flatMap(kind => [`missing-${kind}`, `duplicate-${kind}`, `query-error-${kind}`])])(
    'reads full policy only for owned active rules, preserving one-to-one evidence: %s (AT-03-001/003/004)', variant => {
    const { snapshot } = fixture()
    // The two rules share a display name, but have different native identities/scopes.
    snapshot.rules.push({ ...snapshot.rules[0], program: 'C:\\fixture\\second.exe' })
    if (variant === 'large') snapshot.rules.push(...Array.from({ length: 100 }, (_, i) => ({ ...snapshot.rules[0], name: `${prefix}extra-${i}` })))
    if (variant.startsWith('no-owned') || variant === 'stored-only') snapshot.rules = []
    if (variant === 'profile-disabled-interface') Object.assign(snapshot.profiles[0], { disabledInterfaces: ['Fixture Ethernet'] })
    if (variant === 'profile-not-configured') Object.assign(snapshot.profiles[0], { disabledInterfaces: ['NotConfigured'] })
    snapshot.storedNames = snapshot.rules.map(rule => rule.name)
    if (variant === 'stored-only') snapshot.storedNames = [prefix + 'orphan']
    const encoded = Buffer.from(JSON.stringify(snapshot)).toString('base64')
    const script = `
$fixture=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')) | ConvertFrom-Json
$global:filterCalls=@{}
function Get-Service { [CmdletBinding()]param($Name)
  if(-not $fixture.rules.Count){throw 'Unneeded service query'}
  $fixture.services | ForEach-Object { [pscustomobject]@{Name=$_.name;Status=$_.status} }
}
function Get-NetFirewallProfile { [CmdletBinding()]param($PolicyStore,$Profile)
  if(-not $fixture.rules.Count){throw 'Unneeded profile query'}
  if($PolicyStore -ne 'ActiveStore'){throw 'Must read effective profiles'}
  $fixture.profiles | ForEach-Object {
    $profile=[pscustomobject]@{Name=$_.name;Enabled=$_.enabled;DefaultOutboundAction=$_.outbound;DisabledInterfaceAliases=$(if('${variant}' -eq 'profile-null'){$null}else{$_.disabledInterfaces})}
    if('${variant}' -eq 'profile-missing-field'){$profile.PSObject.Properties.Remove('DisabledInterfaceAliases')}
    if('${variant}' -eq 'profile-invalid-value'){$profile.DisabledInterfaceAliases=17}
    $profile
  }
}
function Get-NetFirewallRule { [CmdletBinding()]param($PolicyStore)
  if($PolicyStore -notin @('ActiveStore','PersistentStore')){throw 'Missing policy store'}
  if(('${variant}' -eq 'no-owned-active-error' -and $PolicyStore -eq 'ActiveStore') -or ('${variant}' -eq 'no-owned-stored-error' -and $PolicyStore -eq 'PersistentStore')){throw 'Fixture rule query denied'}
  if($PolicyStore -eq 'PersistentStore'){
    $fixture.storedNames | ForEach-Object { [pscustomobject]@{DisplayName=$_} }
    return
  }
  for($i=0;$i -lt $fixture.rules.Count;$i++){ $r=$fixture.rules[$i]; [pscustomobject]@{Name=$(if($i -eq 0 -and '${variant}' -eq 'missing-rule-id'){''}else{'rule-'+$i});DisplayName=$r.name;Enabled=$r.enabled;Direction=$r.direction;Action=$r.action;Profile=$r.profile;Scope=$r} }
  if($PolicyStore -eq 'ActiveStore'){[pscustomobject]@{DisplayName='Foreign allow';Enabled='True';Direction='Outbound';Action='Allow'}}
}
function Read-FixtureFilter($kind,$All,$PolicyStore) {
  if(-not $fixture.rules.Count){throw 'Unneeded filter query'}
  if(-not $All -or $PolicyStore -ne 'ActiveStore'){throw 'Bulk ActiveStore read required'}
  if($global:filterCalls.ContainsKey($kind)){throw 'Repeated filter query'}
  $global:filterCalls[$kind]=1
  if('${variant}' -eq ('query-error-'+$kind)){throw 'Fixture filter query denied'}
  # Filter enumeration order must not determine its association with a rule.
  for($i=$fixture.rules.Count-1;$i -ge 0;$i--){
    if($i -eq 0 -and '${variant}' -eq ('missing-'+$kind)){continue}
    $r=$fixture.rules[$i]
    $filter=switch($kind){
      'Application' {[pscustomobject]@{InstanceID=('rule-'+$i);Program=$r.program}}
      'Address' {[pscustomobject]@{InstanceID=('rule-'+$i);RemoteAddress=$r.remote;LocalAddress=$r.local}}
      'Port' {[pscustomobject]@{InstanceID=('rule-'+$i);Protocol=$r.protocol;RemotePort=$r.remotePorts}}
      'Interface' {[pscustomobject]@{InstanceID=('rule-'+$i);InterfaceAlias=$r.interfaces}}
    }
    if($i -eq 0 -and '${variant}' -eq 'missing-filter-id'){$filter.InstanceID=''}
    $filter
    if($i -eq 0 -and '${variant}' -eq ('duplicate-'+$kind)){$filter}
  }
}
function Get-NetFirewallApplicationFilter { [CmdletBinding()]param([switch]$All,$PolicyStore) Read-FixtureFilter 'Application' $All $PolicyStore }
function Get-NetFirewallAddressFilter { [CmdletBinding()]param([switch]$All,$PolicyStore) Read-FixtureFilter 'Address' $All $PolicyStore }
function Get-NetFirewallPortFilter { [CmdletBinding()]param([switch]$All,$PolicyStore) Read-FixtureFilter 'Port' $All $PolicyStore }
function Get-NetFirewallInterfaceFilter { [CmdletBinding()]param([switch]$All,$PolicyStore) Read-FixtureFilter 'Interface' $All $PolicyStore }
$actual=&{${FIREWALL_STATUS_PS}}
[pscustomobject]@{snapshot=$actual;calls=$global:filterCalls}|ConvertTo-Json -Compress`
    mkdirSync(join(process.cwd(), '.tmp'), { recursive: true })
    const directory = mkdtempSync(join(process.cwd(), '.tmp', 'vpnte-status-'))
    try {
      const file = join(directory, 'fixture.ps1'); writeFileSync(file, '\ufeff' + script)
      const run = () => execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', file], { encoding: 'utf8', windowsHide: true, timeout: 15000, stdio: ['pipe', 'pipe', 'pipe'] })
      if (['small', 'large', 'no-owned', 'stored-only', 'profile-disabled-interface', 'profile-not-configured', 'profile-null'].includes(variant)) {
        const actual = JSON.parse(run())
        expect(parseFirewallStatusSnapshot(actual.snapshot)).toEqual({ ...snapshot, foreignAllows: 1,
          ...(!snapshot.rules.length ? { services: [], profiles: [] } : {}) })
        expect(actual.calls).toEqual(snapshot.rules.length ? { Application: 1, Address: 1, Port: 1, Interface: 1 } : {})
      } else if (variant === 'profile-invalid-value') expect(() => parseFirewallStatusSnapshot(JSON.parse(run()).snapshot)).toThrow('Incomplete firewall status snapshot')
      else expect(run).toThrow(variant.endsWith('-error') ? 'Fixture rule query denied' : variant.startsWith('query-error-') ? 'Fixture filter query denied' :
        variant === 'profile-missing-field' ? 'Incomplete firewall profile read-back' : 'Incomplete firewall filter read-back')
    } finally { rmSync(directory, { recursive: true, force: true }) }
  })
  it('accepts a complete scoped snapshot and both loopback families', () => {
    const { snapshot, matches } = fixture()
    expect(parseFirewallStatusSnapshot(JSON.stringify(snapshot))).toEqual(snapshot)
    expect(matches()).toBe(true)
    snapshot.rules.push({ ...snapshot.rules[3], remote: ['::1/128'] })
    expect(matches()).toBe(true)
  })
  it.each(['Domain', 'Private', 'Public'])('refuses disabled physical interfaces in the %s profile (AT-03-001)', name => {
    const { snapshot, matches } = fixture()
    const profile = snapshot.profiles.find(p => p.name === name)
    assert(profile, `Missing firewall fixture profile: ${name}`)
    profile.disabledInterfaces = ['Fixture Ethernet']
    expect(matches()).toBe(false)
  })
  it('accepts explicit NotConfigured without excluded interfaces (AT-03-001)', () => {
    const { snapshot, matches } = fixture()
    for (const profile of snapshot.profiles) Object.assign(profile, { disabledInterfaces: ['NotConfigured'] })
    expect(matches()).toBe(true)
  })
  it.each([undefined, null, 'NotConfigured', [null], [17], [''], ['NotConfigured', 'Fixture Ethernet']])(
    'never verifies an incomplete or excluded interface scope: %j (AT-03-001)', disabledInterfaces => {
      const { snapshot, matches } = fixture()
      Object.assign(snapshot.profiles[0], { disabledInterfaces })
      if (Array.isArray(disabledInterfaces) && disabledInterfaces.every(x => typeof x === 'string')) {
        expect(parseFirewallStatusSnapshot(JSON.stringify(snapshot))).toEqual(snapshot)
      } else expect(() => parseFirewallStatusSnapshot(JSON.stringify(snapshot))).toThrow()
      expect(matches()).toBe(false)
    })
  it('recognizes the dotted IPv4 subnet masks returned by real ActiveStore (AT-03-001/009)', () => {
    const { snapshot, matches } = fixture()
    requireRule(snapshot, 'loopback-out').remote = ['127.0.0.0/255.0.0.0']
    requireRule(snapshot, 'loopback-in').local = ['127.0.0.0/255.0.0.0']
    requireRule(snapshot, 'lan').remote = ['127.0.0.0/255.0.0.0', '10.0.0.0/255.0.0.0']
    requireRule(snapshot, 'tun').remote = ['192.168.250.252/255.255.255.252']
    expect(matches()).toBe(true)
  })
  it('does not accept invalid or broader dotted masks (AT-03-009)', () => {
    for (const mask of ['255.0.255.0', '0.0.0.0', '255.255.255.0']) {
      const { snapshot, matches } = fixture()
      requireRule(snapshot, 'tun').remote = ['192.168.250.252/' + mask]
      expect(matches()).toBe(false)
    }
  })
  it.each(['service', 'profile', 'disabled-profile', 'foreign-allow', 'missing-rule', 'extra-rule', 'persistent-only', 'unknown-helper'])(
    'refuses %s instead of treating presence as blocking', kind => {
      const { snapshot, manifest, matches } = fixture()
      if (kind === 'service') snapshot.services[0].status = 'Stopped'
      if (kind === 'profile') snapshot.profiles[0].outbound = 'Allow'
      if (kind === 'disabled-profile') snapshot.profiles[0].enabled = 'False'
      if (kind === 'foreign-allow') snapshot.foreignAllows = 1
      if (kind === 'missing-rule') snapshot.rules.pop()
      if (kind === 'extra-rule') snapshot.rules.push({ ...snapshot.rules[0], name: prefix + 'unknown' })
      if (kind === 'persistent-only') snapshot.storedNames.push(prefix + 'orphan')
      if (kind === 'unknown-helper') { snapshot.rules[0].name = prefix + 'xray-engine'; snapshot.storedNames[0] = snapshot.rules[0].name; manifest.ruleNames[0] = snapshot.rules[0].name }
      expect(matches()).toBe(false)
    })
  it.each([
    ['singbox', 'program'], ['app', 'program'], ['tun-interface', 'interfaces'],
    ['loopback-out', 'remote'], ['loopback-in', 'local'], ['lan', 'remote'], ['tun', 'remote'],
    ['dhcp', 'protocol'], ['dhcp', 'remotePorts'], ['ntp', 'protocol'], ['ntp', 'remotePorts']
  ] as const)(
    'refuses broadened %s %s independently despite the correct display name', (name, field) => {
      const { snapshot, matches } = fixture()
      const rule = requireRule(snapshot, name)
      if (field === 'program' || field === 'protocol') rule[field] = 'Any'
      else rule[field] = ['Any']
      expect(matches()).toBe(false)
    })
  it.each(['enabled', 'action', 'direction', 'profile'] as const)('refuses incorrect %s and duplicate names', field => {
    const { snapshot, matches } = fixture()
    snapshot.rules[0][field] = 'Wrong'
    expect(matches()).toBe(false)
  })
  it('rejects duplicate profile/rule snapshots and duplicate loopback scopes', () => {
    const a = fixture(); a.snapshot.profiles[0] = a.snapshot.profiles[1]; expect(a.matches()).toBe(false)
    const b = fixture(); b.snapshot.rules.push({ ...b.snapshot.rules[0] }); expect(b.matches()).toBe(false)
    const c = fixture(); c.snapshot.rules.push({ ...c.snapshot.rules[3] }); expect(c.matches()).toBe(false)
  })
  it.each([null, {}, { profiles: [], rules: [], storedNames: [], foreignAllows: 0 }, { ...fixture().snapshot, foreignAllows: -1 },
    { ...fixture().snapshot, rules: [{ name: 'only-a-name' }] }, { ...fixture().snapshot, profiles: [null] }])('rejects incomplete/untyped read-back %#', value => {
    expect(() => parseFirewallStatusSnapshot(JSON.stringify(value))).toThrow()
  })
})
