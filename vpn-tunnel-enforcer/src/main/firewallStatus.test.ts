// AT-03-001/003/004/009/010: effective policy evidence, fail-closed status.
import { describe, expect, it } from 'vitest'
import { FIREWALL_STATUS_PS, parseFirewallStatusSnapshot } from './firewallStatus'
import { execFileSync } from 'child_process'
import { mkdtempSync, writeFileSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'

import { firewallStatusFixture as fixture } from './testFixtures/firewallStatus'
const prefix = 'VPNTE-killswitch-allow-'
describe('effective firewall evidence', () => {
  it.skipIf(process.platform !== 'win32')('executes the production read-only snapshot against native cmdlet fixtures (AT-03-001/004)', () => {
    const { snapshot } = fixture()
    const encoded = Buffer.from(JSON.stringify(snapshot)).toString('base64')
    const script = `
$fixture=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')) | ConvertFrom-Json
function Get-Service { [CmdletBinding()]param($Name) $fixture.services | ForEach-Object { [pscustomobject]@{Name=$_.name;Status=$_.status} } }
function Get-NetFirewallProfile { [CmdletBinding()]param($PolicyStore,$Profile)
  if($PolicyStore -ne 'ActiveStore'){throw 'Must read effective profiles'}
  $fixture.profiles | ForEach-Object { [pscustomobject]@{Name=$_.name;Enabled=$_.enabled;DefaultOutboundAction=$_.outbound} }
}
function Get-NetFirewallRule { [CmdletBinding()]param($PolicyStore)
  if($PolicyStore -notin @('ActiveStore','PersistentStore')){throw 'Missing policy store'}
  foreach($r in $fixture.rules){ [pscustomobject]@{DisplayName=$r.name;Enabled=$r.enabled;Direction=$r.direction;Action=$r.action;Profile=$r.profile;Scope=$r} }
  if($PolicyStore -eq 'ActiveStore'){[pscustomobject]@{DisplayName='Foreign allow';Enabled='True';Direction='Outbound';Action='Allow'}}
}
function Get-NetFirewallApplicationFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$Rule) process { [pscustomobject]@{Program=$Rule.Scope.program} } }
function Get-NetFirewallAddressFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$Rule) process { [pscustomobject]@{RemoteAddress=$Rule.Scope.remote;LocalAddress=$Rule.Scope.local} } }
function Get-NetFirewallPortFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$Rule) process { [pscustomobject]@{Protocol=$Rule.Scope.protocol;RemotePort=$Rule.Scope.remotePorts} } }
function Get-NetFirewallInterfaceFilter { [CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$Rule) process { [pscustomobject]@{InterfaceAlias=$Rule.Scope.interfaces} } }
${FIREWALL_STATUS_PS}`
    const directory = mkdtempSync(join(tmpdir(), 'vpnte-status-'))
    try {
      const file = join(directory, 'fixture.ps1'); writeFileSync(file, '\ufeff' + script)
      const actual = parseFirewallStatusSnapshot(execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-File', file], { encoding: 'utf8', windowsHide: true, timeout: 15000 }))
      expect(actual).toEqual({ ...snapshot, foreignAllows: 1 })
    } finally { rmSync(directory, { recursive: true, force: true }) }
  })
  it('accepts a complete scoped snapshot and both loopback families', () => {
    const { snapshot, matches } = fixture()
    expect(parseFirewallStatusSnapshot(JSON.stringify(snapshot))).toEqual(snapshot)
    expect(matches()).toBe(true)
    snapshot.rules.push({ ...snapshot.rules[3], remote: ['::1/128'] })
    expect(matches()).toBe(true)
  })
  it('recognizes the dotted IPv4 subnet masks returned by real ActiveStore (AT-03-001/009)', () => {
    const { snapshot, matches } = fixture()
    snapshot.rules.find(r => r.name === prefix + 'loopback-out')!.remote = ['127.0.0.0/255.0.0.0']
    snapshot.rules.find(r => r.name === prefix + 'loopback-in')!.local = ['127.0.0.0/255.0.0.0']
    snapshot.rules.find(r => r.name === prefix + 'lan')!.remote = ['127.0.0.0/255.0.0.0', '10.0.0.0/255.0.0.0']
    snapshot.rules.find(r => r.name === prefix + 'tun')!.remote = ['192.168.250.252/255.255.255.252']
    expect(matches()).toBe(true)
  })
  it('does not accept invalid or broader dotted masks (AT-03-009)', () => {
    for (const mask of ['255.0.255.0', '0.0.0.0', '255.255.255.0']) {
      const { snapshot, matches } = fixture()
      snapshot.rules.find(r => r.name === prefix + 'tun')!.remote = ['192.168.250.252/' + mask]
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
  it.each(['singbox', 'app', 'tun-interface', 'loopback-out', 'loopback-in', 'lan', 'tun', 'dhcp', 'ntp'])(
    'refuses broadened %s scope despite the correct display name', name => {
      const { snapshot, matches } = fixture()
      const rule = snapshot.rules.find(r => r.name === prefix + name)!
      rule.program = 'Any'; rule.interfaces = ['Any']; rule.remote = ['Any']; rule.local = ['Any']; rule.protocol = 'Any'; rule.remotePorts = ['Any']
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
