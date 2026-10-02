// AT-03-004/007/008/009, AT-00-005: execute production API primitives with fake COM.
import { execFileSync } from 'node:child_process'
import { describe, expect, it, vi } from 'vitest'
import { FIREWALL_RULES_API_PS, withFirewallRulesApi } from './firewallRulesApi'
vi.mock('./admin', () => ({ isProcessElevated: async () => false }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

const fakeCom = `
Add-Type -TypeDefinition @'
using System;using System.Collections;using System.Collections.Generic;
public class FakeRule {
 public string Name,Description,ApplicationName,RemoteAddresses="*",LocalAddresses="*";
 public object[] Interfaces;
 public int Direction,Action,Profiles,Protocol=256;public bool Enabled,EdgeTraversal;
 public string RemotePorts {get{return ports;}set{if(Protocol!=6&&Protocol!=17)throw new Exception("Protocol order");ports=value;}}private string ports;
}
public class FakeRules:IEnumerable {
 public List<FakeRule> Values=new List<FakeRule>();public bool FailRead,FailRemove,LeaveBehind,FailAdd;
 public IEnumerator GetEnumerator(){if(FailRead)throw new Exception("query failed");return Values.ToArray().GetEnumerator();}
 public void Add(FakeRule rule){if(FailAdd)throw new Exception("add failed");Values.Add(rule);}
 public void Remove(string name){if(FailRemove)throw new Exception("remove failed");if(LeaveBehind)return;int at=Values.FindIndex(r=>r.Name==name);if(at>=0)Values.RemoveAt(at);}
}
public class FakePolicy { public FakeRules Rules=new FakeRules(); }
'@
$fixturePolicy=[FakePolicy]::new();$factoryCalls=0;$failFactory=$false
function New-Object { param($ComObject)
 $script:factoryCalls++
 if($script:failFactory){throw 'factory failed'}
 if($ComObject -eq 'HNetCfg.FwPolicy2'){return $fixturePolicy}
 if($ComObject -eq 'HNetCfg.FwRule'){return [FakeRule]::new()}
 throw 'unexpected factory'
}
function Add-FixtureRule([string]$name){$r=[FakeRule]::new();$r.Name=$name;$fixturePolicy.Rules.Add($r)}
`
function run(script: string): any {
  const native = `$ErrorActionPreference='Stop';${fakeCom}\n${FIREWALL_RULES_API_PS}\n${script}`
  const output = execFileSync(process.env.VPNTE_PWSH || 'powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(native, 'utf16le').toString('base64')],
    { windowsHide: true, encoding: 'utf8', timeout: 15000, stdio: 'pipe' })
  return JSON.parse(output.trim())
}
describe('firewall API assembly', () => {
  it('adds the native primitives only to commands using them', () => {
    expect(withFirewallRulesApi('Get-NetFirewallProfile')).toBe('Get-NetFirewallProfile')
    expect(withFirewallRulesApi('Get-VpnteFirewallRuleNames -DisplayName x')).toBe(FIREWALL_RULES_API_PS + 'Get-VpnteFirewallRuleNames -DisplayName x')
    expect(FIREWALL_RULES_API_PS).not.toMatch(/Set-NetFirewallProfile|DefaultOutboundAction|Start-Process|Invoke-Expression/)
  })
  it('admits the complete backend to the firewall policy but rejects adapter policy', async () => {
    const { execElevatedPs } = await import('./elevatedPsHelper')
    await expect(execElevatedPs(FIREWALL_RULES_API_PS, 1000, 'firewall-killswitch')).rejects.toMatchObject({ code: 'elevated-helper-unavailable' })
    await expect(execElevatedPs(FIREWALL_RULES_API_PS + '\nGet-NetAdapter', 1000, 'physical-adapter-lockdown')).rejects.toMatchObject({ code: 'elevated-helper-script-rejected' })
  })
})
describe.skipIf(process.platform !== 'win32' && !process.env.VPNTE_PWSH)('native rule primitives', () => {
  it.skipIf(process.platform !== 'win32')('assigns the interface property on a real unregistered COM rule without changing firewall', () => {
    // Add is an in-memory boundary; OS property validation needs no elevation.
    const native = `$ErrorActionPreference='Stop'
$alias=[string](Get-NetAdapter -ErrorAction Stop|Select-Object -First 1).Name
if(-not $alias){throw 'No interface available for native property validation'}
$fixtureRules=[pscustomobject]@{Created=$null}
$fixtureRules|Add-Member -MemberType ScriptMethod -Name Add -Value {param($r)$this.Created=$r}
$fixturePolicy=[pscustomobject]@{Rules=$fixtureRules}
function New-Object {param($ComObject)
 if($ComObject -eq 'HNetCfg.FwPolicy2'){return $fixturePolicy}
 Microsoft.PowerShell.Utility\\New-Object -ComObject $ComObject
}
${FIREWALL_RULES_API_PS}
New-VpnteFirewallRule -DisplayName 'VPNTE-killswitch-user-test' -Direction Outbound -Action Allow -Profile Any -Enabled False -InterfaceAlias $alias
@{accepted=(@($fixtureRules.Created.Interfaces) -contains $alias);profiles=$fixtureRules.Created.Profiles;enabled=$fixtureRules.Created.Enabled}|ConvertTo-Json -Compress`
    const output = execFileSync(process.env.VPNTE_PWSH || 'powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(native, 'utf16le').toString('base64')], { windowsHide: true, encoding: 'utf8', timeout: 15000, stdio: 'pipe' })
    expect(JSON.parse(output.trim())).toEqual({ accepted: true, profiles: 2147483647, enabled: false })
  })
  it('preserves only matching owned names, duplicate names and fresh enumerations', () => {
    expect(run(`
Add-FixtureRule 'foreign-rule';Add-FixtureRule 'VPNTE-killswitch-user-old';Add-FixtureRule 'VPNTE-killswitch-user-old';Add-FixtureRule 'VPNTE-killswitch-allow-app'
$first=@(Get-VpnteFirewallRuleNames -DisplayName 'VPNTE-killswitch-user-*')
Remove-VpnteFirewallRules -DisplayName 'VPNTE-killswitch-user-*'
Add-FixtureRule 'VPNTE-killswitch-user-new'
$next=@(Get-VpnteFirewallRuleNames -DisplayName 'VPNTE-killswitch-user-*')
@{first=$first;next=$next;foreign=@($fixturePolicy.Rules.Values.Name -eq 'foreign-rule').Count;remaining=@($fixturePolicy.Rules.Values.Name|Sort-Object);factories=$factoryCalls}|ConvertTo-Json -Compress
`)).toEqual({ first: ['VPNTE-killswitch-user-old', 'VPNTE-killswitch-user-old'], next: ['VPNTE-killswitch-user-new'], foreign: 1,
      remaining: ['foreign-rule', 'VPNTE-killswitch-allow-app', 'VPNTE-killswitch-user-new'], factories: 1 })
  })
  it.each(['factory', 'query', 'remove', 'leftover'])('fails closed for %s even with SilentlyContinue', mode => {
    const setup = { factory: '$failFactory=$true', query: '$fixturePolicy.Rules.FailRead=$true', remove: '$fixturePolicy.Rules.FailRemove=$true', leftover: '$fixturePolicy.Rules.LeaveBehind=$true' }[mode]
    expect(run(`Add-FixtureRule 'VPNTE-killswitch-user-old';${setup};$success=$false;try{Remove-VpnteFirewallRules -DisplayName 'VPNTE-killswitch-user-*' -ErrorAction SilentlyContinue;$success=$true}catch{};@{success=$success;remaining=$fixturePolicy.Rules.Values.Count}|ConvertTo-Json -Compress`)).toEqual({ success: false, remaining: 1 })
  })
  it('does not acquire COM until rule work, preserving independent profile rollback', () => {
    expect(run(`$failFactory=$true;$restored=@();foreach($profile in @('Domain','Private','Public')){$restored+=$profile};$failed=$false;try{Remove-VpnteFirewallRules -DisplayName 'VPNTE-killswitch*'}catch{$failed=$true};@{restored=$restored;failed=$failed}|ConvertTo-Json -Compress`)).toEqual({ restored: ['Domain', 'Private', 'Public'], failed: true })
  })
  it.each(['policy', 'rules'])('rejects a missing %s rather than proving an empty rule set', missing => {
    const setup = missing === 'policy' ? "$fixturePolicy=$null" : "$fixturePolicy.Rules=$null"
    expect(run(`${setup};$ok=$false;try{Get-VpnteFirewallRuleNames -DisplayName 'VPNTE-killswitch*' -ErrorAction SilentlyContinue;$ok=$true}catch{};@{success=$ok}|ConvertTo-Json -Compress`)).toEqual({ success: false })
  })
  it('rejects foreign queries before acquiring policy', () => {
    expect(run(`$ok=$false;try{Get-VpnteFirewallRuleNames -DisplayName 'foreign-*';$ok=$true}catch{};@{success=$ok;factories=$factoryCalls}|ConvertTo-Json -Compress`)).toEqual({ success: false, factories: 0 })
  })
  it('keeps legacy prefix names visible to recovery rather than proving their absence', () => {
    expect(run(`Add-FixtureRule 'VPNTE-killswitch-legacy (old)';Add-FixtureRule 'foreign-rule';$before=@(Get-VpnteFirewallRuleNames -DisplayName 'VPNTE-killswitch*');Remove-VpnteFirewallRules -DisplayName 'VPNTE-killswitch*';@{before=$before;remaining=@($fixturePolicy.Rules.Values.Name)}|ConvertTo-Json -Compress`)).toEqual({ before: ['VPNTE-killswitch-legacy (old)'], remaining: ['foreign-rule'] })
  })
  it.each(['foreign', 'action', 'profile', 'direction', 'enabled', 'protocol', 'port-without-protocol'])('rejects invalid %s rule before mutation', mode => {
    const values = { foreign: "-DisplayName 'foreign-rule'", action: '-Action Block', profile: '-Profile Public', direction: '-Direction Sideways', enabled: '-Enabled Unknown', protocol: '-Protocol ICMP', 'port-without-protocol': '-RemotePort 443' }
    const base: Record<string,string> = { DisplayName: "'VPNTE-killswitch-user-test'", Action: 'Allow', Profile: 'Any', Direction: 'Outbound', Enabled: 'True' }
    const change = values[mode as keyof typeof values]
    const property = /^-(\S+)/.exec(change)![1]
    delete base[property]
    expect(run(`$ok=$false;try{New-VpnteFirewallRule ${Object.entries(base).map(([k,v])=>`-${k} ${v}`).join(' ')} ${change};$ok=$true}catch{};@{success=$ok;count=$fixturePolicy.Rules.Values.Count}|ConvertTo-Json -Compress`)).toEqual({ success: false, count: 0 })
  })
  it('preserves program, interface, IPv4/IPv6 addresses, UDP ports, all profiles and edge policy', () => {
    expect(run(`
New-VpnteFirewallRule -DisplayName 'VPNTE-killswitch-user-test' -Description 'fixture' -Direction Inbound -Action Allow -Profile Any -Enabled True -Program 'C:\fixture.exe' -RemoteAddress '127.0.0.0/8','::1/128' -LocalAddress '::1/128' -InterfaceAlias 'Ethernet 5' -Protocol UDP -RemotePort 67,68
$r=$fixturePolicy.Rules.Values[0];@{name=$r.Name;description=$r.Description;direction=$r.Direction;action=$r.Action;profiles=$r.Profiles;enabled=$r.Enabled;edge=$r.EdgeTraversal;program=$r.ApplicationName;remote=$r.RemoteAddresses;local=$r.LocalAddresses;interfaces=$r.Interfaces;protocol=$r.Protocol;ports=$r.RemotePorts}|ConvertTo-Json -Compress
`)).toEqual({ name:'VPNTE-killswitch-user-test',description:'fixture',direction:1,action:1,profiles:2147483647,enabled:true,edge:false,
      program:'C:\fixture.exe',remote:'127.0.0.0/8,::1/128',local:'::1/128',interfaces:['Ethernet 5'],protocol:17,ports:'67,68' })
  })
  it('propagates a failed native Add without presenting a created rule', () => {
    expect(run(`$fixturePolicy.Rules.FailAdd=$true;$ok=$false;try{New-VpnteFirewallRule -DisplayName 'VPNTE-killswitch-user-test' -Direction Outbound -Action Allow -Profile Any -Enabled True;$ok=$true}catch{};@{success=$ok;count=$fixturePolicy.Rules.Values.Count}|ConvertTo-Json -Compress`)).toEqual({ success:false,count:0 })
  })
})
