// AT-03-002/003/004/012: execute the real script with fake Windows boundaries.
// ACL, WFP and reboot evidence still require Windows L3; mocks are not acceptance.
import { execFileSync } from 'child_process'
import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
const pwsh = process.env.VPNTE_PWSH
const source = readFileSync(join(process.cwd(), 'resources/vpnte-recover.ps1'), 'utf8')
const fixtures = () => ({
  policy: { schemaVersion: 1, owner: 'VPNTE', strictMode: false },
  firewall: null as any, tun: null as any, untrusted: false, failProfile: '',
  adapters: [{ Name: 'Other VPN', InterfaceGuid: '11111111-1111-1111-1111-111111111111', InterfaceDescription: 'Wintun', ifIndex: 10, Status: 'Up' }],
  rules: false
})
function run(patch: Partial<ReturnType<typeof fixtures>> = {}) {
  const fixture = { ...fixtures(), ...patch }
  const encoded = Buffer.from(JSON.stringify(fixture)).toString('base64')
  const mocks = `
$env:ProgramData='/trusted'
$global:f = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')) | ConvertFrom-Json
$global:profiles = @{Domain='Block';Private='Block';Public='Block'}
$global:removed=$false
function Get-Item {
 param($LiteralPath,[switch]$Force,$ErrorAction)
 [pscustomobject]@{Attributes=[IO.FileAttributes]::Normal;PSIsContainer=($LiteralPath -notmatch '\\.json$');Length=100}
}
function Get-Acl {
 param($LiteralPath,$ErrorAction)
 $acl=[pscustomobject]@{AreAccessRulesProtected=(-not $global:f.untrusted)}
 $acl|Add-Member ScriptMethod GetOwner { param($type) [pscustomobject]@{Value='S-1-5-32-544'} }
 $acl|Add-Member ScriptMethod GetAccessRules { param($a,$b,$type) @([pscustomobject]@{AccessControlType='Allow';IdentityReference=[pscustomobject]@{Value='S-1-5-18'}}) }
 return $acl
}
function Test-Path {
 param($LiteralPath,$Path)
 $p=if($LiteralPath){$LiteralPath}else{$Path}
 switch -Regex ($p) {
  'recovery-policy.json$' { return $true }
  'firewall.json$' { return [bool]$global:f.firewall }
  'tun-owner.json$' { return [bool]$global:f.tun }
  'latest-.*json$' { return $false }
  default { return $true }
 }
}
function Get-Content {
 param($LiteralPath,[switch]$Raw,$Encoding)
 if($LiteralPath -match 'recovery-policy.json$'){return ($global:f.policy|ConvertTo-Json -Depth 10 -Compress)}
 if($LiteralPath -match 'firewall.json$'){return ($global:f.firewall|ConvertTo-Json -Depth 10 -Compress)}
 if($LiteralPath -match 'tun-owner.json$'){return ($global:f.tun|ConvertTo-Json -Depth 10 -Compress)}
 throw 'Unexpected manifest read'
}
function Set-NetFirewallProfile {
 param($Profile,$DefaultOutboundAction,$ErrorAction)
 foreach($p in @($Profile)){Write-Output "PROFILE:$p/$DefaultOutboundAction";if($p -eq $global:f.failProfile){throw 'injected failure'};$global:profiles[$p]=[string]$DefaultOutboundAction}
}
function Get-NetFirewallProfile {param($Profile,$ErrorAction) [pscustomobject]@{DefaultOutboundAction=$global:profiles[$Profile]}}
function Get-NetFirewallRule {param($DisplayName,$ErrorAction) if($global:f.rules -and -not $global:removed){[pscustomobject]@{DisplayName='VPNTE-killswitch-test'}}}
function Remove-NetFirewallRule {param([Parameter(ValueFromPipeline=$true)]$InputObject,$ErrorAction) process{$global:removed=$true;Write-Output 'REMOVE_RULE'}}
function Get-NetAdapter {param($ErrorAction) @($global:f.adapters)}
function Get-NetIPAddress {param($InterfaceIndex,$AddressFamily,$ErrorAction) [pscustomobject]@{IPAddress='192.168.250.253';PrefixLength=30}}
function Get-DnsClientServerAddress {param($InterfaceAlias,$AddressFamily,$ErrorAction) [pscustomobject]@{ServerAddresses=@('192.168.250.254')}}
function Clear-DnsClientCache {param($ErrorAction)}
function Remove-NetAdapter {param($Name,$Confirm,$ErrorAction) Write-Output "REMOVE_ADAPTER:$Name"}
function Disable-NetAdapter {param($Name,$Confirm,$ErrorAction) Write-Output "DISABLE_ADAPTER:$Name"}
function Remove-Item {param($LiteralPath,$Path,[switch]$Force,$ErrorAction) Write-Output "DELETE:$LiteralPath$Path"}
`
  // Replace only report I/O using an AST-delimited definition; keep all recovery control flow.
  const quotedSource = Buffer.from(source).toString('base64')
  const bootstrap = `${mocks}
$source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${quotedSource}'))
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Source syntax error'}
$fn=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Write-RecoveryReport'},$true)
$source=$source.Remove($fn.Extent.StartOffset,$fn.Extent.EndOffset-$fn.Extent.StartOffset).Insert($fn.Extent.StartOffset,'function Write-RecoveryReport([string]$status) { Write-Output ("REPORT:"+$status) }')
& ([scriptblock]::Create($source))
`
  try { return { status: 0, output: execFileSync(pwsh!, ['-NoProfile', '-NonInteractive', '-Command', bootstrap], { encoding: 'utf8', timeout: 15000 }) } }
  catch (error: any) { return { status: error.status, output: String(error.stdout) + String(error.stderr) } }
}
describe.skipIf(!pwsh)('actual boot recovery control flow on mocked system APIs', () => {
  it('does not alter a foreign Block profile without VPNTE ownership', () => {
    const result = run()
    expect(result.status).toBe(0)
    expect(result.output).not.toContain('PROFILE:')
    expect(result.output).not.toContain('REMOVE_ADAPTER:')
    expect(result.output).toContain('REPORT:restored')
  })
  it('rejects untrusted ACL before any network effect or report write', () => {
    const result = run({ untrusted: true })
    expect(result.status).toBe(1)
    expect(result.output).not.toContain('PROFILE:')
    expect(result.output).not.toContain('REPORT:')
  })
  it('strict recovery never sets Allow or cleans adapters/rules', () => {
    const result = run({ policy: { schemaVersion: 1, owner: 'VPNTE', strictMode: true }, rules: true })
    expect(result.status).toBe(0)
    expect(result.output).toContain('PROFILE:Public/Block')
    expect(result.output).not.toContain('/Allow')
    expect(result.output).not.toContain('REMOVE_RULE')
    expect(result.output).not.toContain('REMOVE_ADAPTER')
    expect(result.output).toContain('REPORT:strict-retained')
  })
  it('continues independent profile restoration and preserves the snapshot on failure', () => {
    const firewall = { schemaVersion: 1, owner: 'VPNTE', strictMode: false, phase: 'active', savedProfiles: ['Domain','Private','Public'].map(name => ({ name, defaultOutbound: 'Allow' })) }
    const result = run({ firewall, failProfile: 'Domain', rules: true })
    expect(result.status).toBe(1)
    expect(result.output).toContain('PROFILE:Private/Allow')
    expect(result.output).toContain('PROFILE:Public/Allow')
    expect(result.output).not.toContain('DELETE:/trusted/VPNTE/manifests/firewall.json')
    expect(result.output).toContain('REPORT:warnings')
  })
  it('only removes the exact GUID/driver/subnet-owned Wintun adapter', () => {
    const adapters = [...fixtures().adapters, { ...fixtures().adapters[0], Name: 'VPNTE', ifIndex: 11, InterfaceGuid: '22222222-2222-2222-2222-222222222222' }]
    const result = run({ adapters, tun: { schemaVersion: 1, owner: 'VPNTE', interfaceGuid: adapters[1].InterfaceGuid } })
    expect(result.output).toContain('REMOVE_ADAPTER:VPNTE')
    expect(result.output).not.toContain('REMOVE_ADAPTER:Other VPN')
  })
})
