// AT-03-002/003/004/012: execute the real script with fake Windows boundaries.
// ACL, WFP and reboot evidence still require Windows L3; mocks are not acceptance.
import { execFileSync } from 'child_process'
import { readFileSync, mkdirSync, mkdtempSync, writeFileSync, unlinkSync, rmdirSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
const pwsh = process.env.VPNTE_PWSH || (process.platform === 'win32' ? 'powershell.exe' : undefined)
const source = readFileSync(join(process.cwd(), 'resources/vpnte-recover.ps1'), 'utf8')
const fixtures = () => ({
  policy: { schemaVersion: 1, owner: 'VPNTE', strictMode: false },
  firewall: null as any, tun: null as any, untrusted: false, failProfile: '',
  adapters: [{ Name: 'Other VPN', InterfaceGuid: '11111111-1111-1111-1111-111111111111', InterfaceDescription: 'sing-tun Tunnel', DriverDescription: 'Wintun Userspace Tunnel', PnPDeviceID: 'SWD\\Wintun\\fixture', ifIndex: 10, Status: 'Up' }],
  rules: false, extra: {} as Record<string, unknown>, corrupt: '', untrustedFile: '', wfpRules: false, wfpFailure: false
})
function run(patch: Partial<ReturnType<typeof fixtures>> = {}) {
  const fixture = { ...fixtures(), ...patch }
  const encoded = Buffer.from(JSON.stringify(fixture)).toString('base64')
  const mocks = `
$env:ProgramData=if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)}else{'/trusted'}
$global:f = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')) | ConvertFrom-Json
$global:profiles = @{Domain='Block';Private='Block';Public='Block'}
$global:removed=$false
$global:quarantined=@{}
$global:restoredDns=@{}
$global:registryValues=@{}
function Get-FixtureUserHive {
 $key=[pscustomobject]@{}
 $key | Add-Member ScriptMethod CreateSubKey {param($path) Get-FixtureUserHive}
 $key | Add-Member ScriptMethod SetValue {param($name,$data,$kind) $global:registryValues[$name]=@{data=$data;kind=$kind};Write-Host "REGISTRY_SET:$name"}
 $key | Add-Member ScriptMethod DeleteValue {param($name,$strict) $global:registryValues.Remove($name);Write-Host "REGISTRY_DELETE:$name"}
 $key | Add-Member ScriptMethod GetValueNames { @($global:registryValues.Keys) }
 $key | Add-Member ScriptMethod GetValueKind {param($name) $global:registryValues[$name].kind}
 $key | Add-Member ScriptMethod GetValue {param($name,$fallback,$options) return ,$global:registryValues[$name].data}
 $key | Add-Member ScriptMethod Close {}
 return $key
}
function Get-Item {
 param($LiteralPath,[switch]$Force,$ErrorAction)
 [pscustomobject]@{Attributes=[IO.FileAttributes]::Normal;PSIsContainer=($LiteralPath -notmatch '\\.json(?:\\.corrupt-.*)?$');Length=100}
}
function Get-Acl {
 param($LiteralPath,$ErrorAction)
 $acl=[pscustomobject]@{AreAccessRulesProtected=(-not $global:f.untrusted -and -not ($global:f.untrustedFile -and $LiteralPath.EndsWith($global:f.untrustedFile)))}
 $acl|Add-Member ScriptMethod GetOwner { param($type) [pscustomobject]@{Value='S-1-5-32-544'} }
 $acl|Add-Member ScriptMethod GetAccessRules { param($a,$b,$type) @([pscustomobject]@{AccessControlType='Allow';IdentityReference=[pscustomobject]@{Value='S-1-5-18'}}) }
 return $acl
}
function Test-Path {
 param($LiteralPath,$Path)
 $p=if($LiteralPath){$LiteralPath}else{$Path}
 $name=Split-Path $p -Leaf
 if($global:quarantined.ContainsKey($name)){return $false}
 if($name -eq $global:f.corrupt -or $global:f.extra.PSObject.Properties.Name -contains $name){return $true}
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
 $name=Split-Path $LiteralPath -Leaf
 if($name -eq $global:f.corrupt){return '{'}
 if($global:f.extra.PSObject.Properties.Name -contains $name){return ($global:f.extra.$name|ConvertTo-Json -Depth 10 -Compress)}
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
function Remove-NetFirewallRule {[CmdletBinding()]param([Parameter(ValueFromPipeline=$true)]$InputObject) process{$global:removed=$true;Write-Output 'REMOVE_RULE'}}
function Get-NetAdapter {param($ErrorAction) @($global:f.adapters)}
function Get-NetIPAddress {param($InterfaceIndex,$AddressFamily,$ErrorAction) [pscustomobject]@{IPAddress='192.168.250.253';PrefixLength=30}}
function Get-DnsClientServerAddress {param($InterfaceAlias,$AddressFamily,$ErrorAction) [pscustomobject]@{ServerAddresses=$(if($global:restoredDns.ContainsKey($InterfaceAlias)){$global:restoredDns[$InterfaceAlias]}else{@('192.168.250.254')})}}
function Set-DnsClientServerAddress {param($InterfaceAlias,$ServerAddresses,[switch]$ResetServerAddresses,$ErrorAction) $global:restoredDns[$InterfaceAlias]=@($ServerAddresses);Write-Output "RESTORE_DNS:$InterfaceAlias"}
function Enable-NetAdapterBinding {param($InterfaceAlias,$ComponentID,$ErrorAction) Write-Output "RESTORE_BINDING:$InterfaceAlias"}
function Get-NetAdapterBinding {param($InterfaceAlias,$ComponentID,$ErrorAction) [pscustomobject]@{Enabled=$true}}
function Get-ItemProperty {param($LiteralPath,$Name,$ErrorAction) throw 'Unexpected registry read in boot fixture'}
function netsh { Write-Host ('NETSH:'+($args -join ' ')); $global:LASTEXITCODE=0 }
function Clear-DnsClientCache {param($ErrorAction)}
function Remove-NetAdapter {param($Name,$Confirm,$ErrorAction) Write-Output "REMOVE_ADAPTER:$Name"}
function Disable-NetAdapter {param($Name,$Confirm,$ErrorAction) Write-Output "DISABLE_ADAPTER:$Name"}
function Remove-Item {param($LiteralPath,$Path,[switch]$Force,$ErrorAction) Write-Output "DELETE:$LiteralPath$Path"}
function Move-Item {param($LiteralPath,$Destination,$ErrorAction) $global:quarantined[(Split-Path $LiteralPath -Leaf)]=$true;Write-Host "QUARANTINE:$LiteralPath"}
`
  // Replace only report I/O using an AST-delimited definition; keep all recovery control flow.
  const quotedSource = Buffer.from(source).toString('base64')
  const bootstrap = `${mocks}
$source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${quotedSource}'))
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Source syntax error'}
$fn=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Write-RecoveryReport'},$true)
$source=$source.Remove($fn.Extent.StartOffset,$fn.Extent.EndOffset-$fn.Extent.StartOffset).Insert($fn.Extent.StartOffset,'function Write-RecoveryReport([string]$status) { Write-Output ("REPORT:"+$status); $script:recoveryMessages | ForEach-Object { Write-Output $_.message }; foreach($name in @("Domain","Private","Public")){Write-Output ("PROFILE_STATE:"+$name+"/"+(Get-NetFirewallProfile -Profile $name -ErrorAction Stop).DefaultOutboundAction)} }')
$ast=[System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
$fn=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-VpnteWfpIpv6Recovery'},$true)
$source=$source.Remove($fn.Extent.StartOffset,$fn.Extent.EndOffset-$fn.Extent.StartOffset).Insert($fn.Extent.StartOffset,'function Invoke-VpnteWfpIpv6Recovery { if($global:f.wfpFailure){throw "injected WFP failure"}; if($global:f.wfpRules){Write-Output "WFP_CLEANUP"} }')
# Substitute only registry handles; production validation and restore/read-back remain intact.
$source=$source.Replace('[Microsoft.Win32.Registry]::Users.OpenSubKey($sid,$true)','(Get-FixtureUserHive)').Replace('[Microsoft.Win32.Registry]::LocalMachine','(Get-FixtureUserHive)')
& ([scriptblock]::Create($source))
`
  // Windows cannot pass this full-script harness within its command-line limit.
  const tempRoot = join(process.cwd(), '.tmp')
  mkdirSync(tempRoot, { recursive: true })
  const tempDir = mkdtempSync(join(tempRoot, 'boot-recovery-native-'))
  const harnessPath = join(tempDir, 'harness.ps1')
  try {
    writeFileSync(harnessPath, bootstrap, 'utf8')
    return { status: 0, output: execFileSync(pwsh!, ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', harnessPath], { encoding: 'utf8', timeout: 15000, windowsHide: true, stdio: ['ignore','pipe','pipe'] }) }
  } catch (error: any) { return { status: error.status, output: String(error.stdout) + String(error.stderr) } }
  finally { unlinkSync(harnessPath); rmdirSync(tempDir) }
}
// Each fixture can spend up to 15s inside the synchronous PowerShell boundary.
// Keep the runner budget outside that native deadline, including process cleanup.
describe.skipIf(!pwsh)('actual boot recovery control flow on mocked system APIs', { timeout: 20_000 }, () => {
  it.each(['empty', 'complete'] as const)('handles a trusted %s physical adapter snapshot without losing recovery evidence (AT-03-003c/007)', kind => {
    const physical = { Name: 'Fixture Ethernet', InterfaceGuid: '33333333-3333-3333-3333-333333333333', ifIndex: 12,
      InterfaceDescription: 'Physical fixture', DriverDescription: 'Physical fixture driver', PnPDeviceID: 'PCI\\fixture', MacAddress: '02-00-00-00-00-01', Status: 'Up' }
    const snapshot = { ifIndex: 12, interfaceGuid: physical.InterfaceGuid, alias: physical.Name, ipv6Enabled: true, forcedIpv6Off: true,
      ipv4DnsServers: ['192.0.2.53'], ipv4DnsSource: 'static', forcedDnsTo: ['192.168.250.254'] }
    const result = run({ adapters: [physical], extra: { 'latest-physical-adapter-lockdown.json': {
      schemaVersion: 1, owner: 'VPNTE', appliedAt: 1, tunDnsIpv4: '192.168.250.254',
      adapters: kind === 'empty' ? [] : [snapshot],
      transitionAdapters: { teredoType: 'client', sixToFourState: 'enabled', isatapState: 'disabled' },
      dnsRegistryPolicy: { smartNameResolution: { exists: false }, parallelAandAAAA: { exists: true, type: 'REG_DWORD', data: '0x0' } }
    } } })
    expect(result.output).toContain('NETSH:interface teredo set state type=client')
    expect(result.output).toContain('NETSH:interface 6to4 set state state=enabled')
    expect(result.output).toContain('NETSH:interface isatap set state state=disabled')
    expect(result.output).toContain('Registry: restored and verified DisableSmartNameResolution')
    expect(result.output).toContain('Registry: restored and verified DisableParallelAandAAAA')
    expect(result.output).not.toContain('QUARANTINE:')
    if (kind === 'empty') {
      expect(result.status).toBe(1)
      expect(result.output).toContain('Physical adapter snapshot missing; skipped')
      expect(result.output).toContain('REPORT:warnings')
      expect(result.output).not.toContain('REPORT:restored')
      expect(result.output).not.toMatch(/RESTORE_DNS:|RESTORE_BINDING:|DELETE:.*latest-physical-adapter-lockdown\.json/)
    } else {
      expect(result.status).toBe(0)
      expect(result.output).toContain('REPORT:restored')
      expect(result.output).toContain('RESTORE_DNS:Fixture Ethernet')
      expect(result.output).toContain('RESTORE_BINDING:Fixture Ethernet')
      expect(result.output).toMatch(/DELETE:.*latest-physical-adapter-lockdown\.json/)
    }
  }, 20_000)
  it.each(['missing', 'invalid'] as const)('reports a %s transition field while restoring valid neighbors (AT-03-003c)', kind => {
    const transitionAdapters: any = { teredoType: 'client', sixToFourState: 'enabled', isatapState: null }
    if (kind === 'missing') delete transitionAdapters.teredoType
    else transitionAdapters.teredoType = 'invalid'
    const result = run({ extra: { 'latest-physical-adapter-lockdown.json': {
      schemaVersion: 1, owner: 'VPNTE', adapters: [], transitionAdapters,
      dnsRegistryPolicy: { smartNameResolution: { exists: false }, parallelAandAAAA: { exists: false } }
    } } })
    expect(result.status).toBe(1)
    expect(result.output).toContain('Transition teredo snapshot rejected; skipped')
    expect(result.output).toContain('REPORT:warnings')
    expect(result.output).not.toMatch(/DELETE:.*latest-physical-adapter-lockdown\.json/)
    expect(result.output).not.toContain('NETSH:interface teredo set state')
    expect(result.output).toContain('NETSH:interface 6to4 set state state=enabled')
  })
  it.each(['duplicate', 'dns-null'] as const)('rejects ambiguous or invalid adapter records: %s (AT-03-003c/012)', kind => {
    const physical = { Name: 'Fixture Ethernet', InterfaceGuid: '33333333-3333-3333-3333-333333333333', ifIndex: 12,
      InterfaceDescription: 'Physical fixture', DriverDescription: 'Physical fixture driver', PnPDeviceID: 'PCI\\fixture', MacAddress: '02-00-00-00-00-01', Status: 'Up' }
    const snapshot = { ifIndex: 12, interfaceGuid: physical.InterfaceGuid, alias: physical.Name, ipv6Enabled: true, forcedIpv6Off: true,
      ipv4DnsServers: ['192.0.2.53'], ipv4DnsSource: 'static', forcedDnsTo: ['192.168.250.254'] }
    const result = run({ adapters: [physical], extra: { 'latest-physical-adapter-lockdown.json': {
      schemaVersion: 1, owner: 'VPNTE', adapters: kind === 'duplicate' ? [snapshot, { ...snapshot, interfaceGuid: `{${snapshot.interfaceGuid}}` }] : [{ ...snapshot, ipv4DnsServers: [null] }]
    } } })
    expect(result.status).toBe(1)
    expect(result.output).toContain('Adapter entry rejected: 0; skipped')
    expect(result.output).not.toMatch(/RESTORE_DNS:|RESTORE_BINDING:|DELETE:.*latest-physical-adapter-lockdown\.json/)
  })
  it.each(['invalid', 'duplicate', 'empty'] as const)('restores only valid baseline entries after %s records (AT-03-003c)', kind => {
    const values: any[] = [
      ...['ProxyEnable','ProxyServer','AutoConfigURL','AutoDetect'].map(name => ({ target: 'internet', name, exists: false, kind: null, data: null })),
      ...['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY'].map(name => ({ target: 'environment', name, exists: false, kind: null, data: null })),
      { target: 'winhttp', name: 'WinHttpSettings', exists: false, kind: null, data: null }
    ]
    if (kind === 'invalid') for (let i = 0; i < 4; i++) values[i].exists = 'false'
    if (kind === 'duplicate') values[0] = { ...values[1] }
    const result = run({ extra: { 'latest-tun-network-baseline.json': {
      schemaVersion: 1, owner: 'VPNTE', userSid: 'S-1-5-21-1-2-3-1001', values: kind === 'empty' ? [] : values
    } } })
    expect(result.status).toBe(1)
    expect(result.output).toContain('REPORT:warnings')
    expect(result.output).not.toMatch(/DELETE:.*latest-tun-network-baseline\.json/)
    const expected = kind === 'empty' ? [] : values.slice(kind === 'invalid' ? 4 : 2)
    const restored = [...result.output.matchAll(/^Baseline restored: (.+)$/gm)].map(match => match[1].trim())
    expect(restored).toEqual(expected.map(value => `${value.target}/${value.name}`))
    if (kind === 'empty') expect(result.output).not.toMatch(/REGISTRY_(SET|DELETE):/)
    else expect(result.output).toContain('Baseline entry rejected: 0; skipped')
  })
  it('retains strict protection despite invalid saved profile entries (AT-03-003c)', () => {
    const result = run({ firewall: { schemaVersion: 1, owner: 'VPNTE', strictMode: true, phase: 'active', savedProfiles: [
      { name: 'Domain', defaultOutbound: 'Block' }, { name: 'Private', defaultOutbound: 'invalid' }
    ] }, rules: true })
    expect(result.output).toContain('REPORT:strict-retained')
    expect(result.output).not.toMatch(/REMOVE_RULE|RESTORE_DNS:|REGISTRY_(SET|DELETE):|PROFILE:.*\/Allow/)
    expect(result.output).not.toMatch(/QUARANTINE:|DELETE:.*firewall\.json/)
  })
  it.each(['firewall', 'adapter', 'baseline', 'tun'] as const)('keeps independent valid recovery after a partial %s manifest (AT-03-003/007)', kind => {
    const profiles = ['Domain','Private','Public'].map(name => ({ name, defaultOutbound: 'Block' }))
    const firewall = { schemaVersion: 1, owner: 'VPNTE', strictMode: false, phase: 'active', savedProfiles: profiles }
    const tun = { schemaVersion: 1, owner: 'VPNTE', interfaceGuid: fixtures().adapters[0].InterfaceGuid }
    const physical = { Name: 'Fixture Ethernet', InterfaceGuid: '33333333-3333-3333-3333-333333333333', ifIndex: 12,
      InterfaceDescription: 'Physical fixture', DriverDescription: 'Physical fixture driver', PnPDeviceID: 'PCI\\fixture', MacAddress: '02-00-00-00-00-01', Status: 'Up' }
    const partial: Record<string, unknown> = kind === 'adapter' ? {
      'latest-physical-adapter-lockdown.json': { schemaVersion: 1, owner: 'VPNTE', adapters: [
        { ifIndex: physical.ifIndex, alias: physical.Name, interfaceGuid: physical.InterfaceGuid, ipv6Enabled: true, forcedIpv6Off: true, forcedDnsTo: ['192.168.250.254'], ipv4DnsSource: 'static', ipv4DnsServers: ['192.0.2.53'] },
        { ifIndex: 11 } // Interrupted write: no ownership identity or previous state.
      ] }
    } : kind === 'baseline' ? {
      'latest-tun-network-baseline.json': { schemaVersion: 1, owner: 'VPNTE', userSid: 'S-1-5-21-1-2-3-1001',
        values: ['ProxyEnable','ProxyServer','AutoConfigURL','AutoDetect'].map(name => ({ target: 'internet', name, exists: false, kind: null, data: null })) }
    } : {}
    const result = run({ rules: true, firewall: kind === 'firewall' ? { ...firewall, savedProfiles: profiles.slice(0, 1) } : firewall,
      tun: kind === 'tun' ? { ...tun, interfaceGuid: '' } : tun, extra: partial,
      adapters: [...fixtures().adapters, physical] })
    expect(result.status).toBe(1)
    expect(result.output).toContain('REPORT:warnings')
    expect(result.output).toContain('REMOVE_RULE')
    expect(result.output).not.toContain('Unexpected registry read')
    if (kind === 'adapter') {
      expect(result.output).toContain('RESTORE_DNS:Fixture Ethernet')
      expect(result.output).toContain('RESTORE_BINDING:Fixture Ethernet')
      expect(result.output).not.toContain('DNS read-back mismatch')
    } else expect(result.output).not.toMatch(/RESTORE_DNS:|RESTORE_BINDING:/)
    if (kind === 'firewall') {
      expect(result.output).not.toMatch(/QUARANTINE:|DELETE:.*firewall\.json/)
      expect(result.output).toContain('Firewall profile restored: Domain')
      expect(result.output).not.toMatch(/PROFILE:(Private|Public)\//)
      for (const name of ['Domain','Private','Public']) expect(result.output).toContain(`PROFILE_STATE:${name}/Block`)
    } else {
      for (const name of ['Domain','Private','Public']) expect(result.output).toContain(`PROFILE:${name}/Block`)
      for (const name of ['Domain','Private','Public']) expect(result.output).toContain(`PROFILE_STATE:${name}/Block`)
      expect(result.output).toMatch(/DELETE:.*firewall\.json/)
    }
    if (kind === 'tun') {
      expect(result.output).toContain('TUN recovery failed; ownership record preserved')
      expect(result.output).not.toMatch(/REMOVE_ADAPTER:|DELETE:.*tun-owner\.json/)
    } else {
      expect(result.output).toContain('REMOVE_ADAPTER:Other VPN')
      expect(result.output).toMatch(/DELETE:.*tun-owner\.json/)
      expect(result.output).not.toContain('TUN recovery failed')
    }
    expect(result.output).not.toContain('REMOVE_ADAPTER:Fixture Ethernet')
    if (kind === 'adapter') expect(result.output).toContain('Adapter entry rejected: 1; skipped')
    if (kind === 'baseline') {
      for (const name of ['ProxyEnable','ProxyServer','AutoConfigURL','AutoDetect']) expect(result.output).toContain(`Baseline restored: internet/${name}`)
      expect(result.output).toContain('Baseline snapshot missing: environment/HTTP_PROXY; skipped')
    }
    expect(result.output).not.toMatch(/DELETE:.*latest-(?:physical-adapter-lockdown|tun-network-baseline)\.json/)
  })
  it.each(['recovery-policy.json', 'firewall.json', 'latest-physical-adapter-lockdown.json', 'latest-tun-network-baseline.json', 'tun-owner.json'])('rejects an unsupported %s version before any network effects (AT-03-003)', name => {
    const result = run({ rules: true, extra: { [name]: { schemaVersion: 2, owner: 'VPNTE', strictMode: true } } })
    expect(result.status).toBe(1)
    expect(result.output).not.toMatch(/PROFILE:|REMOVE_RULE|REMOVE_ADAPTER:|QUARANTINE:/)
    expect(result.output).toContain('Unsupported recovery manifest version')
  })
  it('quarantines corrupt trusted firewall data and reports unknown Allow fallback (AT-03-003)', () => {
    const result = run({ rules: true, corrupt: 'firewall.json' })
    expect(result.status).toBe(1)
    expect(result.output).toMatch(/QUARANTINE:.*firewall\.json/)
    expect(result.output).toContain('PROFILE:Public/Allow')
    expect(result.output).not.toContain('/Block')
    expect(result.output).toContain('protection unknown')
    expect(result.output).toContain('REPORT:warnings')
  })
  it('keeps explicitly selected strict protection when the firewall snapshot is corrupt (AT-03-003)', () => {
    const result = run({ policy: { schemaVersion: 1, owner: 'VPNTE', strictMode: true }, corrupt: 'firewall.json', rules: true })
    expect(result.status).toBe(1)
    expect(result.output).toContain('QUARANTINE:')
    expect(result.output).toContain('PROFILE:Public/Block')
    expect(result.output).not.toMatch(/\/Allow|REMOVE_RULE/)
  })
  it('rejects an untrusted later manifest before firewall rollback, without quarantine (AT-03-012)', () => {
    const result = run({ rules: true, extra: { 'tun-owner.json': { schemaVersion: 1, owner: 'VPNTE' } }, untrustedFile: 'tun-owner.json' })
    expect(result.status).toBe(1)
    expect(result.output).not.toMatch(/PROFILE:|REMOVE_RULE|QUARANTINE:/)
  })
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
    const result = run({ policy: { schemaVersion: 1, owner: 'VPNTE', strictMode: true }, rules: true, wfpRules: true })
    expect(result.status).toBe(0)
    expect(result.output).toContain('PROFILE:Public/Block')
    expect(result.output).not.toContain('/Allow')
    expect(result.output).not.toContain('REMOVE_RULE')
    expect(result.output).not.toContain('REMOVE_ADAPTER')
    expect(result.output).not.toContain('WFP_CLEANUP')
    expect(result.output).toContain('REPORT:strict-retained')
  })
  it('removes orphaned owned WFP filters even without a firewall journal (AT-03-003)', () => {
    const result = run({ wfpRules: true })
    expect(result.status).toBe(0)
    expect(result.output).toContain('WFP_CLEANUP')
    expect(result.output).not.toContain('PROFILE:')
  })
  it('reports WFP recovery failure while continuing independent firewall/TUN recovery (AT-03-007)', () => {
    const firewall = { schemaVersion: 1, owner: 'VPNTE', strictMode: false, phase: 'active', savedProfiles: ['Domain','Private','Public'].map(name => ({ name, defaultOutbound: 'Allow' })) }
    const result = run({ firewall, wfpFailure: true, rules: true })
    expect(result.status).toBe(1)
    expect(result.output).toContain('PROFILE:Public/Allow')
    expect(result.output).toContain('IPv6 WFP recovery failed')
    expect(result.output).toContain('REPORT:warnings')
    expect(result.output).not.toMatch(/DELETE:.*firewall\.json/)
  })
  it('rejects a future nested IPv6 policy before firewall or WFP effects (AT-03-003)', () => {
    const result = run({ firewall: { schemaVersion: 1, owner: 'VPNTE', ipv6Policy: { schemaVersion: 2 } }, rules: true, wfpRules: true })
    expect(result.status).toBe(1)
    expect(result.output).not.toMatch(/PROFILE:|REMOVE_RULE|WFP_CLEANUP|QUARANTINE:/)
  })
  it('continues independent profile restoration and preserves the snapshot on failure', () => {
    const firewall = { schemaVersion: 1, owner: 'VPNTE', strictMode: false, phase: 'active', savedProfiles: ['Domain','Private','Public'].map(name => ({ name, defaultOutbound: 'Allow' })) }
    const result = run({ firewall, failProfile: 'Domain', rules: true })
    expect(result.status).toBe(1)
    expect(result.output).toContain('PROFILE:Private/Allow')
    expect(result.output).toContain('PROFILE:Public/Allow')
    expect(result.output).toContain('PROFILE_STATE:Domain/Block')
    expect(result.output).toContain('PROFILE_STATE:Private/Allow')
    expect(result.output).toContain('PROFILE_STATE:Public/Allow')
    expect(result.output).not.toMatch(/DELETE:.*firewall\.json/)
    expect(result.output).toContain('REPORT:warnings')
  })
  it('only removes the exact GUID/driver/subnet-owned Wintun adapter', () => {
    const adapters = [...fixtures().adapters, { ...fixtures().adapters[0], Name: 'VPNTE', ifIndex: 11, InterfaceGuid: '22222222-2222-2222-2222-222222222222' }]
    const result = run({ adapters, tun: { schemaVersion: 1, owner: 'VPNTE', interfaceGuid: adapters[1].InterfaceGuid } })
    expect(result.output).toContain('REMOVE_ADAPTER:VPNTE')
    expect(result.output).not.toContain('REMOVE_ADAPTER:Other VPN')
  })
})
