// AT-03-003/006/007/012: actual dispatcher with fake cmdlets, no system writes.
import { describe, expect, it } from 'vitest'
import { execFileSync } from 'node:child_process'
import { DNS_POLICY_SNAPSHOT_SCRIPT, recoveryWorkerFunctions, recoveryWorkerScript } from './recoveryPsProtocol'

const native = process.platform === 'win32' || Boolean(process.env.VPNTE_PWSH)
function run(request: unknown, variant = 'trusted'): {value: string; set: number; removed: number} {
  const serialized = Buffer.from(JSON.stringify(request)).toString('base64')
  const fixture = String.raw`
$global:variant='${variant}'
$global:sets=0;$global:removed=0
function Test-Path { [CmdletBinding()]param($LiteralPath) return -not ($global:variant -eq 'storageMissing' -or ($global:variant -eq 'absent' -and $LiteralPath -like '*firewall.json')) }
function Get-Item { [CmdletBinding()]param($LiteralPath,[switch]$Force)
  $isFile=$LiteralPath -like '*.json' -or $LiteralPath -like '*tmp-*'
  $parent=$LiteralPath -eq [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  $reparse=($global:variant -eq 'parentReparse' -and $parent) -or ($global:variant -eq 'directoryReparse' -and -not $isFile -and -not $parent) -or ($global:variant -eq 'fileReparse' -and $isFile)
  [pscustomobject]@{PSIsContainer=((-not $isFile) -or ($global:variant -eq 'fileType' -and $isFile));Attributes=$(if($reparse){[IO.FileAttributes]::ReparsePoint}else{[IO.FileAttributes]::Normal});Length=$(if($global:variant -eq 'oversized' -and $isFile){1048577}else{10})}
}
function Get-Acl { [CmdletBinding()]param($LiteralPath)
  $isFile=$LiteralPath -like '*.json' -or $LiteralPath -like '*tmp-*'
  $acl=[pscustomobject]@{IsFile=$isFile;AreAccessRulesProtected=($global:variant -ne 'unprotected' -and -not ($global:variant -eq 'postUnprotected' -and $global:sets -gt 0))}
  $acl|Add-Member ScriptMethod GetOwner {param($type) [pscustomobject]@{Value=$(if($global:variant -eq 'owner' -or ($global:variant -eq 'fileOwner' -and $this.IsFile)){'S-1-5-32-545'}else{'S-1-5-32-544'})} }
  $acl|Add-Member ScriptMethod GetAccessRules {param($a,$b,$c) [pscustomobject]@{AccessControlType='Allow';IdentityReference=[pscustomobject]@{Value=$(if($global:variant -eq 'ace'){'S-1-5-32-545'}else{'S-1-5-18'})}} }
  $acl
}
function Get-Content { [CmdletBinding()]param($LiteralPath,[switch]$Raw,$Encoding) return ([pscustomobject]@{owner='VPNTE';text='сеть'}|ConvertTo-Json -Compress) }
function Remove-Item { [CmdletBinding()]param($LiteralPath,[switch]$Force) $global:removed++;if($global:variant -eq 'removeError'){throw 'Fixture remove failure'} }
function Set-Acl { [CmdletBinding()]param($LiteralPath,$AclObject) $global:sets++;if($global:variant -eq 'setError'){throw 'Fixture ACL failure'} }
function Get-NetAdapter { [CmdletBinding()]param($Name)
  $a=[pscustomobject]@{Name=$(if($global:variant -eq 'renamed'){'Ethernet 6'}else{'Ethernet 5'});Status=$(if($global:variant -eq 'down'){'Disconnected'}else{'Up'});DriverDescription=$(if($global:variant -eq 'driver'){'Physical NIC'}else{'Wintun Userspace Tunnel'});PnPDeviceID=$(if($global:variant -eq 'pnp'){'ROOT\NIC\x'}else{'SWD\Wintun\fixture'});ifIndex=5;InterfaceGuid=$(if($global:variant -eq 'guid'){'invalid'}else{'00000000-0000-0000-0000-000000000005'})}
  $a;if($global:variant -eq 'duplicate'){$a}
}
function Get-NetIPAddress { [CmdletBinding()]param($InterfaceIndex,$AddressFamily)
  [pscustomobject]@{IPAddress=$(if($global:variant -eq 'ip'){'192.168.250.254'}else{'192.168.250.253'});PrefixLength=$(if($global:variant -eq 'prefix'){24}else{30})}
}
${recoveryWorkerFunctions(variant === 'environmentMismatch' ? 'C:\\different-programdata' : process.env.ProgramData || 'C:\\ProgramData')}
$request=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${serialized}'))|ConvertFrom-Json
$value=Invoke-RecoveryOperation $request
[pscustomobject]@{value=$value;set=$global:sets;removed=$global:removed}|ConvertTo-Json -Compress
`
  const env = {...process.env}
  for(const key of Object.keys(env))if(key.toLowerCase()==='psmodulepath')delete env[key]
  const stdout=execFileSync(process.env.VPNTE_PWSH || 'powershell.exe', ['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from("$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.Encoding]::UTF8;"+fixture,'utf16le').toString('base64')], {env,timeout:15000,encoding:'utf8',stdio:['ignore','pipe','pipe']})
  return JSON.parse(stdout.replace(/^\uFEFF/,'').trim())
}
describe('fixed recovery dispatcher native proof', () => {
  it.skipIf(!native)('reads both real DNS policies identically to the fixed standalone reader without system writes', () => {
    const script = "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + DNS_POLICY_SNAPSHOT_SCRIPT
    const standalone = execFileSync(process.env.VPNTE_PWSH || 'powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], {
      timeout: 15000, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe']
    })
    const result = run({ op: 'inspect-dns-policy' })
    const rows = JSON.parse(result.value)
    expect(rows).toEqual(JSON.parse(standalone.replace(/^\uFEFF/, '').trim()))
    expect(rows.map((row: { tag: string }) => row.tag)).toEqual(['smartNameResolution', 'parallelAandAAAA'])
    for (const row of rows) {
      expect(typeof row.exists).toBe('boolean')
      expect(Object.keys(row).sort()).toEqual(['data', 'exists', 'tag', 'type'])
      if (row.exists) {
        expect(row.type).toBe('REG_DWORD')
        expect(row.data).toMatch(/^0x[0-9a-f]{1,8}$/i)
      } else expect(row).toMatchObject({ type: null, data: null })
    }
    expect(result).toMatchObject({ set: 0, removed: 0 })
  }, 30000)
  it.skipIf(!native).each([
    { op: 'inspect-dns-policy', key: 'HKLM\\arbitrary' },
    { op: 'inspect-dns-policy', path: 'C:\\arbitrary' },
    { op: 'inspect-dns-policy', script: 'Get-Process' },
    { op: 'inspect-dns-policy', name: 'firewall.json' },
    { op: 'INSPECT-DNS-POLICY' }
  ])('rejects an expanded DNS request at the native boundary: %j', request => {
    expect(() => run(request)).toThrow()
  }, 20000)
  it.skipIf(!native)('reads trusted JSON with unicode and reports checked absence',()=>{
    expect(JSON.parse(run({op:'read',name:'firewall.json'}).value)).toEqual({owner:'VPNTE',text:'сеть'})
    expect(run({op:'read',name:'firewall.json'},'absent').value).toBe('RECOVERY_ARTIFACT_ABSENT')
    expect(run({op:'read',name:'firewall.json'},'storageMissing').value).toBe('RECOVERY_STORAGE_MISSING')
  },20000)
  it.skipIf(!native).each(['owner','ace','unprotected','fileOwner','fileType','fileReparse','parentReparse','directoryReparse','oversized','environmentMismatch'])('rejects %s on actual read path',variant=>{
    expect(()=>run({op:'read',name:'firewall.json'},variant)).toThrow()
  },20000)
  it.skipIf(!native)('removes only a checked artifact and verifies existing storage',()=>{
    expect(run({op:'remove',name:'firewall.json'})).toMatchObject({value:'RECOVERY_ARTIFACT_REMOVED',removed:1,set:0})
    expect(run({op:'ensure'})).toMatchObject({value:'RECOVERY_STORAGE_VERIFIED',set:0})
  },20000)
  it.skipIf(!native).each(['owner','ace','fileReparse','directoryReparse','removeError'])('refuses unsafe/failed removal: %s',variant=>{
    expect(()=>run({op:'remove',name:'firewall.json'},variant)).toThrow()
  },20000)
  it.skipIf(!native)('protects only a new UUID temporary and verifies its ACL after setting',()=>{
    expect(run({op:'protect',name:'tmp-00000000-0000-0000-0000-000000000001'})).toMatchObject({value:'RECOVERY_TEMP_VERIFIED',set:1,removed:0})
  },20000)
  it.skipIf(!native).each(['fileReparse','fileType','directoryReparse','setError','postUnprotected'])('does not bless unsafe or unverifiable temporary: %s',variant=>{
    expect(()=>run({op:'protect',name:'tmp-00000000-0000-0000-0000-000000000001'},variant)).toThrow()
  },20000)
  it.skipIf(!native)('inspects exact owned TUN alias and returns GUID for durable commit',()=>{
    expect(JSON.parse(run({op:'inspect-tun',alias:'Ethernet 5'}).value)).toMatchObject({owner:'VPNTE',alias:'Ethernet 5',interfaceGuid:'00000000-0000-0000-0000-000000000005'})
  },20000)
  it.skipIf(!native).each(['down','driver','pnp','ip','prefix','guid','duplicate','renamed'])('rejects bad TUN evidence: %s',variant=>{
    expect(()=>run({op:'inspect-tun',alias:'Ethernet 5'},variant)).toThrow()
  },20000)
  it.skipIf(!native).each([{op:'read',name:'..\\file.json'},{op:'protect',name:'firewall.json'},{op:'ensure',script:'Remove-Item'},{op:'inspect-tun',alias:'Ethernet 5; x'},{op:'bogus'},{op:'READ',name:'firewall.json'}])('validates data again in PowerShell: %j',request=>{
    expect(()=>run(request)).toThrow()
  },20000)
  it('does not interpret incoming scripts or reset arbitrary trees',()=>{
    const script=recoveryWorkerScript('C:\\ProgramData')
    expect(script).not.toMatch(/ScriptBlock|Invoke-Expression|cmd\.exe|\.request\.script|-Recurse|icacls/i)
    expect(script).toContain('switch -Exact')
  })
})
