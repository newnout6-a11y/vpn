// AT-02-005/AT-03-006/007/012: real dispatcher, synthetic module/query boundaries.
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { recoveryWorkerFunctions } from './recoveryPsProtocol'

describe.skipIf(process.platform !== 'win32')('shared network definition preparation', () => {
  it.each(['selective', 'definition-missing', 'types-failed', 'fallback-failed'])(
    'prepares once before fresh adapter reads and retries failed preparation: %s', variant => {
      const script = String.raw`
${recoveryWorkerFunctions(process.env.ProgramData || 'C:\\ProgramData')}
$global:variant='${variant}'; $global:imports=@(); $global:types=0; $global:reads=0
function Import-Module { [CmdletBinding()]param([string[]]$Name,[switch]$Global)
  foreach($item in $Name){
    $global:imports+=Split-Path -Leaf $item
    if($item -in @('NetAdapter','DnsClient','NetTCPIP','NetConnection')){
      if($global:variant -eq 'fallback-failed'){throw 'Fallback refused'}
    } elseif($global:variant -in @('definition-missing','fallback-failed')){throw 'Definition unavailable'}
  }
}
function Update-TypeData { [CmdletBinding()]param($PrependPath)
  $global:types++; if($global:variant -eq 'types-failed'){throw 'Types unavailable'}
}
function Read-PhysicalAdapterDns { $global:reads++; return ('fresh-'+$global:reads) }
function Read-PhysicalAdapters { $global:reads++; return 'fresh-adapters' }
function Read-TransitionAdapters { $global:reads++; return 'fresh-transition' }
function Read-DnsPolicySnapshot { return 'unrelated' }
function Get-NetAdapter { [CmdletBinding()]param($Name)
  $global:reads++
  [pscustomobject]@{Name=$Name;Status='Up';DriverDescription='Wintun Userspace Tunnel';PnPDeviceID='SWD\Wintun\fixture';ifIndex=5;InterfaceGuid='00000000-0000-0000-0000-000000000005'}
}
function Get-NetIPAddress { [CmdletBinding()]param($InterfaceIndex,$AddressFamily)
  [pscustomobject]@{IPAddress='192.168.250.253';PrefixLength=30}
}
# Refuse malformed input before even importing fixed command definitions.
foreach($body in @('{'+'"op":"inspect-physical-dns","extra":true}', '{"op":"inspect-tun","alias":"unexpected"}', '{"op":"warmup-adapters","module":"unexpected"}')){
  $refused=$false; try { Invoke-RecoveryOperation ($body|ConvertFrom-Json)|Out-Null } catch { $refused=$true }
  if(-not $refused -or $global:imports.Count -or $global:reads){throw 'Invalid input reached preparation'}
}
if((Invoke-RecoveryOperation ([pscustomobject]@{op='inspect-dns-policy'})) -ne 'unrelated' -or $global:imports.Count){throw 'Unrelated operation prepared network modules'}
$requests=@(
  @{op='inspect-physical-dns'}, @{op='inspect-physical-dns'},
  @{op='inspect-physical-adapters'}, @{op='inspect-transition-adapters'},
  @{op='inspect-tun';alias='Ethernet 5'}, @{op='warmup-adapters';module='NetAdapter'}
)
$values=@(); $failed=0
foreach($request in $requests){try{$values+=Invoke-RecoveryOperation ([pscustomobject]$request)}catch{$failed++}}
$beforeRetry=[pscustomobject]@{imports=@($global:imports);types=$global:types;reads=$global:reads;failed=$failed;values=$values}
if($global:variant -eq 'fallback-failed'){$global:variant='selective'}
$retry=Invoke-RecoveryOperation ([pscustomobject]@{op='inspect-physical-dns'})
[pscustomobject]@{before=$beforeRetry;imports=@($global:imports);reads=$global:reads;retry=$retry}|ConvertTo-Json -Depth 5 -Compress
`
      mkdirSync(join(process.cwd(), '.tmp'), { recursive: true })
      const directory = mkdtempSync(join(process.cwd(), '.tmp', 'network-modules-'))
      let result: ReturnType<typeof spawnSync>
      try {
        const file = join(directory, 'fixture.ps1'); writeFileSync(file, '\ufeff' + script)
        result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', file],
          { encoding: 'utf8', windowsHide: true, timeout: 15000 })
      } finally { rmSync(directory, { recursive: true, force: true }) }
      expect(result.error?.message).toBeUndefined(); expect(result.status, String(result.stderr)).toBe(0)
      const evidence = JSON.parse(String(result.stdout).trim())
      expect(evidence.before.failed).toBe(variant === 'fallback-failed' ? 4 : 0)
      expect(evidence.before.reads).toBe(variant === 'fallback-failed' ? 2 : 5)
      if (variant === 'fallback-failed') {
        // CIM/netsh operations stay independent of network command definitions.
        expect(evidence.before.values).toEqual(['fresh-adapters', 'fresh-transition'])
        expect(evidence.before.imports).toHaveLength(8) // Every definition-dependent command retries before its query.
        expect(evidence.imports).toHaveLength(16)
        expect(evidence.retry).toBe('fresh-3')
      } else {
        expect(evidence.before.values.slice(0, 2)).toEqual(['fresh-1', 'fresh-2'])
        expect(evidence.imports).toEqual(evidence.before.imports) // Successful definitions only are cached.
        expect(evidence.retry).toBe('fresh-6')
        expect(evidence.imports).toHaveLength(variant === 'selective' ? 8 : variant === 'types-failed' ? 12 : 5)
        if (variant !== 'selective') expect(evidence.imports.slice(-4)).toEqual(['NetAdapter', 'DnsClient', 'NetTCPIP', 'NetConnection'])
      }
    })
})
