// AT-11-002 / AT-11-009, F-183: opt-in harmless native shutdown fixtures.
import { join } from 'node:path'
import { execFile as execFileCb } from 'node:child_process'
import { promisify } from 'node:util'
import { describe, expect, it } from 'vitest'

const helperPath = join(__dirname, '../../build/shutdown-for-update.ps1')

const execFile = promisify(execFileCb)
describe.skipIf(process.platform !== 'win32')('native shutdown gate (no real client/network effects)', () => {
  it.each([0, 73])('reads exit=%s from a real bound handle to a harmless PowerShell child', async code => {
    const child = Buffer.from(`Start-Sleep -Milliseconds 800; exit ${code}`, 'utf16le').toString('base64')
    const script = `
. '${helperPath.replace(/'/g, "''")}' -InstallDir 'C:\\fixture\\vpn'
$exe=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\\v1.0\\powershell.exe'
$child=Start-Process -FilePath $exe -ArgumentList '-NoProfile -NonInteractive -EncodedCommand ${child}' -PassThru
$bound=Open-VpnteAppProcess $child.Id
try {
  if(-not $bound.WaitForExit(10000)){throw 'harmless fixture timed out'}
  'BOUND_EXIT:'+$bound.ExitCode
} finally { $bound.Dispose(); $child.Dispose() }
`
    const { stdout } = await execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], {
      timeout: 15000, windowsHide: true, encoding: 'utf8'
    })
    expect(stdout).toContain(`BOUND_EXIT:${code}`)
  }, 20000)
  it.each(['success', 'absent', 'timeout', 'exit-zero', 'crash', 'foreign', 'query-error', 'remaining', 'released-after-polls'] as const)('handles %s without forced termination', async scenario => {
    const script = `
. '${helperPath.replace(/'/g, "''")}' -InstallDir 'C:\\fixture\\vpn'
$global:scenario='${scenario}'; $global:queries=0; $global:launched=$false; $global:disposed=$false
function Get-VpnteProcesses {
  $global:queries++
  if ($global:scenario -eq 'query-error') { throw 'fixture query failed' }
  if ($global:scenario -eq 'absent') { return }
  if ($global:queries -gt 1) {
    if ($global:scenario -eq 'remaining' -or ($global:scenario -eq 'released-after-polls' -and $global:queries -lt 4)) {
      return [pscustomobject]@{Name='vpnte-xray.exe'}
    }
    return
  }
  $path=if($global:scenario -eq 'foreign') {'C:\\foreign\\VPN Tunnel Enforcer.exe'} else {'C:\\fixture\\vpn\\VPN Tunnel Enforcer.exe'}
  [pscustomobject]@{Name='VPN Tunnel Enforcer.exe';ExecutablePath=$path;CommandLine='client';ProcessId=42}
}
function Open-VpnteAppProcess([int]$Id) {
  if($Id -ne 42){throw 'unexpected fixture PID'}
  $code=switch($global:scenario){'exit-zero'{0};'crash'{1};default{73}}
  $p=[pscustomobject]@{ExitCode=$code;MainModule=[pscustomobject]@{FileName='C:\\fixture\\vpn\\VPN Tunnel Enforcer.exe'}}
  $p | Add-Member ScriptMethod WaitForExit {param($ms) if($ms -ne 1000){throw 'unexpected timeout'}; return $global:scenario -ne 'timeout'}
  $p | Add-Member ScriptMethod Dispose {$global:disposed=$true}
  return $p
}
function Start-Process {param($FilePath,$ArgumentList,$ErrorAction)
  if($FilePath -ne 'C:\\fixture\\vpn\\VPN Tunnel Enforcer.exe' -or $ArgumentList -ne '--shutdown-for-update'){throw 'unexpected fixture launch'}
  $global:launched=$true
}
# Use real sleep so the production poll reaches its deadline; all process data is mocked.
try { Invoke-VpnteShutdown 'C:\\fixture\\vpn' 1; 'RESULT:success' }
catch { 'RESULT:refused'; 'REASON:'+$_.Exception.Message }
'LAUNCHED:'+$global:launched
'DISPOSED:'+$global:disposed
'QUERIES:'+$global:queries
`
    const { stdout } = await execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], {
      timeout: 10000, windowsHide: true, encoding: 'utf8'
    })
    expect(stdout).toContain(['success', 'absent', 'released-after-polls'].includes(scenario) ? 'RESULT:success' : 'RESULT:refused')
    const reasons: Partial<Record<typeof scenario, string>> = {
      timeout: 'Client cleanup timed out; update refused.',
      'exit-zero': 'Client exited without cleanup acknowledgement; update refused.',
      crash: 'Client exited without cleanup acknowledgement; update refused.',
      foreign: 'Cannot identify the installed primary client.',
      'query-error': 'fixture query failed',
      remaining: 'VPNTE background processes remain; update refused.'
    }
    const reason = reasons[scenario]
    if (reason) expect(stdout).toContain(`REASON:${reason}`)
    else expect(stdout).not.toContain('REASON:')
    if (['remaining', 'released-after-polls'].includes(scenario)) {
      expect(Number(stdout.match(/QUERIES:(\d+)/)?.[1])).toBeGreaterThanOrEqual(4)
    }
    expect(stdout).toContain(['absent', 'foreign', 'query-error'].includes(scenario) ? 'LAUNCHED:False' : 'LAUNCHED:True')
    expect(stdout).toContain(['absent', 'foreign', 'query-error'].includes(scenario) ? 'DISPOSED:False' : 'DISPOSED:True')
  }, 15000)
})
