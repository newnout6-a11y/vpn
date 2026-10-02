import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { expect, it } from 'vitest'

// Execute only the extracted function/block, never the recovery script itself.
// All registry/filesystem commands inside those fragments are replaced below.
const source = readFileSync(join(process.cwd(), 'resources/vpnte-recover.ps1'), 'utf8')
const restore = source.slice(source.indexOf('function Restore-RegValue'), source.indexOf('# 1. Firewall'))
const cleanup = source.slice(source.indexOf('if ($adapterManifest -and -not $hasWarnings'), source.lastIndexOf('if ($hasWarnings)'))
const tunCleanup = source.slice(source.indexOf('# 8. Remove only'), source.indexOf('if ($adapterManifest -and -not $hasWarnings'))
const powerShell = process.env.VPNTE_PWSH || (process.platform === 'win32' ? 'powershell.exe' : null)
function run(script: string) {
  const encoded = Buffer.from("$ErrorActionPreference='Stop';\n" + script, 'utf16le').toString('base64')
  return JSON.parse(execFileSync(powerShell!, ['-NoProfile', '-NonInteractive', '-OutputFormat', 'Text', '-EncodedCommand', encoded], {
    encoding: 'utf8', windowsHide: true, timeout: 15000, stdio: ['pipe', 'pipe', 'pipe']
  }).trim())
}

it.skipIf(!powerShell).each([
  { driver: 'Wintun Userspace Tunnel', pnp: 'SWD\\Wintun\\fixture', ip: '192.168.250.253', guidMatch: true, removed: true, warning: false },
  { driver: 'Physical NIC', pnp: 'SWD\\Wintun\\fixture', ip: '192.168.250.253', guidMatch: true, removed: false, warning: true },
  { driver: 'Wintun Userspace Tunnel', pnp: 'ROOT\\NET\\fixture', ip: '192.168.250.253', guidMatch: true, removed: false, warning: true },
  { driver: 'Wintun Userspace Tunnel', pnp: 'SWD\\Wintun\\fixture', ip: '192.168.250.254', guidMatch: true, removed: false, warning: true },
  { driver: 'Wintun Userspace Tunnel', pnp: 'SWD\\Wintun\\fixture', ip: '192.168.250.253', guidMatch: false, removed: false, warning: false }
])('boot recovery checks real driver fields, GUID and subnet (AT-03-002): $driver / $pnp / $guidMatch', fixture => {
  const encoded = Buffer.from(JSON.stringify(fixture)).toString('base64')
  const result = run(`
$fixture=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}'))|ConvertFrom-Json
$script:removed=$false;$script:cleared=$false;$hasWarnings=$false;$trustedManifestDir='fixture'
function Log($message) {}
function Read-TrustedManifest { [pscustomobject]@{interfaceGuid='00000000-0000-0000-0000-000000000005'} }
function Get-NetAdapter { [pscustomobject]@{Name='Ethernet 5';InterfaceDescription='sing-tun Tunnel';DriverDescription=$fixture.driver;PnPDeviceID=$fixture.pnp;ifIndex=5;InterfaceGuid=$(if($fixture.guidMatch){'00000000-0000-0000-0000-000000000005'}else{'00000000-0000-0000-0000-000000000006'})} }
function Get-NetIPAddress { [pscustomobject]@{IPAddress=$fixture.ip;PrefixLength=30} }
function Remove-NetAdapter { $script:removed=$true }
function Disable-NetAdapter { throw 'Unexpected fallback' }
function Remove-Item { $script:cleared=$true }
${tunCleanup}
@{removed=$script:removed;cleared=$script:cleared;warning=$hasWarnings}|ConvertTo-Json -Compress
`)
  expect(result).toEqual({ removed: fixture.removed, cleared: !fixture.warning, warning: fixture.warning })
}, 20000)

it.skipIf(!powerShell)('recovery handles failed deletion, zero values and missing snapshots without real registry access', () => {
  const result = run(`
    function Log($message) {}
    $script:calls = @()
    $script:injectDeleteFailure = $true
    $script:present = $false
    $script:data = 0
    function Get-RecoveryRegistryKey($path) {
      $key = [pscustomobject]@{}
      $key | Add-Member ScriptMethod SetValue { param($name,$data,$kind) $script:calls += "set:$name/$data"; $script:data=$data; $script:present=$true }
      $key | Add-Member ScriptMethod DeleteValue { param($name,$strict) if($script:injectDeleteFailure){throw 'Access denied'}; $script:present=$false }
      $key | Add-Member ScriptMethod GetValueNames { if($script:present){return @('DisableSmartNameResolution')}else{return @()} }
      $key | Add-Member ScriptMethod GetValueKind { param($name) [Microsoft.Win32.RegistryValueKind]::DWord }
      $key | Add-Member ScriptMethod GetValue { param($name) $script:data }
      $key | Add-Member ScriptMethod Close {}
      return $key
    }
    ${restore}
    $script:hasWarnings = $false
    Restore-RegValue 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' 'DisableSmartNameResolution' @{ exists=$false } 'test'
    $failedDelete = $script:hasWarnings
    $script:injectDeleteFailure = $false
    $script:hasWarnings = $false
    Restore-RegValue 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' 'DisableSmartNameResolution' @{ exists=$true; type='REG_DWORD'; data=0 } 'test'
    $zeroSuccess = -not $script:hasWarnings
    $before = $script:calls.Count
    Restore-RegValue 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' 'DisableSmartNameResolution' $null 'test'
    @{ failedDelete=$failedDelete; zeroSuccess=$zeroSuccess; unknownWarning=$script:hasWarnings;
       unknownUnchanged=($before -eq $script:calls.Count); calls=$script:calls } | ConvertTo-Json -Compress
  `)
  expect(result).toMatchObject({ failedDelete: true, zeroSuccess: true, unknownWarning: true, unknownUnchanged: true })
  expect(result.calls).toContain('set:DisableSmartNameResolution/0')
}, 20000)

it.skipIf(!powerShell)('recovery preserves unrelated snapshots and all snapshots on warnings', () => {
  const result = run(`
    function Log($message) {}
    function Test-Path { $true }
    function Get-Content { param($LiteralPath, [switch]$Raw); if ($LiteralPath -eq 'other') { '{"id":2}' } else { '{"id":1}' } }
    function Remove-Item { param($Path, [switch]$Force, $ErrorAction); $script:removed += $Path }
    $adapterManifest = [pscustomobject]@{id=1}
    $candidatePaths = @('canonical','copy','other')
    $script:removed = @()
    $hasWarnings = $false
    ${cleanup}
    $successful = @($script:removed)
    $script:removed = @()
    $hasWarnings = $true
    ${cleanup}
    @{ successful=$successful; onWarning=@($script:removed) } | ConvertTo-Json -Compress
  `)
  expect(result.successful).toEqual(['canonical', 'copy'])
  expect(result.onWarning).toEqual([])
}, 20000)
