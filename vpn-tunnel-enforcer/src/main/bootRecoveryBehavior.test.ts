import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { expect, it } from 'vitest'

// Execute only the extracted function/block, never the recovery script itself.
// All registry/filesystem commands inside those fragments are replaced below.
const source = readFileSync(join(process.cwd(), 'resources/vpnte-recover.ps1'), 'utf8')
const restore = source.slice(source.indexOf('function Restore-RegValue'), source.indexOf('# 1. Firewall'))
const cleanup = source.slice(source.indexOf('if ($adapterManifest -and -not $hasWarnings'), source.lastIndexOf('if ($hasWarnings)'))
function run(script: string) {
  const encoded = Buffer.from("$ErrorActionPreference='Stop';\n" + script, 'utf16le').toString('base64')
  return JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-OutputFormat', 'Text', '-EncodedCommand', encoded], {
    encoding: 'utf8', windowsHide: true, timeout: 15000, stdio: ['pipe', 'pipe', 'pipe']
  }).trim())
}

it.skipIf(process.platform !== 'win32')('recovery handles failed deletion, zero values and missing snapshots without real registry access', () => {
  const result = run(`
    function Log($message) {}
    $script:calls = @()
    function reg { $script:calls += ($args -join ' '); $global:LASTEXITCODE = 5; 'Access denied' }
    ${restore}
    $script:hasWarnings = $false
    Restore-RegValue 'HKLM\\fake' 'Policy' @{ exists=$false } 'test'
    $failedDelete = $script:hasWarnings
    function reg { $script:calls += ($args -join ' '); $global:LASTEXITCODE = 0 }
    $script:hasWarnings = $false
    Restore-RegValue 'HKLM\\fake' 'Policy' @{ exists=$true; type='REG_DWORD'; data=0 } 'test'
    $zeroSuccess = -not $script:hasWarnings
    $before = $script:calls.Count
    Restore-RegValue 'HKLM\\fake' 'Policy' $null 'test'
    @{ failedDelete=$failedDelete; zeroSuccess=$zeroSuccess; unknownWarning=$script:hasWarnings;
       unknownUnchanged=($before -eq $script:calls.Count); calls=$script:calls } | ConvertTo-Json -Compress
  `)
  expect(result).toMatchObject({ failedDelete: true, zeroSuccess: true, unknownWarning: true, unknownUnchanged: true })
  expect(result.calls[1]).toContain('add HKLM\\fake /v Policy /t REG_DWORD /d 0')
}, 20000)

it.skipIf(process.platform !== 'win32')('recovery preserves unrelated snapshots and all snapshots on warnings', () => {
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
