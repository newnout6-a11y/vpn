// AT-00-005 / AT-03-007: native transport evidence, no network or registry mutations.
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import ts from 'typescript'
import { PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT } from './physicalAdapterSnapshot'

const source = readFileSync(join(process.cwd(), 'src/main/elevatedPsHelper.ts'), 'utf8')
const marker = 'const PS_RUNNER_SCRIPT = `'
const begin = source.indexOf(marker)
const end = source.indexOf('\n`', begin + marker.length)
if (begin < 0 || end < 0) throw new Error('Production helper runner not found')
const runner = source.slice(begin + marker.length, end)
const shell = process.env.VPNTE_PWSH || 'powershell.exe'
const ast = ts.createSourceFile('elevatedPsHelper.ts', source, ts.ScriptTarget.Latest, true)
const warmup = ast.statements.find(node => ts.isVariableStatement(node) && node.declarationList.declarations.some(decl => decl.name.getText(ast) === 'HELPER_WARMUP_COMMANDS'))
if (!warmup) throw new Error('Production helper warm-up commands not found')
const commands = new Function(ts.transpileModule(warmup.getText(ast), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText + '\nreturn HELPER_WARMUP_COMMANDS;')()

describe.skipIf(process.platform !== 'win32')('native helper timing envelope', () => {
  it('prepares network cmdlets for physical policy without loading unrelated definitions', () => {
    const requests = [
      { id: 1, script: "@(Get-Module | Select-Object -ExpandProperty Name) | ConvertTo-Json -Compress" },
      { id: 2, policy: 'physical-adapter-lockdown', script: "Get-NetAdapter -Physical -ErrorAction Stop | Out-Null; Get-NetIPInterface -ErrorAction Stop | Out-Null" },
      { id: 3, script: "@(Get-Module | Select-Object -ExpandProperty Name) | ConvertTo-Json -Compress" }
    ]
    const result = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-Command', runner], {
      input: requests.map(item => JSON.stringify(item)).join('\n') + '\n__EXIT__\n',
      encoding: 'utf8', windowsHide: true, timeout: 15000
    })
    expect(result.error).toBeUndefined()
    expect(result.status).toBe(0)
    const replies = result.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line))
    for (const reply of replies) expect(reply).toMatchObject({ success: true, exitCode: 0 })
    const modules = JSON.parse(replies[2].stdout) as string[]
    expect(JSON.parse(replies[0].stdout)).not.toContain('MSFT_NetAdapter.cmdletDefinition')
    expect(modules).toContain('MSFT_NetAdapter.cmdletDefinition')
    expect(modules).toContain('MSFT_NetAdapterBinding.cmdletDefinition')
    for (const module of ['NetAdapter', 'DnsClient', 'NetTCPIP', 'NetConnection']) expect(modules).not.toContain(module)
  }, 20000)
  it.each(['selective', 'definition-missing', 'types-failed', 'fallback-failed'])(
    'prepares network definitions once and refuses the caller on failed fallback: %s (AT-02-005/AT-03-007)', variant => {
      const fixture = `
$global:imports=@(); $global:typeReads=0; $global:callerReads=0
function Import-Module { [CmdletBinding()]param([string[]]$Name, [switch]$Global)
  foreach ($item in $Name) {
    $global:imports += Split-Path -Leaf $item
    if ($item -in @('NetAdapter','DnsClient','NetTCPIP','NetConnection')) {
      if ('${variant}' -eq 'fallback-failed') { throw 'Fallback unavailable' }
    } elseif ('${variant}' -in @('definition-missing','fallback-failed')) { throw 'Definition unavailable' }
  }
}
function Update-TypeData { [CmdletBinding()]param($PrependPath)
  $global:typeReads++
  if ('${variant}' -eq 'types-failed') { throw 'Types unavailable' }
}
`
      const requests = [1, 2].map(id => ({ id, policy: 'physical-adapter-lockdown', script: '$global:callerReads++' }))
      const input = [...requests, { id: 3, script: '[pscustomobject]@{ imports=$global:imports; typeReads=$global:typeReads; callerReads=$global:callerReads } | ConvertTo-Json -Compress' }]
      const result = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(fixture + runner, 'utf16le').toString('base64')], {
        input: input.map(item => JSON.stringify(item)).join('\n') + '\n__EXIT__\n',
        encoding: 'utf8', windowsHide: true, timeout: 10000
      })
      expect(result.error).toBeUndefined()
      expect(result.status).toBe(0)
      const replies = result.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line))
      expect(replies.map(reply => reply.id)).toEqual([1, 2, 3])
      for (const reply of replies.slice(0, 2)) expect(reply.success).toBe(variant !== 'fallback-failed')
      expect(replies[2].success).toBe(true)
      const evidence = JSON.parse(replies[2].stdout)
      expect(evidence.callerReads).toBe(variant === 'fallback-failed' ? 0 : 2)
      if (variant === 'selective') {
        expect(evidence.imports).toHaveLength(8)
        expect(evidence.typeReads).toBe(6)
        expect(evidence.imports).not.toContain('NetAdapter')
      } else if (variant === 'fallback-failed') {
        // Failed preparation is retried; it never marks this session ready.
        expect(evidence.imports).toEqual(['MSFT_NetAdapter.cmdletDefinition.cdxml', 'NetAdapter', 'MSFT_NetAdapter.cmdletDefinition.cdxml', 'NetAdapter'])
      } else {
        expect(evidence.imports.slice(-4)).toEqual(['NetAdapter', 'DnsClient', 'NetTCPIP', 'NetConnection'])
        expect(evidence.imports).toHaveLength(variant === 'types-failed' ? 12 : 5)
        expect(evidence.typeReads).toBe(variant === 'types-failed' ? 1 : 0)
      }
    })
  it.each(['selective', 'definition-missing', 'types-failed', 'fallback-failed'])(
    'loads only required firewall definitions, with a complete fallback: %s (AT-00-005/AT-03-007)', variant => {
      const script = `
$global:imports=@(); $global:typeReads=0; $global:profileReads=0
function Import-Module { [CmdletBinding()]param($Name)
  $global:imports += Split-Path -Leaf $Name
  if ($Name -eq 'NetSecurity') {
    if ('${variant}' -eq 'fallback-failed') { throw 'Fallback unavailable' }
  } elseif ('${variant}' -in @('definition-missing','fallback-failed')) { throw 'Definition unavailable' }
}
function Update-TypeData { [CmdletBinding()]param($PrependPath)
  $global:typeReads++
  if ('${variant}' -eq 'types-failed') { throw 'Types unavailable' }
}
function Get-NetFirewallProfile { [CmdletBinding()]param($Profile)
  $global:profileReads++
  [pscustomobject]@{ Name='Domain'; DefaultOutboundAction='NotConfigured' }
}
$succeeded=$false
try { & { ${commands[0].script} }; $succeeded=$true } catch {}
[pscustomobject]@{ imports=$global:imports; typeReads=$global:typeReads; profileReads=$global:profileReads; succeeded=$succeeded } | ConvertTo-Json -Compress
`
      const result = spawnSync(shell, ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
        { encoding: 'utf8', windowsHide: true, timeout: 10000 })
      expect(result.error).toBeUndefined()
      expect(result.status).toBe(0)
      const evidence = JSON.parse(result.stdout.trim())
      expect(evidence.succeeded).toBe(variant !== 'fallback-failed')
      expect(evidence.profileReads).toBe(variant === 'fallback-failed' ? 0 : 1)
      if (variant === 'selective' || variant === 'types-failed') {
        expect(evidence.imports.slice(0, 6)).toEqual(['NetFirewallProfile', 'NetFirewallRule', 'NetFirewallApplicationFilter',
          'NetFirewallAddressFilter', 'NetFirewallPortFilter', 'NetFirewallInterfaceFilter'].map(name => name + '.cmdletDefinition.cdxml'))
        expect(evidence.typeReads).toBe(1)
      }
      if (variant === 'selective') expect(evidence.imports).toHaveLength(6)
      else expect(evidence.imports.at(-1)).toBe('NetSecurity')
    })
  it('executes fixed warm-up and fresh native reads in the same production runner', () => {
    const requests = commands.map((command: { script: string; policy: string }, index: number) => ({ id: index + 1, script: command.script, policy: command.policy }))
    requests.push({ id: 6, script: "Get-NetFirewallProfile -Profile Domain,Private,Public -ErrorAction Stop | ForEach-Object { [string]$_.Name }" })
    requests.push({ id: 7, script: PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT })
    const result = spawnSync(shell, ['-NoProfile', '-NoLogo', '-NonInteractive', '-Command', runner], {
      input: requests.map((item: unknown) => JSON.stringify(item)).join('\n') + '\n__EXIT__\n',
      encoding: 'utf8', windowsHide: true, timeout: 20000
    })
    expect(result.error).toBeUndefined()
    expect(result.status).toBe(0)
    const replies = result.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line))
    expect(replies.map(item => item.id)).toEqual([...commands.map((_: unknown, i: number) => i + 1), 6, 7])
    for (const reply of replies) expect(reply).toMatchObject({ success: true, exitCode: 0 })
    for (const reply of replies.slice(0, commands.length)) expect(reply.stdout.trim()).toBe('')
    expect(replies[commands.length].stdout.trim().split(/\s+/).sort()).toEqual(['Domain', 'Private', 'Public'])
    const snapshot = replies[commands.length + 1].stdout.trim()
    const parsed = snapshot ? JSON.parse(snapshot) : []
    for (const row of Array.isArray(parsed) ? parsed : [parsed]) {
      expect(row).toMatchObject({ ifIndex: expect.any(Number), interfaceGuid: expect.any(String), alias: expect.any(String),
        ipv6Enabled: expect.any(Boolean), ipv4Dns: expect.any(Array), networkProfiles: expect.any(Array), isCellularOrTethering: expect.any(Boolean) })
    }
  }, 25000)
  it('preserves command IDs, outputs and failures while reporting execution cost', () => {
    const requests = [
      { id: 1, script: "Start-Sleep -Milliseconds 75; Write-Output 'READ_ONLY_FIXTURE'" },
      { id: 2, script: "throw 'FIXTURE_FAILURE'" },
      { id: 3, script: "Write-Output 'AFTER_FAILURE'" }
    ]
    const result = spawnSync(shell, ['-NoProfile', '-NoLogo', '-ExecutionPolicy', 'Bypass', '-Command', runner], {
      input: requests.map(item => JSON.stringify(item)).join('\n') + '\n__EXIT__\n',
      encoding: 'utf8', windowsHide: true, timeout: 15000
    })
    expect(result.error).toBeUndefined()
    expect(result.status).toBe(0)
    const replies = result.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line))
    expect(replies.map(item => item.id)).toEqual([1, 2, 3])
    expect(replies[0]).toMatchObject({ success: true, exitCode: 0 })
    expect(replies[0].stdout).toContain('READ_ONLY_FIXTURE')
    expect(replies[1]).toMatchObject({ success: false, exitCode: 1, stderr: 'FIXTURE_FAILURE' })
    expect(replies[2].stdout).toContain('AFTER_FAILURE')
    expect(replies[2].exitCode).toBe(0)
    for (const reply of replies) {
      expect(Number.isFinite(reply.executionMs)).toBe(true)
      expect(reply.executionMs).toBeGreaterThanOrEqual(0)
    }
    expect(replies[0].executionMs).toBeGreaterThanOrEqual(65)
  // The child has a 15s native timeout; let it report before the outer harness expires.
  }, 20_000)
})
