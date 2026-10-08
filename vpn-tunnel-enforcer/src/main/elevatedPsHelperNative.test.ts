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
  it('executes fixed warm-up and fresh native reads in the same production runner', () => {
    const requests = commands.map((command: { script: string }, index: number) => ({ id: index + 1, script: command.script }))
    requests.push({ id: 6, script: "Get-NetFirewallProfile -Profile Domain,Private,Public -ErrorAction Stop | ForEach-Object { [string]$_.Name }" })
    requests.push({ id: 7, script: PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT })
    const result = spawnSync(shell, ['-NoProfile', '-NoLogo', '-NonInteractive', '-Command', runner], {
      input: requests.map((item: unknown) => JSON.stringify(item)).join('\n') + '\n__EXIT__\n',
      encoding: 'utf8', windowsHide: true, timeout: 20000
    })
    expect(result.error).toBeUndefined()
    expect(result.status).toBe(0)
    const replies = result.stdout.trim().split(/\r?\n/).map(line => JSON.parse(line))
    expect(replies.map(item => item.id)).toEqual([1, 2, 3, 4, 5, 6, 7])
    for (const reply of replies) expect(reply).toMatchObject({ success: true, exitCode: 0 })
    for (const reply of replies.slice(0, 5)) expect(reply.stdout.trim()).toBe('')
    expect(replies[5].stdout.trim().split(/\s+/).sort()).toEqual(['Domain', 'Private', 'Public'])
    const snapshot = replies[6].stdout.trim()
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
  })
})
