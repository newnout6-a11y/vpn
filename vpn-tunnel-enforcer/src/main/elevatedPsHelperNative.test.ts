// AT-00-005 / AT-03-007: native transport evidence, no network or registry mutations.
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const source = readFileSync(join(process.cwd(), 'src/main/elevatedPsHelper.ts'), 'utf8')
const marker = 'const PS_RUNNER_SCRIPT = `'
const begin = source.indexOf(marker)
const end = source.indexOf('\n`', begin + marker.length)
if (begin < 0 || end < 0) throw new Error('Production helper runner not found')
const runner = source.slice(begin + marker.length, end)
const shell = process.env.VPNTE_PWSH || 'powershell.exe'

describe.skipIf(process.platform !== 'win32')('native helper timing envelope', () => {
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
