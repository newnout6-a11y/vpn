// AT-02-004/005 / F-191: exercise real exit-proof functions with fake native probes.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'
import { RecoveryWorkerError } from './recoveryPsWorker'

const source = ts.createSourceFile('tunController.ts', readFileSync(join(process.cwd(), 'src/main/tunController.ts'), 'utf8'), ts.ScriptTarget.Latest, true)
function load<T>(name: string, dependencies: Record<string, unknown>): T {
  const node = source.statements.find(n => ts.isFunctionDeclaration(n) && n.name?.text === name)
  if (!node) throw new Error(`Missing production function ${name}`)
  const text = node.getText(source).replace(/^export /, '')
  const js = ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
  return new Function(...Object.keys(dependencies), `${js};return ${name}`)(...Object.values(dependencies))
}

describe('runtime exit proof', () => {
  it.each([{ success: false, error: 'native refused', candidates: 0, killed: 0 },
    { success: true, candidates: 2, killed: 1 }])('rejects failed/partial native termination: %j', async result => {
    const kill = load<() => Promise<void>>('killOwnedRuntimeProcesses', { killOwnedTunRuntimeProcesses: async () => result })
    await expect(kill()).rejects.toThrow()
  })
  it('allows successful termination while still requiring a separate exit proof', async () => {
    const kill = load<() => Promise<void>>('killOwnedRuntimeProcesses', { killOwnedTunRuntimeProcesses: async () => ({ success: true, candidates: 1, killed: 1 }) })
    await expect(kill()).resolves.toBeUndefined()
    const probe = vi.fn(async () => { throw new Error('probe denied') })
    const wait = load<() => Promise<boolean>>('waitForOwnedRuntimeToExit', { isOwnedTunRuntimeRunning: probe })
    await expect(wait()).rejects.toThrow('probe denied')
    expect(probe).toHaveBeenCalledWith(true)
  })
  it.each(['', 'garbage', 'false\nwarning', 'native error'])('never treats an invalid/failed probe as proof of absence: %j', async output => {
    const probe = load<(strict: boolean) => Promise<boolean>>('isOwnedTunRuntimeRunning', {
      process: { platform: 'win32' }, getTunRuntimeDir: () => 'fixture', RUNTIME_EXE_NAME: 'owned.exe',
      RecoveryWorkerError, executeRecoveryOperation: async () => { throw new RecoveryWorkerError('unavailable', 'fixture fallback') },
      psSingleQuote: (value: string) => `'${value}'`, logEvent: vi.fn(),
      runPowerShell: async () => { if (output === 'native error') throw new Error(output); return output }
    })
    await expect(probe(true)).rejects.toThrow(output === 'native error' ? output : 'Owned runtime status response is invalid')
  })
  it.each([['true', true], ['false\r\n', false]])('accepts only an exact native boolean: %j', async (output, expected) => {
    const native = vi.fn(async (..._args: any[]) => output)
    const probe = load<(strict: boolean) => Promise<boolean>>('isOwnedTunRuntimeRunning', {
      process: { platform: 'win32' }, getTunRuntimeDir: () => 'fixture', RUNTIME_EXE_NAME: 'owned.exe',
      RecoveryWorkerError, executeRecoveryOperation: async () => { throw new RecoveryWorkerError('unavailable', 'fixture fallback') },
      psSingleQuote: (value: string) => `'${value}'`, logEvent: vi.fn(), runPowerShell: native
    })
    expect(await probe(true)).toBe(expected)
    expect(native.mock.calls[0][0]).toContain('Get-CimInstance Win32_Process -ErrorAction Stop')
  })
})
