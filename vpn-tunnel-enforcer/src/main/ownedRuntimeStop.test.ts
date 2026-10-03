// AT-02-001/005 / AT-03-007/012: stop dispatch is separate from fresh exit proof.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'
import { RecoveryWorkerError } from './recoveryPsWorker'
import { OWNED_RUNTIME_STOP_SCRIPT, validateRecoveryRequest, type RecoveryRequest } from './recoveryPsProtocol'
const source = ts.createSourceFile('tunController.ts', readFileSync(join(process.cwd(), 'src/main/tunController.ts'), 'utf8'), ts.ScriptTarget.Latest, true)
const node = source.statements.find(n => ts.isFunctionDeclaration(n) && n.name?.text === 'killOwnedTunRuntimeProcesses')
if (!node) throw new Error('Production runtime stop missing')
const js = ts.transpileModule(node.getText(source).replace(/^export /, '') + '\nreturn killOwnedTunRuntimeProcesses;', { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
const runtimeDir = 'C:\\VPNTE-fixture-runtime'
const reply = { candidates: 1, killed: 1, names: ['vpnte-sing-box.exe'] }
function harness(platform = 'win32') {
  const deps = { process: { platform }, getTunRuntimeDir: () => runtimeDir,
    executeRecoveryOperation: vi.fn(async (_request: RecoveryRequest, _deadline: number) => JSON.stringify(reply)),
    RecoveryWorkerError, OWNED_RUNTIME_STOP_SCRIPT,
    psSingleQuote: (value: string) => `'${value.replace(/'/g, "''")}'`,
    runPowerShell: vi.fn(async (_script: string, _deadline: number) => JSON.stringify(reply)), logEvent: vi.fn() }
  return { ...deps, stop: new Function(...Object.keys(deps), js)(...Object.values(deps)) as () => Promise<any> }
}
describe('closed owned runtime stop dispatch', () => {
  it('uses the existing worker with the original deadline and only fixed request fields', async () => {
    const h = harness()
    expect(await h.stop()).toEqual({ success: true, ...reply })
    expect(h.executeRecoveryOperation).toHaveBeenCalledExactlyOnceWith({ op: 'stop-runtime', runtimeDir }, 8000)
    expect(h.runPowerShell).not.toHaveBeenCalled()
  })
  it('falls back only when the worker was unavailable before dispatch', async () => {
    const h = harness(); h.executeRecoveryOperation.mockRejectedValue(new RecoveryWorkerError('unavailable', 'fixture'))
    expect((await h.stop()).success).toBe(true)
    expect(h.runPowerShell).toHaveBeenCalledExactlyOnceWith(`$runtimeDir = '${runtimeDir}'\n${OWNED_RUNTIME_STOP_SCRIPT}`, 8000)
  })
  it.each(['timeout', 'exited', 'protocol', 'rejected', 'busy', 'closed'] as const)('does not replay after %s', async code => {
    const h = harness(); h.executeRecoveryOperation.mockRejectedValue(new RecoveryWorkerError(code, 'unknown native result'))
    expect(await h.stop()).toMatchObject({ success: false })
    expect(h.runPowerShell).not.toHaveBeenCalled()
  })
  it('does not replay a forged unavailable error', async () => {
    const h = harness(); h.executeRecoveryOperation.mockRejectedValue(Object.assign(new Error('unknown'), { code: 'unavailable' }))
    expect((await h.stop()).success).toBe(false)
    expect(h.runPowerShell).not.toHaveBeenCalled()
  })
  it.each(['', '{}', 'null', 'garbage', ...[
    { ...reply, candidates: '1' }, { ...reply, killed: -1 }, { ...reply, killed: 2 },
    { ...reply, candidates: 0 }, { ...reply, names: [] }, { ...reply, names: ['foreign.exe'] },
    { ...reply, names: [null] }, { ...reply, exitProven: true }
  ].map(value => JSON.stringify(value))])('rejects malformed stop evidence: %s', async value => {
    const h = harness(); h.executeRecoveryOperation.mockResolvedValue(value)
    expect((await h.stop()).success).toBe(false)
    expect(h.runPowerShell).not.toHaveBeenCalled()
  })
  it('returns partial termination for the lifecycle owner to reject', async () => {
    const h = harness(); h.executeRecoveryOperation.mockResolvedValue(JSON.stringify({ candidates: 2, killed: 1, names: ['vpnte-xray.exe'] }))
    expect(await h.stop()).toEqual({ success: true, candidates: 2, killed: 1, names: ['vpnte-xray.exe'] })
  })
  it('does no native work on another platform', async () => {
    const h = harness('linux'); expect(await h.stop()).toEqual({ success: true, candidates: 0, killed: 0, names: [] })
    expect(h.executeRecoveryOperation).not.toHaveBeenCalled()
  })
  it.each([
    { op: 'stop-runtime', runtimeDir: 'relative' }, { op: 'stop-runtime', runtimeDir: 'C:\\..\\runtime' },
    { op: 'stop-runtime', runtimeDir, pid: 1 }, { op: 'stop-runtime', runtimeDir, names: ['foreign.exe'] },
    { op: 'stop-runtime', runtimeDir, script: 'Stop-Process' }
  ])('validates the closed request in TypeScript too: %j', request => {
    expect(() => validateRecoveryRequest(request as RecoveryRequest)).toThrow()
  })
})
