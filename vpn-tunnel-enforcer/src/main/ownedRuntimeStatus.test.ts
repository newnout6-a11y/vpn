// AT-02-001/005, AT-03-007/012: fresh exit evidence and closed transport boundaries.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'
import { RecoveryWorkerError } from './recoveryPsWorker'
import { validateRecoveryRequest, type RecoveryRequest } from './recoveryPsProtocol'

const source = readFileSync(join(process.cwd(), 'src/main/tunController.ts'), 'utf8')
const ast = ts.createSourceFile('tunController.ts', source, ts.ScriptTarget.Latest, true)
function compile(name: string) {
  const node = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === name)
  if (!node) throw new Error(`Production function not found: ${name}`)
  return ts.transpileModule(node.getText(ast).replace(/^export /, '') + `\nreturn ${name};`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022 }
  }).outputText
}
const runtimeDir = 'C:\\VPNTE-fixture-runtime'
function harness(platform = 'win32') {
  const deps = {
    process: { platform },
    getTunRuntimeDir: () => runtimeDir,
    executeRecoveryOperation: vi.fn(async (_request: RecoveryRequest, _deadline: number) => 'false'),
    RecoveryWorkerError,
    RUNTIME_EXE_NAME: 'vpnte-sing-box.exe',
    psSingleQuote: (text: string) => `'${text.replace(/'/g, "''")}'`,
    runPowerShell: vi.fn(async (_script: string, _deadline: number) => 'false'),
    logEvent: vi.fn()
  }
  const read = new Function(...Object.keys(deps), compile('isOwnedTunRuntimeRunning'))(...Object.values(deps)) as (requireProof?: boolean) => Promise<boolean>
  return { ...deps, read }
}

describe('fresh owned runtime status', () => {
  it('reads changing process state on every call with the original query deadline', async () => {
    const h = harness()
    h.executeRecoveryOperation.mockResolvedValueOnce('true').mockResolvedValueOnce('false').mockResolvedValueOnce('true')
    expect(await h.read(true)).toBe(true)
    expect(await h.read(true)).toBe(false)
    expect(await h.read(true)).toBe(true)
    expect(h.executeRecoveryOperation).toHaveBeenCalledTimes(3)
    expect(h.executeRecoveryOperation).toHaveBeenCalledWith({ op: 'inspect-runtime', runtimeDir }, 5000)
    expect(h.runPowerShell).not.toHaveBeenCalled()
  })
  it('keeps the original conservative fixed reader only on pre-dispatch unavailability', async () => {
    const h = harness()
    h.executeRecoveryOperation.mockRejectedValue(new RecoveryWorkerError('unavailable', 'fixture'))
    expect(await h.read(true)).toBe(false)
    const [script, deadline] = h.runPowerShell.mock.calls[0] as unknown as [string, number]
    expect(deadline).toBe(5000)
    expect(script).toContain("$runtimeDir = 'C:\\VPNTE-fixture-runtime'")
    expect(script).toContain("@('vpnte-sing-box.exe', 'vpnte-etw-sidecar.exe', 'vpnte-xray.exe')")
    expect(script).toContain('Get-CimInstance Win32_Process -ErrorAction Stop')
    expect(script).toContain('StartsWith($runtimeDir, [System.StringComparison]::OrdinalIgnoreCase)')
    expect(script).not.toMatch(/(?:Stop-|Set-|Remove-|Start-|New-)\w+/)
  })
  it.each(['timeout', 'exited', 'protocol', 'rejected', 'busy', 'closed'] as const)('rejects %s rather than claiming exit or replaying', async code => {
    const h = harness()
    const error = new RecoveryWorkerError(code, 'fixture failure')
    h.executeRecoveryOperation.mockRejectedValue(error)
    await expect(h.read(true)).rejects.toBe(error)
    expect(h.runPowerShell).not.toHaveBeenCalled()
    expect(await h.read()).toBe(false) // existing best-effort diagnostic behavior
    expect(h.logEvent).toHaveBeenCalled()
  })
  it('does not fall back on a forged unavailable error', async () => {
    const h = harness()
    h.executeRecoveryOperation.mockRejectedValue(Object.assign(new Error('unknown'), { code: 'unavailable' }))
    await expect(h.read(true)).rejects.toThrow('unknown')
    expect(h.runPowerShell).not.toHaveBeenCalled()
  })
  it.each(['', 'unknown', 'false\ntrue', '{"running":false}', 'not false'])('rejects invalid worker evidence: %j', async value => {
    const h = harness()
    h.executeRecoveryOperation.mockResolvedValue(value)
    await expect(h.read(true)).rejects.toThrow('Owned runtime status response is invalid')
    expect(h.runPowerShell).not.toHaveBeenCalled()
  })
  it('rejects invalid fallback evidence and propagates a failed query', async () => {
    const h = harness()
    h.executeRecoveryOperation.mockRejectedValue(new RecoveryWorkerError('unavailable', 'fixture'))
    h.runPowerShell.mockResolvedValue('not a result')
    await expect(h.read(true)).rejects.toThrow('Owned runtime status response is invalid')
    h.runPowerShell.mockRejectedValue(new Error('CIM query failed'))
    await expect(h.read(true)).rejects.toThrow('CIM query failed')
  })
  it('skips Windows observation on another platform', async () => {
    const h = harness('linux')
    expect(await h.read(true)).toBe(false)
    expect(h.executeRecoveryOperation).not.toHaveBeenCalled()
    expect(h.runPowerShell).not.toHaveBeenCalled()
  })
  it('does not route process termination through the readonly operation', async () => {
    const h = harness()
    h.runPowerShell.mockResolvedValue('{"candidates":1,"killed":1,"names":["vpnte-sing-box.exe"]}')
    const kill = new Function(...Object.keys(h), compile('killOwnedTunRuntimeProcesses'))(...Object.values(h)) as () => Promise<unknown>
    expect(await kill()).toMatchObject({ success: true, candidates: 1, killed: 1 })
    expect(h.executeRecoveryOperation).not.toHaveBeenCalled()
    expect(h.runPowerShell.mock.calls[0][0]).toContain('Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop')
  })
  it('keeps fresh proof in the wait loop and after its deadline', async () => {
    const isOwnedTunRuntimeRunning = vi.fn(async (_proof: boolean) => true).mockResolvedValueOnce(true).mockResolvedValueOnce(false)
    const wait = new Function('Date', 'Promise', 'setTimeout', 'isOwnedTunRuntimeRunning', compile('waitForOwnedRuntimeToExit'))(
      { now: () => 0 }, Promise, (fn: () => void) => fn(), isOwnedTunRuntimeRunning
    ) as (deadline: number) => Promise<boolean>
    expect(await wait(1)).toBe(true)
    expect(isOwnedTunRuntimeRunning.mock.calls).toEqual([[true], [true]])
    isOwnedTunRuntimeRunning.mockResolvedValueOnce(true)
    expect(await wait(0)).toBe(false)
    expect(isOwnedTunRuntimeRunning).toHaveBeenLastCalledWith(true)
    isOwnedTunRuntimeRunning.mockRejectedValueOnce(new Error('unproven'))
    await expect(wait(0)).rejects.toThrow('unproven')
  })
  it('validates a directory as data, excluding scripts, expanded fields and unsafe path forms', () => {
    for (const runtimeDir of ['C:\\VPNTE-fixture-runtime', 'c:\\Users\\Fixture\\VPN Runtime', "C:\\Fixture's\\Runtime"]) {
      expect(() => validateRecoveryRequest({ op: 'inspect-runtime', runtimeDir })).not.toThrow()
    }
    for (const request of [
      { op: 'inspect-runtime', runtimeDir, script: 'Get-Process' },
      { op: 'inspect-runtime', runtimeDir, names: ['arbitrary.exe'] },
      { op: 'INSPECT-RUNTIME', runtimeDir },
      ...['', 'relative', '\\\\server\\share', 'C:/runtime', 'C:\\..\\runtime', 'C:\\.\\runtime', 'C:\\runtime:stream', 'C:\\runtime\n', 'C:\\"runtime', 'C:\\' + 'x'.repeat(2048)].map(runtimeDir => ({ op: 'inspect-runtime', runtimeDir }))
    ]) expect(() => validateRecoveryRequest(request as RecoveryRequest)).toThrow('Invalid recovery worker request')
  })
  it('forwards the deadline to the worker and refuses invalid deadlines before acquiring it', async () => {
    const workerSource = readFileSync(join(process.cwd(), 'src/main/recoveryPsWorker.ts'), 'utf8')
    const workerAst = ts.createSourceFile('recoveryPsWorker.ts', workerSource, ts.ScriptTarget.Latest, true)
    const node = workerAst.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'executeRecoveryOperation')
    if (!node) throw new Error('Production transport wrapper not found')
    const compiled = ts.transpileModule(node.getText(workerAst).replace(/^export /, '') + '\nreturn executeRecoveryOperation;', {
      compilerOptions: { target: ts.ScriptTarget.ES2022 }
    }).outputText
    const execute = vi.fn(async (_request: RecoveryRequest, _deadline: number) => 'false')
    const getWorker = vi.fn(async () => ({ execute }))
    const send = new Function('validateRecoveryRequest', 'getWorker', 'performance', 'logEvent', compiled)(
      validateRecoveryRequest, getWorker, performance, vi.fn()
    ) as (request: RecoveryRequest, deadline?: number) => Promise<string>
    const request = { op: 'inspect-runtime' as const, runtimeDir }
    for (const deadline of [0, -1, NaN, Infinity, 30001]) await expect(send(request, deadline)).rejects.toThrow('Invalid recovery worker deadline')
    expect(getWorker).not.toHaveBeenCalled()
    expect(await send(request, 5000)).toBe('false')
    expect(execute).toHaveBeenLastCalledWith(request, 5000)
    expect(await send(request)).toBe('false')
    expect(execute).toHaveBeenLastCalledWith(request, 15000)
  })
})
