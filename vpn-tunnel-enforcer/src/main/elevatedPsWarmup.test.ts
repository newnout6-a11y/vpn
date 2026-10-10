// AT-00-005 / AT-02-005 / AT-03-012: production preparation with fake native boundaries.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { afterEach, describe, expect, it, vi } from 'vitest'
vi.mock('./admin', () => ({ isProcessElevated: vi.fn(async () => false) }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
const source = readFileSync(join(process.cwd(), 'src/main/elevatedPsHelper.ts'), 'utf8')
const ast = ts.createSourceFile('elevatedPsHelper.ts', source, ts.ScriptTarget.Latest, true)
const success = { stdout: '', stderr: '', exitCode: 0 }
afterEach(() => vi.useRealTimers())
function harness() {
  const fn = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'warmElevatedPsHelper')
  const commands = ast.statements.find(node => ts.isVariableStatement(node) && node.declarationList.declarations.some(decl => decl.name.getText(ast) === 'HELPER_WARMUP_COMMANDS'))
  if (!fn || !commands) throw new Error('Production helper warm-up not found')
  const pendingCommands = new Map()
  const deps = { execElevatedPs: vi.fn(async () => success), logEvent: vi.fn(), isElevatedPsHelperRunning: vi.fn(() => true), pendingCommands }
  const compiled = ts.transpileModule(commands.getText(ast) + '\n' + fn.getText(ast).replace(/^export\s+/, '') + `
    return { warm: warmElevatedPsHelper, commands: HELPER_WARMUP_COMMANDS, setOwner(value) { helperProcess = value; } };`, {
    compilerOptions: { target: ts.ScriptTarget.ES2022 }
  }).outputText
  const fixture = new Function('helperProcess', ...Object.keys(deps), compiled)({}, ...Object.values(deps))
  return { ...deps, ...fixture }
}
describe('same helper fixed read-only warm-up', () => {
  it.skipIf(process.platform !== 'win32')('keeps each warm-up within the existing helper policy', async () => {
    const h = harness()
    const { execElevatedPs } = await import('./elevatedPsHelper')
    for (const command of h.commands) {
      await expect(execElevatedPs(command.script, 15000, command.policy))
        .rejects.toMatchObject({ code: 'elevated-helper-unavailable' })
    }
  })
  it('runs bounded fixed commands in policy order and discards native data', async () => {
    const h = harness()
    await h.warm()
    expect(h.execElevatedPs).toHaveBeenCalledTimes(5)
    expect(h.execElevatedPs).toHaveBeenNthCalledWith(1, h.commands[0].script, 15000, 'firewall-killswitch')
    expect(h.commands[0].script).toContain('Get-NetFirewallProfile')
    expect(h.commands.slice(1).map((command: {script: string}) => command.script.match(/Import-Module (\w+)/)?.[1]))
      .toEqual(['NetAdapter', 'DnsClient', 'NetTCPIP', 'NetConnection'])
    for (const command of h.commands.slice(1)) expect(command.script).toContain('Get-NetAdapter')
    for (const command of h.commands) {
      expect(command.script).toContain('Out-Null')
      expect(command.script).not.toMatch(/\b(?:Set-|Disable-|Enable-|Remove-|New-)\w+|reg\s+add|netsh/i)
    }
    expect(h.logEvent.mock.calls.filter((call: unknown[]) => call[2] === 'warm-up timing')).toHaveLength(5)
  })
  it('resumes after admitted native work drains instead of abandoning all imports (AT-02-005)', async () => {
    vi.useFakeTimers()
    const h = harness(); h.pendingCommands.set(1, {})
    const pending = h.warm()
    await vi.advanceTimersByTimeAsync(500)
    expect(h.execElevatedPs).not.toHaveBeenCalled()
    h.pendingCommands.clear()
    await vi.advanceTimersByTimeAsync(100)
    await pending
    expect(h.execElevatedPs).toHaveBeenCalledTimes(5)
    expect(vi.getTimerCount()).toBe(0)
  })
  it('does not start a missing helper', async () => {
    const h = harness(); h.setOwner(null)
    await h.warm()
    expect(h.execElevatedPs).not.toHaveBeenCalled()
  })
  it('yields between module imports when a connect command arrives (AT-02-005)', async () => {
    vi.useFakeTimers()
    const h = harness()
    h.execElevatedPs.mockImplementationOnce(async () => success)
    h.execElevatedPs.mockImplementationOnce(async () => { h.pendingCommands.set(99, {}); return success })
    const pending = h.warm()
    await vi.advanceTimersByTimeAsync(300)
    expect(h.execElevatedPs).toHaveBeenCalledTimes(2)
    h.pendingCommands.clear()
    await vi.advanceTimersByTimeAsync(100)
    await pending
    expect(h.execElevatedPs.mock.calls.map((call: unknown[]) => call[0])).toEqual(h.commands.map((command: { script: string }) => command.script))
    expect(vi.getTimerCount()).toBe(0)
  })
  it('defers during a whole connection or cancellation even when its native queue is empty (AT-02-005)', async () => {
    vi.useFakeTimers()
    const h = harness(); let busy = true
    const pending = h.warm(() => busy)
    await vi.advanceTimersByTimeAsync(500)
    expect(h.execElevatedPs).not.toHaveBeenCalled()
    busy = false
    await vi.advanceTimersByTimeAsync(100)
    await pending
    expect(h.execElevatedPs).toHaveBeenCalledTimes(5)
  })
  it.each([null, {}])('drops deferred warm-up when its original helper is stopped/replaced: %j (AT-03-007)', async owner => {
    vi.useFakeTimers()
    const h = harness(); h.pendingCommands.set(1, {})
    const pending = h.warm()
    h.setOwner(owner)
    await vi.advanceTimersByTimeAsync(100)
    await pending
    expect(h.execElevatedPs).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })
  it('does not dispatch into a stopped helper', async () => {
    const h = harness(); h.isElevatedPsHelperRunning.mockReturnValue(false)
    await h.warm()
    expect(h.execElevatedPs).not.toHaveBeenCalled()
  })
  it.each([null, {}])('does not continue when helper ownership changes: %j', async owner => {
    const h = harness()
    h.execElevatedPs.mockImplementationOnce(async () => { h.setOwner(owner); return success })
    await h.warm()
    expect(h.execElevatedPs).toHaveBeenCalledOnce()
  })
  it.each(['throw', 'exitCode'])('reports %s failure without native payloads', async kind => {
    const h = harness()
    if (kind === 'throw') h.execElevatedPs.mockRejectedValueOnce(new Error('PRIVATE_NATIVE_ERROR'))
    else h.execElevatedPs.mockResolvedValueOnce({ stdout: 'PRIVATE_STDOUT', stderr: 'PRIVATE_STDERR', exitCode: 1 })
    await expect(h.warm()).resolves.toBeUndefined()
    expect(h.execElevatedPs).toHaveBeenCalledTimes(5)
    expect(h.logEvent).toHaveBeenCalledWith('warn', 'ps-helper', 'fixed read-only warm-up unavailable', { policy: 'firewall-killswitch' })
    expect(h.logEvent.mock.calls.some((call: unknown[]) => call[2] === 'warm-up timing' && (call[3] as any)?.outcome === 'failed')).toBe(true)
    expect(JSON.stringify(h.logEvent.mock.calls)).not.toMatch(/PRIVATE_|stdout|stderr|script/)
  })
})

describe('app preparation order', () => {
  function appStage(guards: Record<string, boolean> = {}) {
    const appSource = readFileSync(join(process.cwd(), 'src/main/index.ts'), 'utf8')
    const begin = appSource.indexOf('const helperStartup = startElevatedPsHelper()')
    const end = appSource.indexOf('createWindow()', begin)
    if (begin < 0 || end < 0) throw new Error('Production helper/recovery preparation stage not found')
    const deps = { startElevatedPsHelper: vi.fn(async () => {}), performCrashRecovery: vi.fn(async () => {}),
      warmElevatedPsHelper: vi.fn(async () => {}), warmRecoveryPsWorker: vi.fn(), logEvent: vi.fn(),
      connectionLifecycle: { busy: Boolean(guards.busy) }, tunController: { getStatus: () => ({ running: Boolean(guards.running) }) },
      isQuitting: Boolean(guards.isQuitting), shutdownInProgress: Boolean(guards.shutdownInProgress) }
    const run = new Function(...Object.keys(deps), 'return async () => {' + appSource.slice(begin, end) + '}')(...Object.values(deps))
    return { ...deps, run }
  }
  it('gives crash recovery priority over warm-up', async () => {
    const h = appStage()
    let finish!: () => void
    h.performCrashRecovery.mockImplementation(() => new Promise(resolve => { finish = resolve }))
    const starting = h.run()
    await Promise.resolve()
    expect(h.warmElevatedPsHelper).not.toHaveBeenCalled()
    finish()
    await starting
    await Promise.resolve()
    expect(h.warmElevatedPsHelper).toHaveBeenCalledOnce()
  })
  it('keeps window preparation independent of unfinished helper warm-up', async () => {
    const h = appStage()
    let finish!: () => void
    h.warmElevatedPsHelper.mockImplementation(() => new Promise(resolve => { finish = resolve }))
    await h.run()
    await Promise.resolve()
    expect(h.warmElevatedPsHelper).toHaveBeenCalledOnce()
    finish()
  })
  it.each(['busy', 'running', 'isQuitting', 'shutdownInProgress'])('pauses both preparations for %s (AT-02-005)', async guard => {
    const h = appStage({ [guard]: true })
    await h.run()
    await Promise.resolve()
    const shouldDefer = (h.warmElevatedPsHelper.mock.calls[0] as unknown[])[0] as () => boolean
    expect(shouldDefer()).toBe(true)
    const recoveryGate = (h.warmRecoveryPsWorker.mock.calls[0] as unknown[])[0] as () => boolean
    expect(recoveryGate()).toBe(true)
  })
  it('allows helper preparation after a full connection lifecycle settles', async () => {
    const h = appStage({ busy: true })
    await h.run()
    await Promise.resolve()
    const shouldDefer = (h.warmElevatedPsHelper.mock.calls[0] as unknown[])[0] as () => boolean
    h.connectionLifecycle.busy = false
    expect(shouldDefer()).toBe(false)
  })
})
