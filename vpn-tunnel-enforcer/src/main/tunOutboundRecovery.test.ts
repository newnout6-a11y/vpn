// AT-00-003 / AT-00-007 / AT-02-003 / AT-02-011: actual native-exit callback
// and actual recovery timer, with fake time and no operating-system effects.
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import { afterEach, describe, expect, it, vi } from 'vitest'

function gate() {
  let resolve!: () => void
  const promise = new Promise<void>(done => { resolve = done })
  return { promise, resolve }
}
const source = ts.createSourceFile('tunController.ts', readFileSync('src/main/tunController.ts', 'utf8'), ts.ScriptTarget.Latest, true)
let callback: string | undefined
function visit(node: ts.Node): void {
  if (ts.isVariableDeclaration(node) && node.name.getText(source) === 'onExit') callback = `const ${node.getText(source)}`
  ts.forEachChild(node, visit)
}
visit(source)
if (!callback) throw new Error('Production native-exit callback not found')
const callbackText = callback

function harness(switchDrain: Promise<void> | null = null) {
  const controller = new AbortController()
  const previous = { mode: 'directVpn', vpnProfile: { name: 'Previous' } }
  const settings = { autoRestartOnCrash: true }
  const deps = {
    previous, switchDrain, controller,
    settingsStore: { get: () => settings },
    logEvent: vi.fn(), recordForensicTunEvent: vi.fn(), stopProxyWatchdog: vi.fn(), notifyStatus: vi.fn(), notify: vi.fn(),
    rollbackTunNetworkBaselineOrThrow: vi.fn(async () => {}),
    rollbackPhysicalAdapterLockdownIfApplied: vi.fn(async () => {}),
    repairOrphanedPhysicalAdapterDns: vi.fn(async () => {}),
    disableKillSwitchIfActive: vi.fn(async () => {}), stopXray: vi.fn(async () => {}),
    clearRestartTimers: vi.fn(),
    tunController: { start: vi.fn(async (_options: unknown) => ({ success: true })) }
  }
  const text = `
    let currentStatus={running:true,pid:4100,startedAt:1234},mode='directVpn',lastSingBoxExit=null,restartAttempt=0;
    let userInitiatedStop=false,stopInProgress=false,stopRequested=false,resolved=true,startInProgress=false;
    let adapterLockdownEngaged=true,killSwitchEngaged=true,lastStartOptions=previous;
    let outboundSwitchCompletion=switchDrain,outboundSwitchAbort=controller;
    let recoveryCancelGeneration=0,nativeStartupGeneration=1,nativeGeneration=1,restartTimer=null;
    const startCompletion=Promise.resolve(),RESTART_BACKOFF_MS=[2000,5000,10000];
    ${callbackText}
    return {exit:onExit,stop:()=>{userInitiatedStop=true;stopRequested=true;recoveryCancelGeneration++},
      newGeneration:()=>{nativeStartupGeneration++},newStart:()=>{startInProgress=true},
      running:()=>{currentStatus.running=true},cancelGeneration:()=>{recoveryCancelGeneration++},
      status:()=>currentStatus};
  `
  const compiled = ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText
  const api = new Function(...Object.keys(deps), compiled)(...Object.values(deps)) as {
    exit: () => void; stop: () => void; newGeneration: () => void; newStart: () => void; running: () => void;
    cancelGeneration: () => void; status: () => { running: boolean; pid: number | null }
  }
  return { ...deps, ...api, settings }
}

afterEach(() => vi.useRealTimers())

describe('retained switch hands native crash recovery to its current owner', () => {
  it('aborts candidate work immediately and waits for its physical cleanup before recovery start', async () => {
    vi.useFakeTimers()
    const drain = gate(), h = harness(drain.promise)
    h.exit()
    expect(h.controller.signal.aborted).toBe(true)
    expect(h.status()).toMatchObject({ running: false, pid: null })
    await vi.advanceTimersByTimeAsync(2000)
    expect(h.tunController.start).not.toHaveBeenCalled()
    expect(h.disableKillSwitchIfActive).not.toHaveBeenCalled()
    expect(h.rollbackPhysicalAdapterLockdownIfApplied).not.toHaveBeenCalled()
    drain.resolve()
    await vi.advanceTimersByTimeAsync(0)
    expect(h.tunController.start).toHaveBeenCalledExactlyOnceWith(h.previous)
  })

  it.each(['stop', 'newGeneration', 'newStart', 'running', 'cancelGeneration', 'setting-off'] as const)(
    'revalidates %s after waiting for the cancelled switch to settle', async superseded => {
      vi.useFakeTimers()
      const drain = gate(), h = harness(drain.promise)
      h.exit()
      await vi.advanceTimersByTimeAsync(2000)
      if (superseded === 'setting-off') h.settings.autoRestartOnCrash = false
      else h[superseded]()
      drain.resolve()
      await vi.advanceTimersByTimeAsync(0)
      expect(h.tunController.start).not.toHaveBeenCalled()
      expect(h.disableKillSwitchIfActive).not.toHaveBeenCalled()
    }
  )

  it('preserves the existing crash backoff when no retained switch is pending', async () => {
    vi.useFakeTimers()
    const h = harness()
    h.exit()
    await vi.advanceTimersByTimeAsync(1999)
    expect(h.tunController.start).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    expect(h.tunController.start).toHaveBeenCalledExactlyOnceWith(h.previous)
  })
})
