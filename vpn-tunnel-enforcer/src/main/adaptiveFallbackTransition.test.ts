// AT-10-003 / AT-10-004 / AT-10-006 / AT-07-012: execute the production
// entrypoint function with fake runtime boundaries and the real health window.
import { readFileSync } from 'node:fs'
import ts from 'typescript'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { verifyAdaptiveFallback } from './adaptiveVerification'
import { TunnelStateMachine } from './tunnelStateMachine'
import { connectionFailure, type ConnectionStartResult } from '../shared/operation'
import { IPC_ERRORS, type IpcErrorCategory } from '../shared/ipc-result'

function harness() {
  let current = true
  const signal = new AbortController()
  const status = { running: true, startedAt: 1 }
  const tunnelState = new TunnelStateMachine(() => ({ ...status, pid: status.running ? 731 : null, softApplied: false }))
  const deps = {
    connectionFailure,
    tunnelState,
    withProtectedIpTransition: vi.fn(async (options: any) => {
      const result = await options.restart()
      if (result.success && options.isCurrent()) options.onVerified()
      return result
    }),
    verifyAdaptiveFallback,
    tunController: {
      getStatus: () => status,
      areTunRoutesActive: vi.fn(async () => true),
      restartForAdaptiveChange: vi.fn(async (): Promise<ConnectionStartResult> => ({ success: true })),
      stop: vi.fn(async () => { status.running = false; tunnelState.runtimeChanged('adapting'); return { success: true } })
    },
    tunnelHttpProbe: vi.fn(async (): Promise<number | null> => 10),
    serverPicker: { selectProfile: vi.fn() },
    sendToMainWindow: vi.fn(),
    ipMonitor: { clearVpnIp: vi.fn() }
  }
  const source = ts.createSourceFile('index.ts', readFileSync('src/main/index.ts', 'utf8'), ts.ScriptTarget.Latest, true)
  const fn = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'restartAdaptiveWithFreshIp')!
  const text = `let adaptiveTransitionInFlight = null;\n${fn.getText(source)}\nreturn restartAdaptiveWithFreshIp;`
  const js = ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText
  const restart = new Function(...Object.keys(deps), js)(...Object.values(deps))
  return {
    ...deps, signal, status,
    supersede: () => { current = false; signal.abort() },
    run: (sibling = true) => restart('standard', 'fixture', () => current && !signal.signal.aborted, signal.signal,
      sibling ? { id: 'candidate', profile: { name: 'Candidate' } } : undefined) as Promise<{ success: boolean; error?: string }>
  }
}
afterEach(() => vi.useRealTimers())

describe('fallback health before commit', () => {
  it('types a superseded owner before starting native effects (AT-00-004)', async () => {
    const h = harness()
    h.supersede()
    expect(await h.run()).toMatchObject({ success: false, category: 'cancelled', code: 'IPC_CANCELLED' })
    expect(h.tunController.restartForAdaptiveChange).not.toHaveBeenCalled()
  })
  it.each([false, true])('rejects late restart success after ownership is lost, sibling=%s (AT-00-003/004)', async sibling => {
    const h = harness()
    let release!: (result: ConnectionStartResult) => void
    h.tunController.restartForAdaptiveChange.mockImplementationOnce(() => new Promise(resolve => { release = resolve }))
    const pending = h.run(sibling)
    h.supersede()
    release({ success: true })
    expect(await pending).toMatchObject({ success: false, category: 'cancelled', code: 'IPC_CANCELLED' })
    expect(h.tunController.stop).not.toHaveBeenCalled()
    expect(h.serverPicker.selectProfile).not.toHaveBeenCalled()
  })
  it('publishes only after fresh IP proof and the full 2-of-3 stability check', async () => {
    vi.useFakeTimers()
    const h = harness()
    h.tunnelHttpProbe.mockResolvedValueOnce(10).mockResolvedValueOnce(null).mockResolvedValueOnce(20)
    const pending = h.run()
    await vi.advanceTimersByTimeAsync(20_000)
    expect(h.serverPicker.selectProfile).not.toHaveBeenCalled()
    expect(h.sendToMainWindow).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(5_000)
    expect(await pending).toEqual({ success: true })
    expect(h.tunnelHttpProbe).toHaveBeenCalledTimes(3)
    expect(h.serverPicker.selectProfile).toHaveBeenCalledExactlyOnceWith('candidate')
    expect(h.sendToMainWindow).toHaveBeenCalledExactlyOnceWith('server-active-changed', { profileId: 'candidate', profileName: 'Candidate' })
    expect(h.tunController.stop).not.toHaveBeenCalled()
  })
  it.each([0, 1])('does not commit %s successful probes and stops with protection preserved', async successes => {
    vi.useFakeTimers()
    const h = harness()
    h.tunnelHttpProbe.mockResolvedValue(null)
    if (successes) h.tunnelHttpProbe.mockResolvedValueOnce(10)
    const pending = h.run()
    await vi.runAllTimersAsync()
    expect(await pending).toMatchObject({ success: false, category: 'network', code: 'IPC_NETWORK_ERROR' })
    expect(h.serverPicker.selectProfile).not.toHaveBeenCalled()
    expect(h.sendToMainWindow).not.toHaveBeenCalled()
    expect(h.tunController.stop).toHaveBeenCalledExactlyOnceWith({ preserveNetworkProtection: true })
    expect(h.tunnelState.snapshot).toMatchObject({ state: 'unknown', transition: null, cleanupRequired: true })
    expect(h.tunnelState.canStart()).toBe(true)
    expect(h.ipMonitor.clearVpnIp).toHaveBeenCalledOnce()
  })
  it('does not publish without fresh route/IP evidence even if local runtime started', async () => {
    const h = harness()
    h.withProtectedIpTransition.mockImplementation(async options => options.restart())
    expect((await h.run()).success).toBe(false)
    expect(h.tunnelHttpProbe).not.toHaveBeenCalled()
    expect(h.serverPicker.selectProfile).not.toHaveBeenCalled()
    expect(h.tunController.stop).toHaveBeenCalledExactlyOnceWith({ preserveNetworkProtection: true })
  })
  it('ends reconnecting even if stopping the rejected fallback throws', async () => {
    const h = harness()
    h.withProtectedIpTransition.mockImplementation(async options => options.restart())
    h.tunController.stop.mockImplementationOnce(async () => {
      h.tunnelState.runtimeChanged('adapting')
      throw new Error('native stop denied')
    })
    await expect(h.run()).rejects.toThrow('native stop denied')
    expect(h.tunnelState.snapshot).toMatchObject({ state: 'unknown', transition: null, cleanupRequired: true })
  })
  it.each(Object.keys(IPC_ERRORS) as IpcErrorCategory[])('preserves a native %s failure without verification or publication (AT-00-004)', async category => {
    const h = harness()
    const failure = connectionFailure(category)
    h.tunController.restartForAdaptiveChange.mockResolvedValue(failure)
    expect(await h.run()).toEqual(failure)
    expect(h.tunnelHttpProbe).not.toHaveBeenCalled()
    expect(h.serverPicker.selectProfile).not.toHaveBeenCalled()
    expect(h.tunController.stop).not.toHaveBeenCalled()
  })
  it('manual selection aborts the window without stopping or publishing a newer owner', async () => {
    vi.useFakeTimers()
    const h = harness(), pending = h.run()
    await vi.advanceTimersByTimeAsync(100)
    h.supersede()
    expect(await pending).toMatchObject({ success: false, category: 'cancelled', code: 'IPC_CANCELLED' })
    expect(h.serverPicker.selectProfile).not.toHaveBeenCalled()
    expect(h.tunController.stop).not.toHaveBeenCalled()
    expect(h.ipMonitor.clearVpnIp).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })
  it('discards late health samples from a replaced runtime', async () => {
    vi.useFakeTimers()
    const h = harness()
    let release!: (sample: number) => void
    h.tunnelHttpProbe.mockImplementation(() => new Promise(resolve => { release = resolve }))
    const pending = h.run()
    await vi.advanceTimersByTimeAsync(20_000)
    h.status.startedAt = 2
    release(10)
    expect(await pending).toMatchObject({ success: false, category: 'cancelled', code: 'IPC_CANCELLED' })
    expect(h.tunnelHttpProbe).toHaveBeenCalledOnce()
    expect(h.serverPicker.selectProfile).not.toHaveBeenCalled()
    expect(h.tunController.stop).not.toHaveBeenCalled()
  })
  it('keeps compatibility-mode restarts outside sibling publication', async () => {
    const h = harness()
    expect(await h.run(false)).toEqual({ success: true })
    expect(h.tunnelHttpProbe).not.toHaveBeenCalled()
    expect(h.serverPicker.selectProfile).not.toHaveBeenCalled()
  })
})
