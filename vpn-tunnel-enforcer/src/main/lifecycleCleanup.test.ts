// AT-02-005 / AT-03-007: run production lifecycle bodies with fake OS boundaries.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { isIP } from 'node:net'
import { EventEmitter } from 'node:events'
import ts from 'typescript'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ConnectionLifecycle } from './connectionLifecycle'

function body(file: string, name: string): string {
  const source = ts.createSourceFile(file, readFileSync(join(process.cwd(), 'src/main', file), 'utf8'), ts.ScriptTarget.Latest, true)
  let found: ts.FunctionDeclaration | ts.MethodDeclaration | ts.VariableDeclaration | ts.ArrowFunction | undefined
  function visit(node: ts.Node) {
    if ((ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) && node.name?.getText(source) === name) found = node
    if (ts.isVariableDeclaration(node) && node.name.getText(source) === name && node.initializer && ts.isArrowFunction(node.initializer)) found = node
    if (ts.isCallExpression(node) && node.expression.getText(source) === name && node.arguments[0] && ts.isArrowFunction(node.arguments[0])) found = node.arguments[0]
    ts.forEachChild(node, visit)
  }
  visit(source)
  if (!found) throw new Error(`Missing production function ${name}`)
  return `${ts.isVariableDeclaration(found) ? 'const ' : ''}${found.getText(source)}`
}
function compile<T>(text: string, dependencies: Record<string, unknown>): T {
  const js = ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText
  return new Function(...Object.keys(dependencies), js)(...Object.values(dependencies))
}
const noop = () => vi.fn((..._args: any[]) => {})
const done = () => vi.fn(async () => {})

function protectedRestartHarness() {
  const os = {
    waitForTunRelease: vi.fn(async (_isCancelled: () => boolean, _timeoutMs: number): Promise<string> => 'released'),
    logEvent: noop(), notifyStatus: noop(),
    settingsStore: { get: () => ({ proxyEngine: 'singbox' }) },
    stop: vi.fn(async (): Promise<any> => ({ success: true })),
    start: vi.fn(async (): Promise<any> => ({ success: true }))
  }
  const control = compile<{ restart: () => Promise<any>; cancel: () => void }>(`
let transitionCancelRequested=false,currentStatus={running:false},lastStartOptions=null;
const protectedRestartCallback=null;
const controller={stop,start,${body('tunController.ts','restartProtected')}};
return {restart:()=>controller.restartProtected('fixture',{mode:'directVpn'}),cancel:()=>{transitionCancelRequested=true}};
`, os)
  return { ...os, ...control }
}

describe('protected restart readiness (AT-02-002/004/005 / AT-00-003)', () => {
  it('waits for successful stop and interface release before launching', async () => {
    const h = protectedRestartHarness()
    let release!: (outcome: string) => void
    h.waitForTunRelease.mockReturnValue(new Promise(done => { release = done }))
    const pending = h.restart()
    await vi.waitFor(() => expect(h.waitForTunRelease).toHaveBeenCalledOnce())
    expect(h.stop).toHaveBeenCalledExactlyOnceWith({preserveNetworkProtection:true,preserveLastStartOptions:true})
    expect(h.start).not.toHaveBeenCalled()
    release('released')
    expect(await pending).toMatchObject({success:true})
    expect(h.start).toHaveBeenCalledOnce()
  })
  it('retains protection with an explicit error if release cannot be verified', async () => {
    const h = protectedRestartHarness()
    h.waitForTunRelease.mockResolvedValue('unverified')
    expect(await h.restart()).toMatchObject({success:false,error:expect.stringContaining('не подтверждено')})
    expect(h.start).not.toHaveBeenCalled()
    expect(h.stop).toHaveBeenCalledOnce()
    expect(h.notifyStatus).toHaveBeenCalledWith('error')
  })
  it('finishes cancellation during release with ordinary cleanup and no new start', async () => {
    const h = protectedRestartHarness()
    let release!: (outcome: string) => void
    h.waitForTunRelease.mockReturnValue(new Promise(done => { release = done }))
    const pending = h.restart()
    await vi.waitFor(() => expect(h.waitForTunRelease).toHaveBeenCalledOnce())
    h.cancel()
    expect(h.waitForTunRelease.mock.calls[0][0]()).toBe(true)
    release('cancelled')
    expect(await pending).toMatchObject({success:false,error:'Перезапуск отменён'})
    expect(h.start).not.toHaveBeenCalled()
    expect(h.stop).toHaveBeenCalledTimes(2)
    expect(h.stop.mock.calls[1]).toEqual([])
  })
  it('does not await interface release after a failed process stop', async () => {
    const h = protectedRestartHarness()
    h.stop.mockResolvedValueOnce({success:false,error:'exit not confirmed'})
    expect(await h.restart()).toMatchObject({success:false})
    expect(h.waitForTunRelease).not.toHaveBeenCalled()
    expect(h.start).not.toHaveBeenCalled()
  })
})

function stopHarness(startupController: AbortController | null = null, startupCompletion: Promise<void> | null = null) {
  const state = { runtime: true, upstream: true, watchdog: true, competing: true, baseline: true, firewall: true, adapters: true }
  const os = {
    startupController,
    startupCompletion,
    isOwnedTunRuntimeRunning: vi.fn(async () => false),
    stopXray: vi.fn(async () => { state.upstream = false }), killOwnedRuntimeProcesses: done(),
    waitForOwnedRuntimeToExit: vi.fn(async () => { state.runtime = false; return true }),
    rollbackTunNetworkBaselineIfApplied: vi.fn(async () => { state.baseline = false; return { success: true, message: 'restored' } }),
    disableKillSwitchIfActive: vi.fn(async () => { state.firewall = false; return { success: true, message: 'restored' } }),
    rollbackPhysicalAdapterLockdownIfApplied: vi.fn(async (): Promise<{ rolledBack: boolean; skipped?: boolean }> => { state.adapters = false; return { rolledBack: true } }),
    repairOrphanedPhysicalAdapterDns: vi.fn(async () => ({ repaired: false, adapters: [] })),
    ipMonitor: { suspend: noop(), resume: noop() },
    logEvent: noop(), notify: noop(), notifyStatus: noop(), recordForensicTunEvent: noop(),
    clearRestartTimers: noop(), cancelLeakSelfTest: noop(), stopCompetingTunWatch: vi.fn(() => { state.competing = false }),
    stopProxyWatchdog: vi.fn(() => { state.watchdog = false })
  }
  const stop = compile<((options?: { preserveNetworkProtection?: boolean }) => Promise<any>) & { setRunning(running: boolean): void }>(`
let startInProgress=false,stopRequested=false,stopInProgress=false,userInitiatedStop=false,activeStartAbortController=startupController;
let activeStartCompletion=startupCompletion,activeStopCompletion=null,activeStopPreservesProtection=false;
let recoveryCancelGeneration=0,lastStartOptions=null,restartAttempt=0,transitionCancelRequested=false;
let currentStatus={running:true,mode:'directVpn'},clashApiInfo=null,directProxyPort=null,tunnelProbePort=null;
const controller = {${body('tunController.ts', 'stop')}};
return Object.assign(controller.stop.bind(controller), { setRunning: (running) => { currentStatus.running = running } });
`, os)
  return { stop, ...os, state }
}
function mainHarness(name: 'performShutdownCleanup' | 'stopProtection', session: object | null = null) {
  const os = {
    connectionLifecycle: new ConnectionLifecycle(() => {}),
    tunController: { stop: vi.fn(async (): Promise<any> => ({ success: true, networkCleanup: { baseline: true, firewall: true, adapters: true } })) },
    clearOwnedSecretClipboard: done(), stopXray: done(),
    isOwnedTunRuntimeRunning: vi.fn(async () => false),
    killOwnedTunRuntimeProcesses: vi.fn(async () => ({ success: true, candidates: 0, killed: 0, names: [] })), externalProxy: { stopAll: done() },
    rollbackTunNetworkBaselineIfApplied: vi.fn(async () => ({ success: true })),
    disableKillSwitchIfActive: vi.fn(async () => ({ success: true })),
    rollbackPhysicalAdapterLockdownIfApplied: vi.fn(async (): Promise<{ rolledBack: boolean; skipped?: boolean }> => ({ rolledBack: true })),
    repairOrphanedPhysicalAdapterDns: done(), logEvent: noop(), stopElevatedPsHelper: noop(), stopRecoveryPsWorker: done(),
    autoconfig: { isApplied: vi.fn(async () => false), rollback: vi.fn(async () => ({ env: true })) },
    stopServerGroupAutoRefresh: noop(), stopBackgroundTrafficHistory: noop(), stopTrafficConnectionSampler: noop(),
    rollbackSoftAutoconfigIfApplied: done(), stopPeriodicSnapshots: noop(), stopPeriodicLeakTest: noop(), stopNetworkChangeWatcher: noop(),
    stopTrafficForensicsSession: vi.fn(async (): Promise<any> => ({ running: false, cleanupPending: false })),
    ipMonitor: { clearVpnIp: noop() }, trafficMonitor: { stop: noop(), getCurrentStats: vi.fn(() => ({ downloadBytes: 123 })) },
    session, sessionEgressEvidence: () => ({ egressIp: '203.0.113.1' }), makeOutcome: (kind: string, evidence: object) => ({ kind, evidence }), writeSessionEntry: noop(),
    getLocationPrivacyStatus: vi.fn(async () => ({ applied: false })), rollbackLocationPrivacy: done(),
    settingsStore: { save: noop() }, refreshTrayState: noop(), captureSnapshot: done()
  }
  const run = compile<((reason?: string) => Promise<any>) & { state(): { session: object | null; stopping: boolean } }>(`
let shutdownInProgress=false,currentSession=session,stopInProgress=false,adaptiveVerificationGeneration=0,activeAdaptiveContext=null;
${body('index.ts', 'closeSession')}
${body('index.ts', name)}
return Object.assign(${name}, {state:()=>({session:currentSession,stopping:stopInProgress})});
`, os)
  return { run, ...os }
}

function startupExitHarness(pollCompletion: Promise<void> | null = null) {
  const os = {
    pollCompletion, logEvent: noop(), recordForensicTunEvent: noop(), stopProxyWatchdog: noop(),
    stopXray: done(), disableKillSwitchIfActive: done(), rollbackEarlyAdapterLockdown: done(), notifyStatus: noop(),
    finishResult: noop()
  }
  const run = compile<{ exit: (error: Error) => void; settled: () => Promise<unknown[]>; pollCompensating: () => void }>(`
let currentStatus={running:false},mode='directVpn',restartAttempt=0,lastSingBoxExit=null;
let userInitiatedStop=false,stopInProgress=false,resolved=false,startAbortedReason=null;
let startupCompensationStarted=false;
let settleFirewallAdapter=null,pendingKillSwitch=null,adapterLockdownPromise=null;
let startupPollCompletion=pollCompletion;const startupCleanupTasks=[];
function finish(result){resolved=true;finishResult(result)}
${body('tunController.ts', 'onExit')}
return {exit:onExit,settled:()=>Promise.all(startupCleanupTasks),pollCompensating:()=>{startupCompensationStarted=true}};
`, os)
  return {...run,...os}
}

function startupAdmissionHarness(stopCompletion: Promise<unknown> | null = null) {
  const os = {stopCompletion,clearRestartTimers:vi.fn(() => {throw new Error('preparation failed')})}
  return compile<{start: () => Promise<any>; state: () => {starting:boolean;completion:Promise<void>|null}}>(`
let currentStatus={running:false},startInProgress=false,stopInProgress=false,transitionCancelRequested=false;
let activeStartCompletion=null,activeStopCompletion=stopCompletion,activeStartAbortController=null,stopRequested=false,userInitiatedStop=false;
const controller={${body('tunController.ts','start')}};
return {start:()=>controller.start('127.0.0.1:1080'),state:()=>({starting:startInProgress,completion:activeStartCompletion})};
`,os)
}

describe('lifecycle cleanup evidence and retries (AT-02-005 / AT-03-007)', () => {
  it.each(['refused', 'thrown'])('manual stop retains the live session and monitoring when %s, then allows retry (AT-02-009)', async failure => {
    const session = { leakDetected: false }
    const h = mainHarness('stopProtection', session)
    if (failure === 'thrown') h.tunController.stop.mockRejectedValueOnce(new Error('stop failed'))
    else h.tunController.stop.mockResolvedValueOnce({ success: false, error: 'exit unconfirmed', networkCleanup: { adapters: false } })
    if (failure === 'thrown') await expect(h.run()).rejects.toThrow('stop failed')
    else expect(await h.run()).toEqual({ success: false, error: 'exit unconfirmed' })
    expect(h.run.state()).toEqual({ session, stopping: false })
    for (const step of [h.writeSessionEntry, h.rollbackSoftAutoconfigIfApplied, h.externalProxy.stopAll, h.stopPeriodicSnapshots, h.stopPeriodicLeakTest, h.stopNetworkChangeWatcher, h.stopTrafficForensicsSession, h.ipMonitor.clearVpnIp, h.trafficMonitor.stop, h.repairOrphanedPhysicalAdapterDns, h.getLocationPrivacyStatus, h.refreshTrayState]) expect(step).not.toHaveBeenCalled()
    expect(await h.run()).toMatchObject({ success: true })
    expect(h.writeSessionEntry).toHaveBeenCalledOnce()
    expect(h.run.state()).toEqual({ session: null, stopping: false })
  })
  it.each(['stopProtection', 'performShutdownCleanup'] as const)('waits to close history and clean up in %s, preserving pre-stop counters (AT-02-009)', async name => {
    const session = { leakDetected: false }, h = mainHarness(name, session)
    let release!: () => void
    h.tunController.stop.mockImplementationOnce(() => new Promise(resolve => {
      release = () => { h.trafficMonitor.getCurrentStats.mockReturnValue({ downloadBytes: 0 }); resolve({ success: true }) }
    }))
    const pending = h.run('test')
    await vi.waitFor(() => expect(h.tunController.stop).toHaveBeenCalledOnce())
    try {
      expect(h.run.state()).toEqual({ session, stopping: true })
      for (const step of [h.writeSessionEntry, h.externalProxy.stopAll, h.stopPeriodicSnapshots, h.stopTrafficForensicsSession, h.repairOrphanedPhysicalAdapterDns]) expect(step).not.toHaveBeenCalled()
    } finally { release(); await pending }
    expect(h.writeSessionEntry).toHaveBeenCalledWith(session, { downloadBytes: 123 }, expect.objectContaining({ kind: name === 'stopProtection' ? 'test' : 'app-quit' }))
    expect(h.run.state()).toEqual({ session: null, stopping: false })
  })
  it.each(['refused', 'thrown'])('shutdown fallback requires fresh exit proof after controller stop is %s (AT-11-002)', async failure => {
    const h = mainHarness('performShutdownCleanup')
    if (failure === 'thrown') h.tunController.stop.mockRejectedValueOnce(new Error('stop failed'))
    else h.tunController.stop.mockResolvedValueOnce({ success: false, error: 'exit unconfirmed' })
    h.tunController.stop.mockResolvedValueOnce({ success: true, networkCleanup: { baseline: false, firewall: false, adapters: false } })
    await h.run('test')
    expect(h.isOwnedTunRuntimeRunning).toHaveBeenCalledExactlyOnceWith(true)
    expect(h.killOwnedTunRuntimeProcesses.mock.invocationCallOrder[0]).toBeLessThan(h.isOwnedTunRuntimeRunning.mock.invocationCallOrder[0])
    expect(h.tunController.stop).toHaveBeenCalledTimes(2)
    expect(h.isOwnedTunRuntimeRunning.mock.invocationCallOrder[0]).toBeLessThan(h.tunController.stop.mock.invocationCallOrder[1])
    for (const step of [h.stopXray, h.rollbackTunNetworkBaselineIfApplied, h.disableKillSwitchIfActive, h.rollbackPhysicalAdapterLockdownIfApplied]) expect(h.isOwnedTunRuntimeRunning.mock.invocationCallOrder[0]).toBeLessThan(step.mock.invocationCallOrder[0])
  })
  it.each(['refused', 'thrown'])('refuses shutdown if the controller still reports %s after native exit proof (AT-11-002)', async failure => {
    const h = mainHarness('performShutdownCleanup', { leakDetected: false })
    h.tunController.stop.mockResolvedValueOnce({ success: false, error: 'exit unconfirmed' })
    if (failure === 'thrown') h.tunController.stop.mockRejectedValueOnce(new Error('stop failed again'))
    else h.tunController.stop.mockResolvedValueOnce({ success: false, error: 'stop failed again' })
    await expect(h.run('test')).rejects.toThrow('ShutdownCleanupUnconfirmed: runtime')
    for (const step of [h.writeSessionEntry, h.stopXray, h.disableKillSwitchIfActive, h.repairOrphanedPhysicalAdapterDns, h.stopRecoveryPsWorker]) expect(step).not.toHaveBeenCalled()
    expect(h.run.state().stopping).toBe(false)
  })
  it.each(['alive', 'unknown'])('refuses shutdown after acknowledged native stop when runtime is %s (AT-11-002)', async state => {
    const session = { leakDetected: false }, h = mainHarness('performShutdownCleanup', session)
    h.tunController.stop.mockResolvedValueOnce({ success: false, error: 'exit unconfirmed' })
    if (state === 'alive') h.isOwnedTunRuntimeRunning.mockResolvedValueOnce(true)
    else h.isOwnedTunRuntimeRunning.mockRejectedValueOnce(new Error('query denied'))
    await expect(h.run('test')).rejects.toThrow('ShutdownCleanupUnconfirmed: runtime')
    expect(h.run.state()).toEqual({ session, stopping: false })
    for (const step of [h.writeSessionEntry, h.stopXray, h.externalProxy.stopAll, h.rollbackTunNetworkBaselineIfApplied, h.disableKillSwitchIfActive, h.rollbackPhysicalAdapterLockdownIfApplied, h.repairOrphanedPhysicalAdapterDns, h.stopTrafficForensicsSession, h.stopRecoveryPsWorker, h.stopElevatedPsHelper]) expect(step).not.toHaveBeenCalled()
  })
  it.each([
    { status: 'stopping', running: true }, { status: 'error', running: true }, { status: 'adapting', running: true },
    { status: 'stopped', running: false }, { status: 'error', running: false }, { status: 'restarting:1/3', running: false }
  ])('status $status with running=$running retains monitoring only while the runtime is live (AT-02-009)', ({ status, running }) => {
    const h = mainHarness('stopProtection')
    const os = { ...h, tunController: { getStatus: () => ({ running }) }, sendToMainWindow: noop(), granularKillSwitch: { setVpnConnected: noop() },
      startTrafficConnectionSampler: noop(), resetAdaptiveBypassStatus: noop(), isKillSwitchActive: vi.fn(async () => true) }
    const onStatus = compile<(status: string) => void>(`
let currentSession=null,stopInProgress=false,adaptiveVerificationGeneration=0,activeAdaptiveContext=null;
${body('index.ts', 'trayStatusFromTunStatus')}
return ${body('index.ts', 'tunController.onStatusChange')};`, os)
    onStatus(status)
    for (const step of [h.trafficMonitor.stop, h.stopTrafficConnectionSampler, h.stopTrafficForensicsSession]) expect(step).toHaveBeenCalledTimes(running ? 0 : 1)
    const trayStatus = h.refreshTrayState.mock.calls[0][0].status
    if (running) expect(['off', 'protected']).not.toContain(trayStatus)
  })
  it('keeps upstream, watchdog and protection active until runtime exit is proved (AT-02-009)', async () => {
    const h = stopHarness()
    let release!: () => void
    h.waitForOwnedRuntimeToExit.mockImplementationOnce(() => new Promise(resolve => {
      release = () => { h.state.runtime = false; resolve(true) }
    }))
    const pending = h.stop()
    await vi.waitFor(() => expect(h.waitForOwnedRuntimeToExit).toHaveBeenCalledOnce())
    try { expect(h.state).toEqual({ runtime: true, upstream: true, watchdog: true, competing: true, baseline: true, firewall: true, adapters: true }) }
    finally { release() }
    expect(await pending).toMatchObject({ success: true, networkCleanup: { baseline: true, firewall: true, adapters: true } })
    expect(h.state).toEqual({ runtime: false, upstream: false, watchdog: false, competing: false, baseline: false, firewall: false, adapters: false })
  })
  it.each(['stop denied', 'exit timeout', 'exit query failed'])('retains live runtime supervision and protection after %s', async failure => {
    const h = stopHarness()
    if (failure === 'stop denied') h.killOwnedRuntimeProcesses.mockRejectedValueOnce(new Error('native denied'))
    if (failure === 'exit timeout') h.waitForOwnedRuntimeToExit.mockResolvedValueOnce(false)
    if (failure === 'exit query failed') h.waitForOwnedRuntimeToExit.mockRejectedValueOnce(new Error('query denied'))
    expect(await h.stop()).toMatchObject({ success: false, networkCleanup: { baseline: false, firewall: false, adapters: false } })
    expect(h.state).toEqual({ runtime: true, upstream: true, watchdog: true, competing: true, baseline: true, firewall: true, adapters: true })
    expect(h.notifyStatus).toHaveBeenLastCalledWith('error')
    expect(h.ipMonitor.resume).toHaveBeenCalledOnce()
  })
  it('can retry a failed stop without leaving the live runtime unsupervised', async () => {
    const h = stopHarness()
    h.killOwnedRuntimeProcesses.mockRejectedValueOnce(new Error('native denied'))
    expect((await h.stop()).success).toBe(false)
    expect(h.state).toEqual({ runtime: true, upstream: true, watchdog: true, competing: true, baseline: true, firewall: true, adapters: true })
    expect((await h.stop()).success).toBe(true)
    expect(h.state).toEqual({ runtime: false, upstream: false, watchdog: false, competing: false, baseline: false, firewall: false, adapters: false })
  })
  it('awaits capture finalization before releasing shutdown helpers (AT-08-005 / AT-11-002)', async () => {
    const h = mainHarness('performShutdownCleanup')
    let release!: () => void
    const pending = new Promise<void>(resolve => { release = resolve })
    h.stopTrafficForensicsSession.mockImplementationOnce(async () => {
      await pending
      return { running: false, cleanupPending: false }
    })
    const shutdown = h.run('test')
    try {
      await vi.waitFor(() => expect(h.stopTrafficForensicsSession).toHaveBeenCalledOnce())
      expect(h.stopRecoveryPsWorker).not.toHaveBeenCalled()
      expect(h.stopElevatedPsHelper).not.toHaveBeenCalled()
    } finally { release(); await shutdown }
    expect(h.stopTrafficForensicsSession.mock.invocationCallOrder[0]).toBeLessThan(h.stopRecoveryPsWorker.mock.invocationCallOrder[0])
  })
  it.each(['reject', 'running', 'pending'])('refuses shutdown for an unconfirmed capture: %s (AT-08-005 / AT-11-002)', async outcome => {
    const h = mainHarness('performShutdownCleanup')
    if (outcome === 'reject') h.stopTrafficForensicsSession.mockRejectedValueOnce(new Error('native stop failed'))
    else h.stopTrafficForensicsSession.mockResolvedValueOnce({ running: outcome === 'running', cleanupPending: outcome === 'pending' })
    await expect(h.run('test')).rejects.toThrow('ShutdownCleanupUnconfirmed: capture')
    expect(h.tunController.stop).toHaveBeenCalledOnce()
    expect(h.externalProxy.stopAll).toHaveBeenCalledOnce()
    expect(h.stopRecoveryPsWorker).not.toHaveBeenCalled()
    expect(h.stopElevatedPsHelper).not.toHaveBeenCalled()
  })
  it.each(['baseline', 'firewall', 'adapters'])('refuses installer acknowledgement for incomplete %s rollback (AT-11-002)', async step => {
    const h = mainHarness('performShutdownCleanup')
    h.tunController.stop.mockResolvedValue({ success: true, networkCleanup: { baseline: false, firewall: false, adapters: false } })
    if (step === 'baseline') h.rollbackTunNetworkBaselineIfApplied.mockResolvedValueOnce({ success: false })
    if (step === 'firewall') h.disableKillSwitchIfActive.mockResolvedValueOnce({ success: false })
    if (step === 'adapters') h.rollbackPhysicalAdapterLockdownIfApplied.mockResolvedValueOnce({ rolledBack: false })
    await expect(h.run('test')).rejects.toThrow(`ShutdownCleanupUnconfirmed: ${step}`)
    expect(h.stopTrafficForensicsSession).toHaveBeenCalledOnce()
    expect(h.stopRecoveryPsWorker).not.toHaveBeenCalled()
  })
  it('refuses shutdown when the environment proxy rollback returns false (AT-11-002)', async () => {
    const h = mainHarness('performShutdownCleanup')
    h.autoconfig.isApplied.mockResolvedValueOnce(true)
    h.autoconfig.rollback.mockResolvedValueOnce({ env: false })
    await expect(h.run('test')).rejects.toThrow('ShutdownCleanupUnconfirmed: autoconfig')
    expect(h.stopTrafficForensicsSession).toHaveBeenCalledOnce()
    expect(h.stopRecoveryPsWorker).not.toHaveBeenCalled()
  })
  it.each([
    { success: false, candidates: 0, killed: 0, names: [] },
    { success: true, candidates: 2, killed: 1, names: [] }
  ])('refuses shutdown for failed or partial runtime stop: %j (AT-11-002 / F-183)', async result => {
    const h = mainHarness('performShutdownCleanup')
    h.killOwnedTunRuntimeProcesses.mockResolvedValueOnce(result)
    await expect(h.run('test')).rejects.toThrow('ShutdownCleanupUnconfirmed: runtime')
    for (const step of [h.stopXray, h.externalProxy.stopAll, h.stopTrafficForensicsSession, h.rollbackTunNetworkBaselineIfApplied, h.disableKillSwitchIfActive, h.rollbackPhysicalAdapterLockdownIfApplied, h.repairOrphanedPhysicalAdapterDns]) expect(step).not.toHaveBeenCalled()
    expect(h.stopRecoveryPsWorker).not.toHaveBeenCalled()
    expect(h.stopElevatedPsHelper).not.toHaveBeenCalled()
  })
  it('refuses shutdown on unknown env status without blind rollback (AT-11-002 / F-183)', async () => {
    const h = mainHarness('performShutdownCleanup')
    h.autoconfig.isApplied.mockRejectedValueOnce(new Error('registry read failed'))
    await expect(h.run('test')).rejects.toThrow('ShutdownCleanupUnconfirmed: autoconfig')
    expect(h.autoconfig.isApplied).toHaveBeenCalledExactlyOnceWith('env')
    expect(h.autoconfig.rollback).not.toHaveBeenCalled()
    expect(h.stopTrafficForensicsSession).toHaveBeenCalledOnce()
    expect(h.stopRecoveryPsWorker).not.toHaveBeenCalled()
    expect(h.stopElevatedPsHelper).not.toHaveBeenCalled()
  })
  it.each([true, false])('allows confirmed env status and restores only when applied=%s (AT-11-002)', async applied => {
    const h = mainHarness('performShutdownCleanup')
    h.autoconfig.isApplied.mockResolvedValueOnce(applied)
    await h.run('test')
    expect(h.autoconfig.isApplied).toHaveBeenCalledExactlyOnceWith('env')
    if (applied) expect(h.autoconfig.rollback).toHaveBeenCalledExactlyOnceWith(['env'])
    else expect(h.autoconfig.rollback).not.toHaveBeenCalled()
    expect(h.stopRecoveryPsWorker).toHaveBeenCalledOnce()
  })
  it('retains the recovery worker until all shutdown network backstops complete', async () => {
    const h = mainHarness('performShutdownCleanup')
    h.tunController.stop.mockResolvedValue({success:true,networkCleanup:{baseline:false,firewall:false,adapters:false}})
    await h.run('test')
    expect(h.stopRecoveryPsWorker).toHaveBeenCalledOnce()
    for(const step of [h.rollbackTunNetworkBaselineIfApplied,h.disableKillSwitchIfActive,h.rollbackPhysicalAdapterLockdownIfApplied,h.repairOrphanedPhysicalAdapterDns]) {
      expect(step.mock.invocationCallOrder[0]).toBeLessThan(h.stopRecoveryPsWorker.mock.invocationCallOrder[0])
    }
    expect(h.stopRecoveryPsWorker.mock.invocationCallOrder[0]).toBeLessThan(h.stopElevatedPsHelper.mock.invocationCallOrder[0])
  })
  it('keeps start admission closed through the final stop completion microtask', async () => {
    const h = startupAdmissionHarness(new Promise(() => {}))
    expect(await h.start()).toMatchObject({success:false,error:expect.stringContaining('Остановка')})
    expect(h.state().completion).toBeNull()
  })
  it('releases the actual start owner even if preparation unexpectedly throws', async () => {
    const h = startupAdmissionHarness()
    await expect(h.start()).rejects.toThrow('preparation failed')
    expect(h.state()).toEqual({starting:false,completion:null})
    await expect(h.start()).rejects.toThrow('preparation failed')
  })
  it('retains startup exit compensation until a pending poll and adapter rollback finish', async () => {
    let releasePoll!: () => void, releaseRollback!: () => void
    const poll = new Promise<void>(done => { releasePoll = done })
    const h = startupExitHarness(poll)
    h.rollbackEarlyAdapterLockdown.mockReturnValue(new Promise<void>(done => { releaseRollback = done }))
    h.exit(new Error('child failed'))
    expect(h.finishResult).toHaveBeenCalledWith({success:false,error:'child failed'})
    expect(h.stopXray).not.toHaveBeenCalled()
    const settled = vi.fn()
    void h.settled().then(settled)
    releasePoll()
    await vi.waitFor(() => expect(h.rollbackEarlyAdapterLockdown).toHaveBeenCalledOnce())
    expect(settled).not.toHaveBeenCalled()
    releaseRollback()
    await h.settled()
    expect(settled).toHaveBeenCalledOnce()
    expect(h.disableKillSwitchIfActive).toHaveBeenCalledOnce()
  })
  it('does not skip adapter compensation when another startup exit rollback step rejects', async () => {
    const h = startupExitHarness()
    h.stopXray.mockRejectedValue(new Error('xray unconfirmed'))
    h.disableKillSwitchIfActive.mockRejectedValue(new Error('firewall failed'))
    h.exit(new Error('child failed'))
    await h.settled()
    expect(h.rollbackEarlyAdapterLockdown).toHaveBeenCalledOnce()
    expect(h.logEvent).toHaveBeenCalledWith('warn','tun','startup exit rollback failed',expect.any(Error))
  })
  it('does not settle or duplicate the rollback when owned taskkill itself triggers onExit', async () => {
    const h = startupExitHarness()
    h.pollCompensating()
    h.exit(new Error('killed during compensation'))
    await h.settled()
    expect(h.finishResult).not.toHaveBeenCalled()
    expect(h.stopXray).not.toHaveBeenCalled()
    expect(h.disableKillSwitchIfActive).not.toHaveBeenCalled()
    expect(h.rollbackEarlyAdapterLockdown).not.toHaveBeenCalled()
  })
  it('waits for native startup effects beyond two seconds before rolling anything back', async () => {
    vi.useFakeTimers()
    let release!: () => void
    const started = new Promise<void>(done => { release = done })
    const h = stopHarness(new AbortController(), started)
    const result = h.stop()
    await vi.advanceTimersByTimeAsync(3000)
    expect(h.stopXray).not.toHaveBeenCalled()
    expect(h.disableKillSwitchIfActive).not.toHaveBeenCalled()
    expect(h.rollbackTunNetworkBaselineIfApplied).not.toHaveBeenCalled()
    release()
    expect((await result).success).toBe(true)
    vi.useRealTimers()
  })
  it('joins concurrent ordinary stops without duplicate native rollback', async () => {
    let release!: () => void
    const h = stopHarness()
    h.stopXray.mockReturnValue(new Promise<void>(done => { release = done }))
    const first = h.stop(), second = h.stop()
    await vi.waitFor(() => expect(h.stopXray).toHaveBeenCalledOnce())
    release()
    expect(await second).toEqual(await first)
    expect(h.killOwnedRuntimeProcesses).toHaveBeenCalledOnce()
    expect(h.rollbackTunNetworkBaselineIfApplied).toHaveBeenCalledOnce()
    expect(h.disableKillSwitchIfActive).toHaveBeenCalledOnce()
    expect(h.rollbackPhysicalAdapterLockdownIfApplied).toHaveBeenCalledOnce()
  })
  it('coalesces 200 queued stop commands behind one held startup owner (AT-00-007 subset)', async () => {
    let release!: () => void
    const started = new Promise<void>(done => {release=done})
    const h = stopHarness(new AbortController(),started)
    const requests=Array.from({length:200},()=>h.stop())
    await Promise.resolve()
    expect(h.stopXray).not.toHaveBeenCalled()
    release()
    const results=await Promise.all(requests)
    expect(results.every(result=>result.success)).toBe(true)
    expect(h.stopXray).toHaveBeenCalledOnce()
    expect(h.rollbackTunNetworkBaselineIfApplied).toHaveBeenCalledOnce()
    expect(h.disableKillSwitchIfActive).toHaveBeenCalledOnce()
  })
  it('does not tell a preserved-stop caller that full teardown preserved protection', async () => {
    const h = stopHarness()
    const first = h.stop(), protectedStop = h.stop({ preserveNetworkProtection: true })
    await first
    expect(await protectedStop).toMatchObject({ success: false })
    expect(h.disableKillSwitchIfActive).toHaveBeenCalledOnce()
  })
  it('escalates a preserved stop into one full teardown for concurrent ordinary callers (AT-00-007)', async () => {
    const h = stopHarness()
    const preserved = h.stop({ preserveNetworkProtection: true })
    const first = h.stop(), second = h.stop()
    expect((await preserved).networkCleanup).toEqual({baseline:false,firewall:false,adapters:false})
    expect(await second).toEqual(await first)
    expect(h.stopXray).toHaveBeenCalledTimes(2)
    expect(h.disableKillSwitchIfActive).toHaveBeenCalledOnce()
    expect(h.rollbackTunNetworkBaselineIfApplied).toHaveBeenCalledOnce()
  })
  it('releases the stop gate after a thrown listener so later cleanup can retry', async () => {
    const h = stopHarness()
    h.notify.mockImplementationOnce(() => { throw new Error('listener failed') })
    await expect(h.stop()).rejects.toThrow('listener failed')
    expect((await h.stop()).success).toBe(true)
    expect(h.stopXray).toHaveBeenCalledTimes(2)
  })
  it('signals startup cancellation synchronously before cleanup awaits', async () => {
    const startup = new AbortController()
    const h = stopHarness(startup)
    const result = h.stop()
    expect(startup.signal.aborted).toBe(true)
    await result
  })
  it('skips a redundant runtime kill only after fresh exit proof on an idle/cancelled start (AT-02-001)', async () => {
    const h = stopHarness()
    h.stop.setRunning(false)
    const result = await h.stop()
    expect(h.isOwnedTunRuntimeRunning).toHaveBeenCalledExactlyOnceWith(true)
    expect(h.killOwnedRuntimeProcesses).not.toHaveBeenCalled()
    expect(h.waitForOwnedRuntimeToExit).not.toHaveBeenCalled()
    expect(result.networkCleanup).toEqual({ baseline: true, firewall: true, adapters: true })
  })
  it.each(['present', 'unknown'])('keeps process termination and network cleanup when idle runtime is %s', async state => {
    const h = stopHarness()
    h.stop.setRunning(false)
    if (state === 'present') h.isOwnedTunRuntimeRunning.mockResolvedValue(true)
    else h.isOwnedTunRuntimeRunning.mockRejectedValue(new Error('read unavailable'))
    await h.stop()
    expect(h.killOwnedRuntimeProcesses).toHaveBeenCalledOnce()
    expect(h.waitForOwnedRuntimeToExit).toHaveBeenCalledOnce()
    expect(h.disableKillSwitchIfActive).toHaveBeenCalledOnce()
  })
  it.each([{ rolledBack: true }, { rolledBack: false, skipped: true }])('skips redundant DNS recovery after confirmed adapter result %j', async result => {
    const h = stopHarness()
    h.rollbackPhysicalAdapterLockdownIfApplied.mockResolvedValue(result)
    const stopped = await h.stop()
    expect(stopped.networkCleanup).toEqual({ baseline: true, firewall: true, adapters: true })
    expect(h.repairOrphanedPhysicalAdapterDns).not.toHaveBeenCalled()
    expect(h.ipMonitor.resume).toHaveBeenCalledOnce()
    expect(h.logEvent).toHaveBeenCalledWith('info', 'tun', 'stop timing', expect.objectContaining({ phaseDurations: expect.objectContaining({ 'rollback-adapters': expect.any(Number) }) }))
  })
  it('retains DNS retry and reports incomplete adapter recovery', async () => {
    const h = stopHarness()
    h.rollbackPhysicalAdapterLockdownIfApplied.mockResolvedValue({ rolledBack: false })
    const result = await h.stop()
    expect(h.repairOrphanedPhysicalAdapterDns).toHaveBeenCalledOnce()
    expect(result.networkCleanup.adapters).toBe(false)
    expect(result.warning).toContain('восстановление не подтверждено')
    expect(h.notifyStatus).toHaveBeenCalledWith('stopped')
    expect(h.ipMonitor.resume).toHaveBeenCalledOnce()
  })
  it('records a successful fallback repair without rerunning it', async () => {
    const h = stopHarness()
    h.rollbackPhysicalAdapterLockdownIfApplied.mockResolvedValue({ rolledBack: false })
    h.repairOrphanedPhysicalAdapterDns.mockResolvedValue({ repaired: true, adapters: [] })
    expect((await h.stop()).networkCleanup.adapters).toBe(true)
    expect(h.repairOrphanedPhysicalAdapterDns).toHaveBeenCalledOnce()
  })
  it.each(['runtime', 'baseline', 'firewall', 'adapters', 'dns'])('requires runtime exit before independent cleanup: %s failure', async failing => {
    const h = stopHarness()
    const error = new Error(`${failing} failed`)
    if (failing === 'runtime') h.killOwnedRuntimeProcesses.mockRejectedValue(error)
    if (failing === 'baseline') h.rollbackTunNetworkBaselineIfApplied.mockRejectedValue(error)
    if (failing === 'firewall') h.disableKillSwitchIfActive.mockRejectedValue(error)
    if (failing === 'adapters') h.rollbackPhysicalAdapterLockdownIfApplied.mockRejectedValue(error)
    if (failing === 'dns') {
      h.rollbackPhysicalAdapterLockdownIfApplied.mockResolvedValue({ rolledBack: false })
      h.repairOrphanedPhysicalAdapterDns.mockRejectedValue(error)
    }
    const result = await h.stop()
    if (failing === 'runtime') {
      expect(result).toMatchObject({ success: false, error: expect.stringContaining('runtime failed') })
      for (const cleanup of [h.stopXray, h.rollbackTunNetworkBaselineIfApplied, h.disableKillSwitchIfActive, h.rollbackPhysicalAdapterLockdownIfApplied]) expect(cleanup).not.toHaveBeenCalled()
      expect(h.notifyStatus).toHaveBeenCalledWith('error')
      expect(h.ipMonitor.resume).toHaveBeenCalledOnce()
      return
    }
    expect(result.warning).toContain(`${failing} failed`)
    expect(h.rollbackTunNetworkBaselineIfApplied).toHaveBeenCalledOnce()
    expect(h.disableKillSwitchIfActive).toHaveBeenCalledOnce()
    expect(h.rollbackPhysicalAdapterLockdownIfApplied).toHaveBeenCalledOnce()
    expect(h.ipMonitor.resume).toHaveBeenCalledOnce()
  })
  it('does not issue a completed-network receipt for an adaptive stop preserving protection', async () => {
    const h = stopHarness()
    expect((await h.stop({ preserveNetworkProtection: true })).networkCleanup).toEqual({ baseline: false, firewall: false, adapters: false })
    expect(h.rollbackTunNetworkBaselineIfApplied).not.toHaveBeenCalled()
    expect(h.disableKillSwitchIfActive).not.toHaveBeenCalled()
    expect(h.rollbackPhysicalAdapterLockdownIfApplied).not.toHaveBeenCalled()
  })
  it('performs fresh verification on every later stop; it never caches a prior receipt', async () => {
    const h = stopHarness()
    await h.stop()
    h.rollbackPhysicalAdapterLockdownIfApplied.mockRejectedValue(new Error('ACL changed'))
    const next = await h.stop()
    expect(h.rollbackPhysicalAdapterLockdownIfApplied).toHaveBeenCalledTimes(2)
    expect(next.networkCleanup.adapters).toBe(false)
    expect(next.warning).toContain('ACL changed')
  })
  it('does not repeat confirmed network rollback during shutdown, while process backstops remain', async () => {
    const h = mainHarness('performShutdownCleanup')
    await h.run('test')
    for (const call of [h.rollbackTunNetworkBaselineIfApplied, h.disableKillSwitchIfActive, h.rollbackPhysicalAdapterLockdownIfApplied, h.repairOrphanedPhysicalAdapterDns]) expect(call).not.toHaveBeenCalled()
    expect(h.stopXray).toHaveBeenCalledOnce()
    expect(h.killOwnedTunRuntimeProcesses).toHaveBeenCalledOnce()
    expect(h.externalProxy.stopAll).toHaveBeenCalledOnce()
  })
  it.each(['baseline', 'firewall', 'adapters', 'thrown'])('keeps shutdown backstops for an unconfirmed %s step', async failed => {
    const h = mainHarness('performShutdownCleanup')
    if (failed === 'thrown') h.tunController.stop.mockRejectedValueOnce(new Error('stop failed')).mockResolvedValueOnce({ success: true })
    else h.tunController.stop.mockResolvedValue({ success: true, networkCleanup: { baseline: true, firewall: true, adapters: true, [failed]: false } })
    await h.run('test')
    expect(h.rollbackTunNetworkBaselineIfApplied).toHaveBeenCalledTimes(failed === 'baseline' || failed === 'thrown' ? 1 : 0)
    expect(h.disableKillSwitchIfActive).toHaveBeenCalledTimes(failed === 'firewall' || failed === 'thrown' ? 1 : 0)
    expect(h.rollbackPhysicalAdapterLockdownIfApplied).toHaveBeenCalledTimes(failed === 'adapters' || failed === 'thrown' ? 1 : 0)
    expect(h.repairOrphanedPhysicalAdapterDns).toHaveBeenCalledTimes(failed === 'adapters' || failed === 'thrown' ? 1 : 0)
  })
  it.each([true, false])('post-stop DNS backstop uses current confirmed=%s evidence; IPC omits the receipt', async confirmed => {
    const h = mainHarness('stopProtection')
    h.tunController.stop.mockResolvedValue({ success: true, warning: 'fixture', networkCleanup: { adapters: confirmed } })
    expect(await h.run()).toEqual({ success: true, warning: 'fixture' })
    expect(h.repairOrphanedPhysicalAdapterDns).toHaveBeenCalledTimes(confirmed ? 0 : 1)
  })
  it('distinguishes trusted manifest absence from a rejected trust check', async () => {
    const readManifest = vi.fn(async (): Promise<unknown> => null)
    const text = body('physicalAdapterLockdown.ts', 'rollbackPhysicalAdapterLockdownIfApplied').replace(/^export /, '')
    const rollback = compile<(reason: string) => Promise<any>>(`${text}\nreturn rollbackPhysicalAdapterLockdownIfApplied;`, { readManifest, process: { platform: 'win32' } })
    expect(await rollback('test')).toEqual({ rolledBack: false, skipped: true })
    readManifest.mockRejectedValue(new Error('untrusted ACL'))
    await expect(rollback('test')).rejects.toThrow('untrusted ACL')
  })
})

function xrayStartHarness() {
  let clock = 0
  const effect = <T>(cost: number, value: T) => vi.fn(async (..._args: any[]) => { clock += cost; return value })
  const os = {
    performance: { now: () => clock },
    stopXray: effect(5, undefined), stageXrayRuntime: effect(24, 'fixture.exe'),
    cleanupManagedChildPidFile: effect(3, undefined), rename: effect(2, undefined),
    resolveServerAddress: effect(17, '192.0.2.1'), pickFreeLocalPort: effect(4, 10800),
    writeFile: effect(3, undefined), writeManagedChildPidFile: effect(5, undefined),
    runXrayConfigPreflight: effect(11, undefined),
    ensureKillSwitchProgramAllowed: effect(41, { success: true }), waitForLocalSocks: effect(2, undefined),
    removeManagedChildPidFile: effect(1, undefined), logEvent: noop(), getTunRuntimeDir: () => 'fixture-dir',
    toXrayOutbound: () => ({}), buildXrayConfig: () => ({ outbounds: [], routing: { rules: [] } }), join, isIP,
    getNativeXrayProfile: vi.fn(() => null as any), resolveXrayConfigEndpoints: effect(21, undefined),
    spawn: vi.fn((_file: string, args: string[]) => {
      const child = Object.assign(new EventEmitter(), { pid: 42, stdout: new EventEmitter(), stderr: new EventEmitter(), kill: vi.fn() })
      clock += args.includes('-test') ? 11 : 1
      if (args.includes('-test')) queueMicrotask(() => child.emit('exit', 0))
      return child
    })
  }
  const text = body('xrayEngine.ts', 'startXray').replace(/^export /, '')
  const start = compile<(outbound: Record<string, unknown>, options?: Record<string, unknown>) => Promise<any>>(`
const XRAY_PID_FILE='fixture.pid',SOCKS_PROBE_TIMEOUT_MS=3500;
const exitedChildren=new WeakSet();
${body('xrayEngine.ts', 'runtimeHasExited')}
let activeXrayState={proc:null};
${text}
return startXray;
`, os)
  return { start, ...os }
}
describe('Xray startup phase measurements (AT-02-002 / AT-02-004)', () => {
  it('fails unresolved native graph before config write, preflight or process spawn', async () => {
    const h = xrayStartHarness()
    h.getNativeXrayProfile.mockReturnValue({ entry: { outboundTag: 'proxy' } })
    h.resolveXrayConfigEndpoints.mockRejectedValue(new Error('native endpoint unresolved'))
    await expect(h.start({ server: '192.0.2.1' })).rejects.toThrow('native endpoint unresolved')
    expect(h.writeFile).not.toHaveBeenCalled()
    expect(h.runXrayConfigPreflight).not.toHaveBeenCalled()
    expect(h.spawn).not.toHaveBeenCalled()
  })
  it.each([true, false])('classifies a firewall rejection with cancelled=%s without hiding real errors', async cancelled => {
    const h = xrayStartHarness(), owner = new AbortController(), error = new Error('firewall fixture')
    h.ensureKillSwitchProgramAllowed.mockImplementation(async () => {
      if (cancelled) owner.abort()
      throw error
    })
    if (cancelled) h.waitForLocalSocks.mockRejectedValue(new Error('cancelled'))
    const result = h.start({ server: 'fixture.invalid' }, { signal: owner.signal })
    if (cancelled) await expect(result).rejects.toThrow('cancelled')
    else await result
    if (cancelled) {
      expect(h.logEvent).toHaveBeenCalledWith('info', 'xray', 'xray startup cancelled while awaiting firewall')
      expect(h.logEvent.mock.calls.some(call => call[0] === 'warn' && call[2] === 'failed to ensure xray kill-switch allow rule')).toBe(false)
    } else expect(h.logEvent).toHaveBeenCalledWith('warn', 'xray', 'failed to ensure xray kill-switch allow rule', error)
  })
  it('fences cancellation during preserved connection-graph bootstrap before config publication (AT-02-004)', async () => {
    const h = xrayStartHarness()
    h.getNativeXrayProfile.mockReturnValue({ entry: { balancerTag: 'fixture' } })
    let release!: () => void
    h.resolveXrayConfigEndpoints.mockReturnValue(new Promise(done => { release = () => done(undefined) }))
    const owner = new AbortController()
    const result = h.start({ server: 'fixture.invalid' }, { signal: owner.signal })
    const rejected = expect(result).rejects.toThrow('cancelled')
    await vi.waitFor(() => expect(h.resolveXrayConfigEndpoints).toHaveBeenCalledOnce())
    owner.abort()
    release()
    await rejected
    expect(h.writeFile).not.toHaveBeenCalled()
    expect(h.runXrayConfigPreflight).not.toHaveBeenCalled()
    expect(h.spawn).not.toHaveBeenCalled()
  })
  it('does not launch the runtime before held native validation completes', async () => {
    const h = xrayStartHarness()
    let release!: () => void
    h.runXrayConfigPreflight.mockReturnValue(new Promise(done => { release = () => done(undefined) }))
    const result = h.start({ server: 'fixture.invalid' })
    await vi.waitFor(() => expect(h.runXrayConfigPreflight).toHaveBeenCalledOnce())
    expect(h.spawn).not.toHaveBeenCalled()
    release()
    expect((await result).socksPort).toBe(10800)
    expect(h.spawn).toHaveBeenCalledOnce()
  })
  it('does not start work for an already cancelled owner', async () => {
    const h = xrayStartHarness()
    const startup = new AbortController()
    startup.abort()
    await expect(h.start({}, { signal: startup.signal })).rejects.toThrow('cancelled')
    expect(h.stopXray).not.toHaveBeenCalled()
    expect(h.spawn).not.toHaveBeenCalled()
  })
  it('passes the owner signal into validation and fences cancellation after held DNS', async () => {
    const h = xrayStartHarness()
    const startup = new AbortController()
    let release!: (ip: string) => void
    h.resolveServerAddress.mockReturnValue(new Promise(done => { release = done }))
    const result = h.start({ server: 'fixture.invalid' }, { signal: startup.signal })
    const rejected = expect(result).rejects.toThrow('cancelled')
    await vi.waitFor(() => expect(h.resolveServerAddress).toHaveBeenCalledOnce())
    startup.abort()
    release('192.0.2.1')
    await rejected
    expect(h.pickFreeLocalPort).not.toHaveBeenCalled()
    expect(h.runXrayConfigPreflight).not.toHaveBeenCalled()
    expect(h.spawn).not.toHaveBeenCalled()
    const valid = xrayStartHarness()
    await valid.start({ server: 'fixture.invalid' }, { signal: new AbortController().signal })
    expect(valid.runXrayConfigPreflight).toHaveBeenCalledWith('fixture.exe', 'fixture-dir', expect.any(String), expect.any(AbortSignal))
  })
  it('measures each awaited boundary and preserves the successful result', async () => {
    const h = xrayStartHarness()
    expect(await h.start({ server: 'fixture.invalid' })).toEqual({ socksPort: 10800, exePath: 'fixture.exe', resolvedIp: '192.0.2.1' })
    expect(h.logEvent).toHaveBeenCalledWith('info', 'xray', 'start timing', {
      success: true, totalMs: 118,
      phaseDurations: { 'stop-previous': 5, 'prepare-runtime': 24, 'cleanup-pid': 3, 'rotate-log': 2,
        'resolve-server': 17, 'pick-port': 4, 'write-config': 3, 'config-preflight': 11,
        'write-pid': 5, 'allow-firewall': 41, 'wait-local-socks': 2 }
    })
  })
  it('keeps endpoint/port overrides and does not invent times for skipped work', async () => {
    const h = xrayStartHarness()
    await h.start({ server: 'fixture.invalid' }, { resolvedIp: '192.0.2.2', portOverride: 10801 })
    expect(h.resolveServerAddress).not.toHaveBeenCalled()
    expect(h.pickFreeLocalPort).not.toHaveBeenCalled()
    const report = h.logEvent.mock.calls.find(call => call[2] === 'start timing')![3] as any
    expect(report.phaseDurations['resolve-server']).toBeUndefined()
    expect(report.phaseDurations['pick-port']).toBeUndefined()
    expect(report.success).toBe(true)
  })
  it('records partial failed timings while propagating the original failure', async () => {
    const h = xrayStartHarness()
    const error = new Error('sensitive fixture failure')
    h.stageXrayRuntime.mockRejectedValue(error)
    await expect(h.start({ server: 'fixture.invalid' })).rejects.toBe(error)
    expect(h.spawn).not.toHaveBeenCalled()
    expect(h.logEvent).toHaveBeenCalledWith('info', 'xray', 'start timing', {
      success: false, totalMs: 5, phaseDurations: { 'stop-previous': 5, 'prepare-runtime': 0 }
    })
    expect(JSON.stringify(h.logEvent.mock.calls)).not.toContain(error.message)
  })
})

function ipStartupHarness(mode: 'direct' | 'proxy') {
  let running = false
  const settings = { autoNetworkBaseline: false, directVpnInput: '' }
  const os = {
    ...mainHarness('stopProtection'),
    rollbackSoftAutoconfigIfApplied: done(), suppressLeakSelfTestsFor: noop(), captureSnapshot: done(),
    clearStaleKillSwitchBeforeStart: vi.fn(async () => ({ success: true })), recordStartFailure: noop(),
    settingsStore: { get: () => settings },
    serverPicker: { getActiveProfile: () => ({ id: 'fixture', name: 'fixture', protocol: 'vless', outbound: { server: 'fixture.invalid', server_port: 443 } }) },
    killSwitchManifestExists: vi.fn(async () => false), combinedPreStartProbe: vi.fn(async () => ({ tunnels: [], listeners: [] })),
    getRoutingPlan: vi.fn(async () => ({ canStartHard: true })),
    beginAdaptiveConnection: () => ({ capabilities: {}, mode: 'standard' }),
    readAdaptiveNetworkFingerprint: vi.fn(async () => null),
    tunController: { start: vi.fn(async (): Promise<any> => { running = true; return { success: true } }), getStatus: () => ({ running }),
      stop: vi.fn(async () => ({ success:true,networkCleanup:{baseline:true,firewall:true,adapters:true} })) },
    applyTunNetworkBaseline: vi.fn(async (): Promise<any> => ({ success: true })), rollbackTunNetworkBaselineIfApplied: done(),
    markAdaptiveFailure: noop(), readRecentSingBoxOutboundFault: vi.fn(async () => null), scheduleAdaptiveVerification: noop(),
    ipMonitor: { clearVpnIp:noop(),startMonitoring: noop(), getCurrentIp: vi.fn(async (_guard?: () => boolean) => ({ ip: '203.0.113.1' })),
      recheck: vi.fn(async (_rebaseline: boolean, _guard?: () => boolean) => ({ ip: '203.0.113.1', isLeak: false })) },
    startTrafficForensicsSession: done(), refreshTrayState: noop(), openSession: noop(), startPeriodicSnapshots: noop(),
    startPeriodicLeakTest: noop(), startNetworkChangeWatcher: noop(), sendToMainWindow: noop(), logEvent: noop(),
    areTunRoutesActive: vi.fn(async () => false)
  }
  os.connectionLifecycle = new ConnectionLifecycle(() => { running=false })
  const name = mode === 'direct' ? 'startDirectVpnProtection' : 'startProtection'
  const control = compile<{ start: () => Promise<any>; cancel: () => void; stop: () => Promise<any>; shutdown: () => Promise<void> }>(`
let adaptiveVerificationGeneration=0,activeAdaptiveContext=null,latestPublicIp=null,currentSession=null,stopInProgress=false,shutdownInProgress=false;
const KILL_SWITCH_RULE_PREFIX='VPNTE-killswitch';
${body('index.ts', name)}
${body('index.ts','stopProtection')}
${body('index.ts','performShutdownCleanup')}
return {start: () => ${name}(${mode === 'proxy' ? "'127.0.0.1:1080','socks5'" : ''}),stop:stopProtection,shutdown:()=>performShutdownCleanup('test'), cancel: () => {adaptiveVerificationGeneration++}};
`, os)
  return { ...control, ...os, settings, setRunning: (value: boolean) => { running = value } }
}
describe.each(['direct', 'proxy'] as const)('background IP startup: %s (AT-00-003 / AT-02-002)', mode => {
  afterEach(() => { vi.clearAllTimers(); vi.useRealTimers() })
  it('adopts an unchanged post-start IP once routes are confirmed, without a 16-wave HTTP loop (AT-07-007)', async () => {
    vi.useFakeTimers()
    const h = ipStartupHarness(mode)
    h.areTunRoutesActive.mockResolvedValue(true)
    await h.start()
    await vi.advanceTimersByTimeAsync(8000)
    expect(h.ipMonitor.getCurrentIp).toHaveBeenCalledOnce()
    expect(h.ipMonitor.recheck).toHaveBeenCalledExactlyOnceWith(true, expect.any(Function))
    expect(h.areTunRoutesActive).toHaveBeenCalledOnce()
    expect(h.sendToMainWindow).toHaveBeenCalledOnce()
  })
  it('keeps the baseline unchanged and makes no repeated HTTP waves while routes are unconfirmed (AT-07-012)', async () => {
    vi.useFakeTimers()
    const h = ipStartupHarness(mode)
    await h.start()
    await vi.advanceTimersByTimeAsync(8000)
    expect(h.ipMonitor.getCurrentIp).toHaveBeenCalledOnce()
    expect(h.ipMonitor.recheck).not.toHaveBeenCalled()
    expect(h.areTunRoutesActive).toHaveBeenCalledTimes(5)
  })
  it.each(['preflight','native','fault'] as const)('fences cancellation while a main %s boundary is pending', async phase => {
    const h=ipStartupHarness(mode)
    let release!: (result:any)=>void
    const boundary=phase==='preflight' ? (mode==='direct' ? h.clearStaleKillSwitchBeforeStart : h.combinedPreStartProbe)
      : phase==='native' ? h.tunController.start : h.readRecentSingBoxOutboundFault
    if (phase==='fault') h.tunController.start.mockResolvedValue({success:false,error:'native failure'})
    boundary.mockReturnValue(new Promise<any>(done=>{release=done}))
    const started=h.start()
    await vi.waitFor(()=>expect(boundary).toHaveBeenCalledOnce())
    const stopped=h.stop()
    await Promise.resolve()
    expect(h.tunController.stop).not.toHaveBeenCalled()
    release(phase==='preflight' ? {success:true,tunnels:[],listeners:[]} : phase==='native' ? {success:true} : null)
    expect(await started).toEqual({success:false,error:'Запуск отменён'})
    await stopped
    if (phase==='preflight') expect(h.tunController.start).not.toHaveBeenCalled()
    expect(h.recordStartFailure).not.toHaveBeenCalled()
    expect(h.openSession).not.toHaveBeenCalled()
    expect(h.refreshTrayState).not.toHaveBeenCalledWith(expect.objectContaining({status:'protected'}))
  })
  it('waits for main baseline on shutdown and never opens a cancelled session', async () => {
    const h=ipStartupHarness(mode)
    h.settings.autoNetworkBaseline=true
    let release!: (result:any)=>void
    h.applyTunNetworkBaseline.mockReturnValue(new Promise(done=>{release=done}))
    const started=h.start()
    await vi.waitFor(()=>expect(h.tunController.start).toHaveBeenCalledOnce())
    const shutdown=h.shutdown()
    await Promise.resolve()
    expect(h.tunController.stop).not.toHaveBeenCalled()
    release({success:true})
    expect(await started).toMatchObject({success:false})
    await shutdown
    expect(h.tunController.stop).toHaveBeenCalledOnce()
    expect(h.openSession).not.toHaveBeenCalled()
    expect(await h.start()).toMatchObject({success:false})
  })
  it('waits for held main baseline before stop and suppresses stale history/status', async () => {
    const h=ipStartupHarness(mode)
    h.settings.autoNetworkBaseline=true
    let release!: (value:any)=>void
    h.applyTunNetworkBaseline.mockReturnValue(new Promise(done=>{release=done}))
    const started=h.start()
    await vi.waitFor(()=>expect(h.tunController.start).toHaveBeenCalledOnce())
    const stopped=h.stop()
    await Promise.resolve()
    expect(h.tunController.stop).not.toHaveBeenCalled()
    expect(h.openSession).not.toHaveBeenCalled()
    release({success:true})
    expect(await started).toEqual({success:false,error:'Запуск отменён'})
    expect((await stopped).success).toBe(true)
    expect(h.scheduleAdaptiveVerification).not.toHaveBeenCalled()
    expect(h.openSession).not.toHaveBeenCalled()
    expect(h.refreshTrayState).not.toHaveBeenCalledWith(expect.objectContaining({status:'protected'}))
  })
  it('returns the native outcome while the external IP request remains pending', async () => {
    const h = ipStartupHarness(mode)
    let resolve!: (value: { ip: string }) => void
    h.ipMonitor.getCurrentIp.mockReturnValue(new Promise(done => { resolve = done }))
    expect(await h.start()).toEqual({ success: true, warning: null, vpnIp: null })
    expect(h.ipMonitor.getCurrentIp).toHaveBeenCalledOnce()
    expect(h.startNetworkChangeWatcher).toHaveBeenCalledOnce()
    h.cancel()
    resolve({ ip: '198.51.100.1' })
    await Promise.resolve()
    expect(h.ipMonitor.recheck).not.toHaveBeenCalled()
  })
  it('still waits for the required native baseline and preserves its warning', async () => {
    const h = ipStartupHarness(mode)
    h.settings.autoNetworkBaseline = true
    let release!: (value: any) => void
    h.applyTunNetworkBaseline.mockReturnValue(new Promise(done => { release = done }))
    h.ipMonitor.getCurrentIp.mockReturnValue(new Promise(() => {}))
    const finished = vi.fn()
    const pending = h.start().then(result => { finished(result); return result })
    await vi.waitFor(() => expect(h.tunController.start).toHaveBeenCalledOnce())
    expect(finished).not.toHaveBeenCalled()
    release({ success: false, message: 'fixture baseline failure' })
    expect((await pending).warning).toContain('fixture baseline failure')
    h.cancel()
  })
  it('keeps a native startup failure without launching post-start IP checks', async () => {
    const h = ipStartupHarness(mode)
    h.tunController.start.mockResolvedValue({ success: false, error: 'native check failed' })
    expect(await h.start()).toEqual({ success: false, error: 'native check failed' })
    expect(h.ipMonitor.getCurrentIp).not.toHaveBeenCalled()
  })
  it('records a rejected background provider without rejecting completed native startup', async () => {
    const h = ipStartupHarness(mode)
    h.ipMonitor.getCurrentIp.mockRejectedValue(new Error('fixture provider failed'))
    expect((await h.start()).success).toBe(true)
    await Promise.resolve()
    expect(h.logEvent).toHaveBeenCalledWith('warn', 'tun', 'background VPN IP polling failed', { error: 'fixture provider failed' })
  })
  it('ignores cancellation during an in-flight polling response before rebaseline', async () => {
    vi.useFakeTimers()
    const h = ipStartupHarness(mode)
    let release!: (value: any) => void
    h.ipMonitor.recheck.mockReturnValue(new Promise(done => { release = done }))
    await h.start()
    h.areTunRoutesActive.mockResolvedValue(true)
    await vi.advanceTimersByTimeAsync(2000)
    expect(h.ipMonitor.recheck).toHaveBeenCalledOnce()
    h.cancel()
    release({ ip: '198.51.100.1', isLeak: false })
    await Promise.resolve()
    expect(h.ipMonitor.recheck).toHaveBeenCalledExactlyOnceWith(true, expect.any(Function))
    expect(h.sendToMainWindow).not.toHaveBeenCalled()
  })
  it('ignores cancellation during the final route probe', async () => {
    vi.useFakeTimers()
    const h = ipStartupHarness(mode)
    let release!: (value: boolean) => void
    h.areTunRoutesActive.mockReturnValue(new Promise(done => { release = done }))
    await h.start()
    await vi.advanceTimersByTimeAsync(8000)
    expect(h.areTunRoutesActive).toHaveBeenCalledOnce()
    h.cancel()
    release(true)
    await Promise.resolve()
    expect(h.ipMonitor.recheck).not.toHaveBeenCalledWith(true, expect.any(Function))
  })
})
