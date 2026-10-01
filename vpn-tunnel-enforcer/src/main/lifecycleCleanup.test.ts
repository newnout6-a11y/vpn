// AT-02-005 / AT-03-007: run production lifecycle bodies with fake OS boundaries.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { isIP } from 'node:net'
import { EventEmitter } from 'node:events'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'

function body(file: string, name: string): string {
  const source = ts.createSourceFile(file, readFileSync(join(process.cwd(), 'src/main', file), 'utf8'), ts.ScriptTarget.Latest, true)
  let found: ts.FunctionDeclaration | ts.MethodDeclaration | undefined
  function visit(node: ts.Node) {
    if ((ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)) && node.name?.getText(source) === name) found = node
    ts.forEachChild(node, visit)
  }
  visit(source)
  if (!found) throw new Error(`Missing production function ${name}`)
  return found.getText(source)
}
function compile<T>(text: string, dependencies: Record<string, unknown>): T {
  const js = ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.None } }).outputText
  return new Function(...Object.keys(dependencies), js)(...Object.values(dependencies))
}
const noop = () => vi.fn((..._args: any[]) => {})
const done = () => vi.fn(async () => {})

function stopHarness() {
  const os = {
    stopXray: done(), killOwnedRuntimeProcesses: done(), waitForOwnedRuntimeToExit: vi.fn(async () => true),
    rollbackTunNetworkBaselineIfApplied: vi.fn(async () => ({ success: true, message: 'restored' })),
    disableKillSwitchIfActive: vi.fn(async () => ({ success: true, message: 'restored' })),
    rollbackPhysicalAdapterLockdownIfApplied: vi.fn(async (): Promise<{ rolledBack: boolean; skipped?: boolean }> => ({ rolledBack: true })),
    repairOrphanedPhysicalAdapterDns: vi.fn(async () => ({ repaired: false, adapters: [] })),
    ipMonitor: { suspend: noop(), resume: noop() },
    logEvent: noop(), notify: noop(), notifyStatus: noop(), recordForensicTunEvent: noop(),
    clearRestartTimers: noop(), cancelLeakSelfTest: noop(), stopCompetingTunWatch: noop(), stopProxyWatchdog: noop()
  }
  const stop = compile<(options?: { preserveNetworkProtection?: boolean }) => Promise<any>>(`
let startInProgress=false,stopRequested=false,stopInProgress=false,userInitiatedStop=false;
let recoveryCancelGeneration=0,lastStartOptions=null,restartAttempt=0,transitionCancelRequested=false;
let currentStatus={running:true,mode:'directVpn'},clashApiInfo=null,directProxyPort=null,tunnelProbePort=null;
return ({${body('tunController.ts', 'stop')}}).stop;
`, os)
  return { stop, ...os }
}
function mainHarness(name: 'performShutdownCleanup' | 'stopProtection') {
  const os = {
    tunController: { stop: vi.fn(async (): Promise<any> => ({ success: true, networkCleanup: { baseline: true, firewall: true, adapters: true } })) },
    clearOwnedSecretClipboard: done(), stopXray: done(), killOwnedTunRuntimeProcesses: done(), externalProxy: { stopAll: done() },
    rollbackTunNetworkBaselineIfApplied: done(), disableKillSwitchIfActive: done(), rollbackPhysicalAdapterLockdownIfApplied: done(),
    repairOrphanedPhysicalAdapterDns: done(), logEvent: noop(), stopElevatedPsHelper: noop(),
    autoconfig: { getStatus: vi.fn(async () => []), rollback: done() },
    stopServerGroupAutoRefresh: noop(), stopBackgroundTrafficHistory: noop(), stopTrafficConnectionSampler: noop(),
    rollbackSoftAutoconfigIfApplied: done(), stopPeriodicSnapshots: noop(), stopPeriodicLeakTest: noop(), stopNetworkChangeWatcher: noop(),
    stopTrafficForensicsSession: done(), ipMonitor: { clearVpnIp: noop() }, trafficMonitor: { stop: noop() },
    getLocationPrivacyStatus: vi.fn(async () => ({ applied: false })), rollbackLocationPrivacy: done(),
    settingsStore: { save: noop() }, refreshTrayState: noop(), captureSnapshot: done()
  }
  const run = compile<(reason?: string) => Promise<any>>(`
let shutdownInProgress=false,currentSession=null,stopInProgress=false,adaptiveVerificationGeneration=0,activeAdaptiveContext=null;
${body('index.ts', name)}
return ${name};
`, os)
  return { run, ...os }
}

describe('lifecycle cleanup evidence and retries (AT-02-005 / AT-03-007)', () => {
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
  it.each(['runtime', 'baseline', 'firewall', 'adapters', 'dns'])('continues independent cleanup after %s failure', async failing => {
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
    if (failed === 'thrown') h.tunController.stop.mockRejectedValue(new Error('stop failed'))
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
    ensureKillSwitchProgramAllowed: effect(41, { success: true }), waitForLocalSocks: effect(2, undefined),
    removeManagedChildPidFile: effect(1, undefined), logEvent: noop(), getTunRuntimeDir: () => 'fixture-dir',
    toXrayOutbound: () => ({}), buildXrayConfig: () => ({}), join, isIP,
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
let activeXrayState={proc:null};
${text}
return startXray;
`, os)
  return { start, ...os }
}
describe('Xray startup phase measurements (AT-02-002 / AT-02-004)', () => {
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
