// AT-02-005 / AT-03-007: run production lifecycle bodies with fake OS boundaries.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
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
const noop = () => vi.fn(() => {})
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
