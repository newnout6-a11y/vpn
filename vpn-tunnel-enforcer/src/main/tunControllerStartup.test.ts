// AT-02-004 / AT-02-005: execute the production poll callback with fake OS boundaries.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'

const source = readFileSync(join(process.cwd(), 'src/main/tunController.ts'), 'utf8')
const start = source.indexOf('const poller = setInterval(async () => {')
const end = source.indexOf('}, 250)', start)
if (start < 0 || end < 0) throw new Error('Production startup callback not found')
const callback = source.slice(start + 'const poller = setInterval('.length, end + 1)

function harness() {
  const os = {
    isSingboxRunning: vi.fn(async () => true),
    recordOwnedTunAdapter: vi.fn(async (): Promise<void> => { throw new Error('driver identity mismatch') }),
    waitForTunInterface: vi.fn(async () => true),
    applyLowTunInterfaceMetric: vi.fn(async () => {}),
    runPowerShell: vi.fn(async () => '5'),
    isKillSwitchActive: vi.fn(async () => false),
    enableKillSwitch: vi.fn(async (opts: { tunAdapterReady?: Promise<boolean> }) => ({ success: await opts.tunAdapterReady })),
    strictRecoveryRequired: vi.fn(async () => false),
    readGranularKillSwitchExceptions: vi.fn(() => []),
    getTunAdapterAlias: () => 'Ethernet 5',
    killOwnedRuntimeProcesses: vi.fn(async () => {}),
    stopXray: vi.fn(async () => {}),
    rollbackEarlyAdapterLockdown: vi.fn(async () => {}),
    disableKillSwitchIfActive: vi.fn(async () => {}),
    clearInterval: vi.fn(), logEvent: vi.fn(), notifyStatus: vi.fn(),
    recordForensicTunEvent: vi.fn(), mark: vi.fn(), endPhase: vi.fn(),
    clearRestartTimers: vi.fn(), startCompetingTunWatch: vi.fn(),
    notify: vi.fn(), setTimeout: vi.fn(() => 1),
    phaseStart: () => 0, timeAsync: async (_phase: string, effect: () => Promise<unknown>) => effect(),
    onFinish: vi.fn((_result: any) => {})
  }
  // Only this extracted callback runs; never import/start the actual engine.
  const compiled = ts.transpileModule(`
let resolved=false, successHandled=false, pollInFlight=false, stopRequested=false;
let attempts=0, startAbortedReason=null, pendingKillSwitch=null, settleFirewallAdapter=null;
const maxAttempts=30, poller=1, wantKillSwitch=true, adapterLockdownPromise=null;
const runtime={singbox:'fixture.exe'}, proxyOwnerProgramPaths=[], processWaitStarted=0;
const phases={},phaseDurations={},tStart=Date.now();
let currentStatus={running:false,pid:null,startedAt:null,warning:null};
const TUN_ADAPTER_ALIAS='Ethernet 5',mode='directVpn',proxyAddr='',proxyType='socks5';
const vpnProfile={name:'fixture',protocol:'vless'},warning=null,publicWifiCompatibility=true;
const wantAdapterLockdown=false,startOptions={},STABLE_RESET_MS=60000;
let killSwitchEngaged=false,killSwitchWarning=null,restartAttempt=0,lastStartOptions=null;
let stopInProgress=false,userInitiatedStop=false,stableTimer=null;
function finish(result){if(!resolved){resolved=true;onFinish(result)}}
return {poll: ${callback}, requestStop: () => {stopRequested=true}};`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
  const control = new Function(...Object.keys(os), compiled)(...Object.values(os)) as { poll: () => Promise<void>; requestStop: () => void }
  return { ...control, ...os }
}

describe('startup callback fault boundaries', () => {
  it('shares adapter readiness only after exact ownership validation (AT-02-004)', async () => {
    const h = harness()
    let verify!: () => void
    h.recordOwnedTunAdapter.mockReturnValue(new Promise(resolve => { verify = resolve }))
    const pending = h.poll()
    await vi.waitFor(() => expect(h.recordOwnedTunAdapter).toHaveBeenCalledOnce())
    const gate = h.enableKillSwitch.mock.calls[0][0].tunAdapterReady!
    const observed = vi.fn()
    void gate.then(observed)
    await Promise.resolve()
    expect(observed).not.toHaveBeenCalled()
    verify()
    await pending
    expect(observed).toHaveBeenCalledWith(true)
    expect(h.onFinish).toHaveBeenCalledWith({ success: true, warning: null })
  })

  it.each(['interface wait', 'ownership'])('settles cancellation during %s before rollback (AT-02-005)', async phase => {
    const h = harness()
    h.recordOwnedTunAdapter.mockResolvedValue(undefined)
    let release!: () => void
    if (phase === 'interface wait') h.waitForTunInterface.mockReturnValue(new Promise(resolve => { release = () => resolve(true) }))
    else h.recordOwnedTunAdapter.mockReturnValue(new Promise(resolve => { release = resolve }))
    const pending = h.poll()
    await vi.waitFor(() => expect(phase === 'interface wait' ? h.waitForTunInterface : h.recordOwnedTunAdapter).toHaveBeenCalledOnce())
    h.requestStop()
    release()
    await pending
    expect(await h.enableKillSwitch.mock.calls[0][0].tunAdapterReady).toBe(false)
    expect(h.disableKillSwitchIfActive).toHaveBeenCalledOnce()
    expect(h.onFinish).toHaveBeenCalledOnce()
    expect(h.onFinish).toHaveBeenCalledWith(expect.objectContaining({ success: false }))
    expect(h.notifyStatus).not.toHaveBeenCalledWith('running')
  })
  it('completes a verified startup once without performing rollback', async () => {
    const h = harness()
    h.recordOwnedTunAdapter.mockResolvedValue(undefined)
    await h.poll()
    await h.poll()
    expect(h.onFinish).toHaveBeenCalledOnce()
    expect(h.onFinish).toHaveBeenCalledWith({ success: true, warning: null })
    expect(h.notifyStatus).toHaveBeenCalledWith('running')
    expect(h.killOwnedRuntimeProcesses).not.toHaveBeenCalled()
  })

  it('fails a required firewall check instead of reporting a protected connection', async () => {
    const h = harness()
    h.recordOwnedTunAdapter.mockResolvedValue(undefined)
    h.enableKillSwitch.mockResolvedValue({ success: false })
    await h.poll()
    expect(h.onFinish).toHaveBeenCalledWith(expect.objectContaining({ success: false }))
    expect(h.notifyStatus).not.toHaveBeenCalledWith('running')
    expect(h.killOwnedRuntimeProcesses).toHaveBeenCalledOnce()
    expect(h.disableKillSwitchIfActive).toHaveBeenCalledOnce()
  })

  it('fails an unready TUN and rolls back before recording ownership', async () => {
    const h = harness()
    h.waitForTunInterface.mockResolvedValue(false)
    await h.poll()
    expect(h.onFinish).toHaveBeenCalledWith(expect.objectContaining({ success: false }))
    expect(h.recordOwnedTunAdapter).not.toHaveBeenCalled()
    expect(h.notifyStatus).not.toHaveBeenCalledWith('running')
    expect(h.killOwnedRuntimeProcesses).toHaveBeenCalledOnce()
    expect(h.disableKillSwitchIfActive).toHaveBeenCalledOnce()
  })

  it('settles a rejected process probe and independently performs cleanup', async () => {
    const h = harness()
    h.isSingboxRunning.mockRejectedValue(new Error('probe failed'))
    await expect(h.poll()).resolves.toBeUndefined()
    expect(h.clearInterval).toHaveBeenCalledWith(1)
    expect(h.killOwnedRuntimeProcesses).toHaveBeenCalledOnce()
    expect(h.stopXray).toHaveBeenCalledOnce()
    expect(h.rollbackEarlyAdapterLockdown).toHaveBeenCalledOnce()
    expect(h.disableKillSwitchIfActive).toHaveBeenCalledOnce()
    expect(h.onFinish).toHaveBeenCalledWith(expect.objectContaining({ success: false }))
    expect(h.notifyStatus).not.toHaveBeenCalledWith('running')
  })

  it('waits for the parallel firewall transaction before rolling back a rejected ownership check', async () => {
    const h = harness()
    let settle!: (result: { success: boolean }) => void
    h.enableKillSwitch.mockReturnValue(new Promise(resolve => { settle = resolve }))
    const pending = h.poll()
    await vi.waitFor(() => expect(h.recordOwnedTunAdapter).toHaveBeenCalledOnce())
    expect(h.disableKillSwitchIfActive).not.toHaveBeenCalled()
    expect(h.onFinish).not.toHaveBeenCalled()
    settle({ success: true })
    await expect(pending).resolves.toBeUndefined()
    expect(h.disableKillSwitchIfActive).toHaveBeenCalledOnce()
    expect(h.onFinish).toHaveBeenCalledOnce()
    expect(h.onFinish).toHaveBeenCalledWith(expect.objectContaining({ success: false }))
    expect(h.notifyStatus).toHaveBeenCalledWith('stopped')
  })

  it('reports every cleanup failure and still settles the connection attempt', async () => {
    const h = harness()
    h.killOwnedRuntimeProcesses.mockRejectedValue(new Error('process cleanup failed'))
    h.stopXray.mockRejectedValue(new Error('xray cleanup failed'))
    h.rollbackEarlyAdapterLockdown.mockRejectedValue(new Error('adapter cleanup failed'))
    h.disableKillSwitchIfActive.mockRejectedValue(new Error('firewall cleanup failed'))
    await expect(h.poll()).resolves.toBeUndefined()
    const result = h.onFinish.mock.calls[0][0]
    expect(result.success).toBe(false)
    for (const name of ['process','xray','adapter','firewall']) expect(result.warning).toContain(`${name} cleanup failed`)
    expect(h.onFinish).toHaveBeenCalledOnce()
  })

  it('still settles failure when a status listener throws', async () => {
    const h = harness()
    h.notifyStatus.mockImplementation(() => { throw new Error('listener failed') })
    await expect(h.poll()).resolves.toBeUndefined()
    expect(h.onFinish).toHaveBeenCalledWith(expect.objectContaining({ success: false }))
  })

  it('does not overlap slow native probes on successive timer ticks', async () => {
    const h = harness()
    let settle!: (running: boolean) => void
    h.isSingboxRunning.mockReturnValue(new Promise(resolve => { settle = resolve }))
    const pending = h.poll()
    await h.poll()
    expect(h.isSingboxRunning).toHaveBeenCalledOnce()
    settle(false)
    await pending
    h.isSingboxRunning.mockResolvedValue(false)
    await h.poll()
    expect(h.isSingboxRunning).toHaveBeenCalledTimes(2)
    expect(h.onFinish).not.toHaveBeenCalled()
  })
})
