// AT-02-004 / AT-02-005: execute the production poll callback with fake OS boundaries.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { spawnSync } from 'node:child_process'
import { describe, expect, it, vi } from 'vitest'
import { TunnelStateMachine } from './tunnelStateMachine'
import { ConnectionLifecycle } from './connectionLifecycle'
import { ipcError, IpcFault, classifyIpcError, readIpcErrorCategory } from '../shared/ipc-result'
import { connectionFailure } from '../shared/operation'
import { RecoveryWorkerError } from './recoveryPsWorker'

const source = readFileSync(join(process.cwd(), 'src/main/tunController.ts'), 'utf8')
const start = source.indexOf('const pollRuntime = async () => {')
const end = source.indexOf('const poller = setInterval(pollRuntime, 250)', start)
if (start < 0 || end < 0) throw new Error('Production startup callback not found')
const callback = source.slice(start + 'const pollRuntime = '.length, end).trim()
const parsedSource = ts.createSourceFile('tunController.ts', source, ts.ScriptTarget.Latest, true)
const classifier = parsedSource.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'classifyTunError')!
const classifierCode = ts.transpileModule(classifier.getText(parsedSource) + ';return classifyTunError;', { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
const classifyTunError = new Function('RecoveryWorkerError', 'classifyIpcError', classifierCode)(RecoveryWorkerError, classifyIpcError)

function harness(retained = false, lockdown: Promise<void> | null = null) {
  const os = {
    retained, lockdown,
    selectProtectedOutbound: vi.fn(async () => {}),
    connectionFailure, ipcError, IpcFault, classifyTunError, readIpcErrorCategory,
    isSingboxRunning: vi.fn(async () => true),
    readOwnedSingboxPid: vi.fn(async () => 731),
    recordOwnedTunAdapter: vi.fn(async (): Promise<void> => { throw new Error('driver identity mismatch') }),
    waitForTunInterface: vi.fn(async () => true),
    applyLowTunInterfaceMetric: vi.fn(async () => {}),
    runPowerShell: vi.fn(async () => '5'),
    isKillSwitchActive: vi.fn(async () => false),
    enableKillSwitch: vi.fn(async (opts: { tunAdapterReady?: Promise<boolean>; signal: AbortSignal }) => ({ success: await opts.tunAdapterReady })),
    strictRecoveryRequired: vi.fn(async () => false),
    readGranularKillSwitchExceptions: vi.fn(() => []),
    getTunAdapterAlias: () => 'Ethernet 5',
    killOwnedRuntimeProcesses: vi.fn(async () => {}),
    waitForOwnedRuntimeToExit: vi.fn(async () => true),
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
let attempts=0, startAbortedReason=null, startAbortedCategory=null, pendingKillSwitch=null, settleFirewallAdapter=null;
let startupPollCompletion=null;
const startAbortController=new AbortController();
let startupCompensationStarted=false;
const maxAttempts=31, poller=1, wantKillSwitch=true, adapterLockdownPromise=lockdown, adapterLockdownCategory='internal';
const runtime={singbox:'fixture.exe'}, proxyOwnerProgramPaths=[], processWaitStarted=0;
const phases={},phaseDurations={},tStart=Date.now();
let currentStatus={running:false,pid:null,startedAt:null,warning:null};
const TUN_ADAPTER_ALIAS='Ethernet 5',mode='directVpn',proxyAddr='',proxyType='socks5';
const vpnProfile={name:'fixture',protocol:'vless'},warning=null,publicWifiCompatibility=true;
const wantAdapterLockdown=false,startOptions={},STABLE_RESET_MS=60000;
let killSwitchEngaged=false,killSwitchWarning=null,restartAttempt=0,lastStartOptions=null;
let preparedXraySwitch=retained ? {slots:{a:{port:51001},b:{port:51002}},configurationKey:'fixture'} : null;
let xraySwitchRuntime=null,clashApiInfo={port:51003,secret:'0123456789abcdef0123456789abcdef'};
let stopInProgress=false,userInitiatedStop=false,stableTimer=null;
function finish(result){if(!resolved){resolved=true;onFinish(result)}}
return {poll: ${callback}, status:()=>currentStatus, switchRuntime:()=>xraySwitchRuntime, signal: startAbortController.signal, requestStop: () => {stopRequested=true;startAbortController.abort()}, exit: () => {resolved=true;settleFirewallAdapter?.(false)}, completion: () => startupPollCompletion};`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
  const control = new Function(...Object.keys(os), compiled)(...Object.values(os)) as { poll: () => Promise<void>; status: () => { running: boolean; pid: number | null }; switchRuntime: () => object | null; signal: AbortSignal; requestStop: () => void; exit: () => void; completion: () => Promise<void> | null }
  return { ...control, ...os }
}

describe('startup callback fault boundaries', () => {
  it('waits for TUN while physical lockdown runs, joining both before ownership/firewall proof (AT-02-002)', async () => {
    let release!: () => void
    const lockdown = new Promise<void>(done => { release = done })
    const h = harness(true, lockdown)
    h.recordOwnedTunAdapter.mockResolvedValue(undefined)
    const pending = h.poll()
    await vi.waitFor(() => expect(h.waitForTunInterface).toHaveBeenCalledOnce())
    expect(h.recordOwnedTunAdapter).not.toHaveBeenCalled()
    expect(h.onFinish).not.toHaveBeenCalled()
    release(); await pending
    expect(h.recordOwnedTunAdapter).toHaveBeenCalledOnce()
    expect(h.onFinish).toHaveBeenCalledWith(expect.objectContaining({ success: true }))
  })
  it('closes the firewall barrier and drains Xray before compensating failed lockdown (AT-02-004/005)', async () => {
    let reject!: (error: Error) => void
    const lockdown = new Promise<void>((_done, fail) => { reject = fail })
    const h = harness(true, lockdown)
    const pending = h.poll()
    await vi.waitFor(() => expect(h.waitForTunInterface).toHaveBeenCalledOnce())
    reject(new Error('lockdown refused'))
    await pending
    expect(h.recordOwnedTunAdapter).not.toHaveBeenCalled()
    expect(h.stopXray).toHaveBeenCalledExactlyOnceWith('startup validation failed')
    expect(h.waitForOwnedRuntimeToExit.mock.invocationCallOrder[0]).toBeLessThan(h.rollbackEarlyAdapterLockdown.mock.invocationCallOrder[0])
    expect(h.stopXray.mock.invocationCallOrder[0]).toBeLessThan(h.rollbackEarlyAdapterLockdown.mock.invocationCallOrder[0])
    expect(h.onFinish).toHaveBeenCalledWith(expect.objectContaining({ success: false }))
    expect(h.selectProtectedOutbound).not.toHaveBeenCalled()
  })
  it.each(['alive', 'unknown', 'kill-failed'] as const)('retains network protection after lockdown failure when runtime exit is %s (AT-02-004 / AT-03-007)', async outcome => {
    let reject!: (error: Error) => void
    const lockdown = new Promise<void>((_done, fail) => { reject = fail })
    const h = harness(true, lockdown)
    if (outcome === 'alive') h.waitForOwnedRuntimeToExit.mockResolvedValue(false)
    if (outcome === 'unknown') h.waitForOwnedRuntimeToExit.mockRejectedValue(new Error('ownership unreadable'))
    if (outcome === 'kill-failed') h.killOwnedRuntimeProcesses.mockRejectedValue(new Error('kill rejected'))
    const pending = h.poll()
    await vi.waitFor(() => expect(h.waitForTunInterface).toHaveBeenCalledOnce())
    reject(new Error('lockdown refused'))
    await pending
    expect(h.stopXray).not.toHaveBeenCalled()
    expect(h.rollbackEarlyAdapterLockdown).not.toHaveBeenCalled()
    expect(h.disableKillSwitchIfActive).not.toHaveBeenCalled()
    expect(h.onFinish).toHaveBeenCalledWith(expect.objectContaining({ success: false, warning: expect.stringContaining('network protection retained') }))
    expect(h.selectProtectedOutbound).not.toHaveBeenCalled()
  })
  it.each([
    ['preserved-stop', 'complete'], ['release', 'complete'], ['startup', 'complete'],
    ['late-cancel', 'complete'], ['startup', 'partial'], ['startup', 'throw']
  ] as const)('reports only settled full cleanup after %s: %s (AT-00-003 / AT-03-007)', async (phase, outcome) => {
    let method!: ts.MethodDeclaration
    const visit = (node: ts.Node) => {
      if (ts.isMethodDeclaration(node) && node.name.getText(parsedSource) === 'restartProtected') method = node
      ts.forEachChild(node, visit)
    }
    visit(parsedSource)
    const code = ts.transpileModule(`return ({${method.getText(parsedSource)}}).restartProtected`, {
      compilerOptions: { target: ts.ScriptTarget.ES2022 }
    }).outputText
    const cancellation = new AbortController()
    let resolve!: (value: unknown) => void, reject!: (error: Error) => void
    const cleanup = new Promise((ok, fail) => { resolve = ok; reject = fail })
    const deps = {
      connectionFailure, ipcError, readIpcErrorCategory, classifyTunError,
      transitionCancelRequested: false, protectedRestartCallback: null, currentStatus: {},
      lastStartOptions: null, settingsStore: { get: () => ({}) }, notifyStatus: vi.fn(), logEvent: vi.fn(),
      waitForTunRelease: vi.fn(async () => {
        if (phase === 'release') { cancellation.abort(); return 'cancelled' }
        return 'released'
      })
    }
    const restart = new Function(...Object.keys(deps), code)(...Object.values(deps))
    const engine = {
      stop: vi.fn().mockResolvedValueOnce(phase === 'preserved-stop' ? connectionFailure('internal') : { success: true })
        .mockReturnValueOnce(cleanup),
      start: vi.fn(async () => {
        if (phase === 'late-cancel') { cancellation.abort(); return { success: true } }
        return connectionFailure('internal')
      })
    }
    const onCleanup = vi.fn()
    const pending = restart.call(engine, 'fixture', { mode: 'directVpn' }, { signal: cancellation.signal, onCleanup })
    await vi.waitFor(() => expect(engine.stop).toHaveBeenCalledTimes(2))
    expect(engine.stop).toHaveBeenNthCalledWith(1, { preserveNetworkProtection: true, preserveLastStartOptions: true })
    expect(engine.stop).toHaveBeenNthCalledWith(2)
    expect(onCleanup).not.toHaveBeenCalled()
    const receipt = outcome === 'partial'
      ? { ...connectionFailure('internal'), networkCleanup: { baseline: true, firewall: false, adapters: true } }
      : { success: true, networkCleanup: { baseline: true, firewall: true, adapters: true } }
    if (outcome === 'throw') reject(new Error('cleanup failed'))
    else resolve(receipt)
    expect(await pending).toMatchObject({ success: false })
    expect(onCleanup).toHaveBeenCalledTimes(outcome === 'throw' ? 0 : 1)
    if (outcome !== 'throw') expect(onCleanup).toHaveBeenCalledWith(receipt)
  })
  it('returns a timeout receipt without exposing native compensation errors (AT-00-004)', async () => {
    const h = harness()
    h.isSingboxRunning.mockResolvedValue(false)
    h.stopXray.mockRejectedValue(new Error('FAKE-native-secret at C:\\Users\\Private\\xray.exe'))
    for (let i=0;i<31;i++) await h.poll()
    expect(h.onFinish.mock.calls[0][0]).toMatchObject({ success: false, category: 'timeout', code: ipcError('timeout').code, warning: expect.any(String) })
    expect(JSON.stringify(h.onFinish.mock.calls)).not.toMatch(/FAKE-native-secret|Private|xray.exe/)
    expect(h.logEvent).toHaveBeenCalledWith('warn', 'tun', 'timeout xray cleanup failed', expect.objectContaining({ message: expect.stringContaining('FAKE-native-secret') }))
    expect(h.disableKillSwitchIfActive).toHaveBeenCalledOnce()
    expect(h.rollbackEarlyAdapterLockdown).toHaveBeenCalledOnce()
  })
  it('reads the owned startup PID without spawning PowerShell when the isolated native read succeeds (AT-00-002/AT-02-002)', async () => {
    const tree = ts.createSourceFile('tunController.ts', source, ts.ScriptTarget.Latest, true)
    const helper = tree.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'readOwnedSingboxPid')!
    const code = ts.transpileModule(helper.getText(tree) + '; return readOwnedSingboxPid;', { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
    const native = vi.fn(async () => 731), powershell = vi.fn(async () => { throw new Error('Unexpected fallback') })
    const readPid = new Function('runPowerShell', 'psSingleQuote', 'readOwnedRuntimePidNative', 'logEvent', code)(powershell, () => '', native, vi.fn())
    expect(await readPid('C:\\VPNTE\\runtime\\vpnte-sing-box.exe')).toBe(731)
    expect(native).toHaveBeenCalledExactlyOnceWith('C:\\VPNTE\\runtime\\vpnte-sing-box.exe')
    expect(powershell).not.toHaveBeenCalled()
  })
  it.each(['owned', 'foreign', 'prefix collision', 'ambiguous', 'unreadable'] as const)('requires one exact executable path in the PowerShell fallback: %s', async outcome => {
    const executable = 'C:\\VPN\\runtime\\vpnte-sing-box.exe'
    const row = { ExecutablePath: executable, ProcessId: 731 }
    const rows = outcome === 'owned' ? [row] : outcome === 'ambiguous' ? [row, { ...row, ProcessId: 732 }]
      : [{ ...row, ExecutablePath: outcome === 'unreadable' ? null : outcome === 'foreign'
        ? 'C:\\Foreign\\vpnte-sing-box.exe' : 'C:\\VPN\\runtime-evil\\vpnte-sing-box.exe' }]
    const tree = ts.createSourceFile('tunController.ts', source, ts.ScriptTarget.Latest, true)
    const helper = tree.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'readOwnedSingboxPid')!
    const encodedRows = Buffer.from(JSON.stringify(rows)).toString('base64')
    const runPowerShell = async (script: string) => {
      const prefix = `$fixture=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encodedRows}'))); function Get-CimInstance { [CmdletBinding()] param([string]$ClassName,[string]$Filter) $fixture };`
      const result = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(prefix + script, 'utf16le').toString('base64')], { encoding: 'utf8', windowsHide: true, timeout: 10_000 })
      if (result.status !== 0) throw new Error('Runtime observation failed')
      return result.stdout
    }
    const code = ts.transpileModule(helper.getText(tree) + '; return readOwnedSingboxPid;', { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
    const native = vi.fn().mockRejectedValue(new Error('native read unavailable'))
    const readPid = new Function('runPowerShell', 'psSingleQuote', 'readOwnedRuntimePidNative', 'logEvent', code)(runPowerShell,
      (value: string) => `'${value.replaceAll("'", "''")}'`, native, vi.fn())
    if (outcome === 'owned') expect(await readPid(executable)).toBe(731)
    else await expect(readPid(executable)).rejects.toThrow('Runtime observation failed')
  }, 15_000)
  it('feeds the actual successful poll status and owned PID into the production FSM/lane (AT-00-002)', async () => {
    const h = harness()
    h.recordOwnedTunAdapter.mockResolvedValue(undefined)
    const model = new TunnelStateMachine(() => ({ ...h.status(), softApplied: false }))
    const lane = new ConnectionLifecycle(() => {}, undefined, undefined, model)
    const result = await lane.start(async () => { await h.poll(); return h.onFinish.mock.calls[0][0] })
    expect(result.success).toBe(true)
    expect(h.readOwnedSingboxPid).toHaveBeenCalledExactlyOnceWith('fixture.exe')
    expect(model.snapshot).toMatchObject({ state: 'connected', mode: 'tun', pid: 731 })
  })

  it.each(['denied', 'cancelled', 'exited'])('compensates %s during owned PID confirmation (AT-00-003/AT-02-004)', async outcome => {
    const h = harness()
    h.recordOwnedTunAdapter.mockResolvedValue(undefined)
    h.readOwnedSingboxPid.mockImplementationOnce(async () => {
      if (outcome === 'denied') throw new Error('PID read denied')
      if (outcome === 'cancelled') h.requestStop()
      else h.exit()
      return 731
    })
    await h.poll()
    expect(h.notifyStatus).not.toHaveBeenCalledWith('running')
    expect(h.status().running).toBe(false)
    if (outcome !== 'exited') {
      expect(h.killOwnedRuntimeProcesses).toHaveBeenCalledOnce()
      expect(h.onFinish).toHaveBeenCalledWith(expect.objectContaining({ success: false }))
    }
  })
  it('awaits WFP priority reservation before continuing startup and stops on conflict (AT-03-010)', async () => {
    const reserveStart = source.indexOf('// Reserve the sublayer before sing-box')
    const reserveEnd = source.indexOf("mark('preflight')", reserveStart)
    expect(reserveStart).toBeGreaterThan(-1)
    expect(reserveEnd).toBeLessThan(source.indexOf('startXray(', reserveEnd))
    const compiled = ts.transpileModule(`return async function(){${source.slice(reserveStart, reserveEnd)} return {success:true}}`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
    let release!: () => void
    const reserve = vi.fn(() => new Promise<void>(done => { release = done }))
    const signal = new AbortController().signal
    const logEvent = vi.fn()
    const bindings = { wantKillSwitch: true, timeAsync: async (_phase: string, effect: Function) => effect(), reserveKillSwitchIpv6Priority: reserve,
      startAbortController: { signal }, finishStart: (result: unknown) => result, connectionFailure, classifyTunError, ipcError, logEvent }
    const run = new Function(...Object.keys(bindings),compiled)(...Object.values(bindings))
    const done = vi.fn()
    const pending = run().then(done)
    expect(reserve).toHaveBeenCalledExactlyOnceWith(signal)
    await Promise.resolve()
    expect(done).not.toHaveBeenCalled()
    release();await pending
    expect(done).toHaveBeenCalledWith({success:true})
    const conflict = new IpcFault('conflict')
    conflict.message = 'FAKE-native-secret at C:\\Users\\Private\\wfp.exe'
    reserve.mockRejectedValueOnce(conflict)
    expect(await run()).toEqual(connectionFailure('conflict', 'Конфликт IPv6-фильтров WFP: остановите TUN/VPN другого приложения и повторите подключение'))
    for (const [fault, category] of [
      [Object.assign(new Error('FAKE-native-secret'), { code: 'EACCES' }), 'permission'],
      [Object.assign(new Error('FAKE-native-secret'), { code: 'ENOTFOUND' }), 'network'],
      [new RecoveryWorkerError('timeout', 'FAKE-native-secret'), 'timeout'],
      [new RecoveryWorkerError('busy', 'FAKE-native-secret'), 'conflict'],
      [Object.assign(new Error('FAKE-native-secret'), { killed: true, signal: 'SIGTERM', code: null }), 'timeout'],
      [Object.assign(new Error('FAKE-native-secret'), { killed: true, signal: 'SIGTERM', code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' }), 'internal'],
      [new IpcFault('validation'), 'validation'], [new DOMException('FAKE-native-secret', 'AbortError'), 'cancelled']
    ] as const) {
      reserve.mockRejectedValueOnce(fault)
      const result = await run()
      expect(result).toMatchObject({ success: false, category, code: ipcError(category).code })
      expect(JSON.stringify(result)).not.toMatch(/FAKE-native-secret|Private/)
    }
    expect(logEvent).toHaveBeenCalledWith('warn', 'tun', 'WFP priority reservation failed', conflict)
  })
  it('probes immediately and keeps the 250 ms retry timer (AT-02-002)', () => {
    const registrationStart = source.indexOf('const poller = setInterval(pollRuntime, 250)')
    const registrationEnd = source.indexOf('void pollRuntime()', registrationStart) + 'void pollRuntime()'.length
    const schedule = vi.fn(() => 1)
    const probe = vi.fn(async () => {})
    new Function('setInterval', 'pollRuntime', source.slice(registrationStart, registrationEnd))(schedule, probe)
    expect(schedule).toHaveBeenCalledExactlyOnceWith(probe, 250)
    expect(probe).toHaveBeenCalledOnce()
  })
  it('never overlaps the immediate probe with an interval tick (AT-02-005)', async () => {
    const h = harness()
    h.recordOwnedTunAdapter.mockResolvedValue(undefined)
    let release!: (value: boolean) => void
    h.isSingboxRunning.mockReturnValue(new Promise(done => { release = done }))
    const pending = h.poll()
    await h.poll()
    expect(h.isSingboxRunning).toHaveBeenCalledOnce()
    release(true)
    await pending
    expect(h.onFinish).toHaveBeenCalledOnce()
  })
  it.each(['process', 'ownership', 'metric', 'firewall'])('ignores late %s success after process exit (AT-00-003 / AT-02-005)', async phase => {
    const h = harness()
    h.recordOwnedTunAdapter.mockResolvedValue(undefined)
    let release!: () => void
    const held = new Promise<void>(done => { release = done })
    const boundary = phase === 'process' ? h.isSingboxRunning : phase === 'ownership' ? h.recordOwnedTunAdapter : phase === 'metric' ? h.applyLowTunInterfaceMetric : h.enableKillSwitch
    boundary.mockImplementation((async () => { await held; return phase === 'firewall' ? { success: true } : phase === 'process' ? true : undefined }) as any)
    const pending = h.poll()
    await vi.waitFor(() => expect(boundary).toHaveBeenCalledOnce())
    h.exit()
    const released = vi.fn()
    void h.completion()!.then(released)
    await Promise.resolve()
    expect(released).not.toHaveBeenCalled()
    release()
    await pending
    await h.completion()
    expect(h.onFinish).not.toHaveBeenCalled()
    expect(h.notifyStatus).not.toHaveBeenCalledWith('running')
    expect(h.startCompetingTunWatch).not.toHaveBeenCalled()
    expect(released).toHaveBeenCalledOnce()
  })
  it('awaits timeout compensation and stops an owned zombie before network rollback (AT-02-004)', async () => {
    const h = harness()
    h.isSingboxRunning.mockResolvedValue(false)
    for (let i=0;i<30;i++) await h.poll()
    let release!: () => void
    h.killOwnedRuntimeProcesses.mockReturnValue(new Promise<void>(done => { release = done }))
    const pending = h.poll()
    await vi.waitFor(() => expect(h.killOwnedRuntimeProcesses).toHaveBeenCalledOnce())
    expect(h.disableKillSwitchIfActive).not.toHaveBeenCalled()
    expect(h.onFinish).not.toHaveBeenCalled()
    release()
    await pending
    expect(h.waitForOwnedRuntimeToExit).toHaveBeenCalledOnce()
    expect(h.disableKillSwitchIfActive).toHaveBeenCalledOnce()
    expect(h.rollbackEarlyAdapterLockdown).toHaveBeenCalledOnce()
    expect(h.onFinish).toHaveBeenCalledWith(expect.objectContaining({success:false,warning:null}))
  })
  it('retains protection and reports unconfirmed zombie exit on timeout (AT-02-004)', async () => {
    const h = harness()
    h.isSingboxRunning.mockResolvedValue(false)
    h.waitForOwnedRuntimeToExit.mockResolvedValue(false)
    for (let i=0;i<31;i++) await h.poll()
    expect(h.disableKillSwitchIfActive).not.toHaveBeenCalled()
    expect(h.rollbackEarlyAdapterLockdown).not.toHaveBeenCalled()
    expect(h.stopXray).toHaveBeenCalledOnce()
    expect(h.onFinish).toHaveBeenCalledWith(expect.objectContaining({success:false,warning:expect.stringContaining('exit not confirmed')}))
  })
  it('shares adapter readiness only after exact ownership validation (AT-02-004)', async () => {
    const h = harness()
    let verify!: () => void
    h.recordOwnedTunAdapter.mockReturnValue(new Promise(resolve => { verify = resolve }))
    const pending = h.poll()
    await vi.waitFor(() => expect(h.recordOwnedTunAdapter).toHaveBeenCalledOnce())
    const gate = h.enableKillSwitch.mock.calls[0][0].tunAdapterReady!
    expect(h.enableKillSwitch.mock.calls[0][0].signal).toBe(h.signal)
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

  it('establishes the initial live selector before publishing a retained-slot startup (AT-02-002)', async () => {
    const h = harness(true)
    h.recordOwnedTunAdapter.mockResolvedValue(undefined)
    let select!: () => void
    h.selectProtectedOutbound.mockReturnValueOnce(new Promise<void>(done => { select = done }))
    const pending = h.poll()
    await vi.waitFor(() => expect(h.selectProtectedOutbound).toHaveBeenCalledOnce())
    expect(h.selectProtectedOutbound).toHaveBeenCalledWith({ port: 51003, secret: '0123456789abcdef0123456789abcdef' }, 'a')
    expect(h.readOwnedSingboxPid).not.toHaveBeenCalled()
    expect(h.onFinish).not.toHaveBeenCalled()
    expect(h.switchRuntime()).toBeNull()
    select()
    await pending
    expect(h.onFinish).toHaveBeenCalledWith({ success: true, warning: null })
    expect(h.switchRuntime()).toMatchObject({ configurationKey: 'fixture', slots: { a: { port: 51001 }, b: { port: 51002 } } })
  })

  it('compensates selector readback failure without publishing ready slots (AT-02-004/005)', async () => {
    const h = harness(true)
    h.recordOwnedTunAdapter.mockResolvedValue(undefined)
    h.selectProtectedOutbound.mockRejectedValueOnce(new Error('selector readback failed'))
    await h.poll()
    expect(h.onFinish).toHaveBeenCalledWith(expect.objectContaining({ success: false }))
    expect(h.switchRuntime()).toBeNull()
    expect(h.notifyStatus).not.toHaveBeenCalledWith('running')
    expect(h.killOwnedRuntimeProcesses).toHaveBeenCalledOnce()
    expect(h.stopXray).toHaveBeenCalledOnce()
    expect(h.disableKillSwitchIfActive).toHaveBeenCalledOnce()
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

  it.each(['alive', 'probe failed', 'kill failed'])('retains protection after validation failure when runtime is %s (AT-02-004 / AT-03-007)', async outcome => {
    const h = harness()
    if (outcome === 'alive') h.waitForOwnedRuntimeToExit.mockResolvedValue(false)
    if (outcome === 'probe failed') h.waitForOwnedRuntimeToExit.mockRejectedValue(new Error('exit probe failed'))
    if (outcome === 'kill failed') h.killOwnedRuntimeProcesses.mockRejectedValue(new Error('process cleanup failed'))
    await h.poll()
    expect(h.stopXray).not.toHaveBeenCalled()
    expect(h.rollbackEarlyAdapterLockdown).not.toHaveBeenCalled()
    expect(h.disableKillSwitchIfActive).not.toHaveBeenCalled()
    expect(h.notifyStatus).not.toHaveBeenCalledWith('stopped')
    expect(h.onFinish).toHaveBeenCalledWith(expect.objectContaining({ success: false, warning: expect.any(String) }))
  })

  it('waits for delayed runtime exit before releasing protection (AT-02-004)', async () => {
    const h = harness()
    let release!: (exited: boolean) => void
    h.waitForOwnedRuntimeToExit.mockReturnValue(new Promise(resolve => { release = resolve }))
    const pending = h.poll()
    await vi.waitFor(() => expect(h.waitForOwnedRuntimeToExit).toHaveBeenCalledOnce())
    expect(h.disableKillSwitchIfActive).not.toHaveBeenCalled()
    expect(h.onFinish).not.toHaveBeenCalled()
    release(true)
    await pending
    expect(h.disableKillSwitchIfActive).toHaveBeenCalledOnce()
  })

  it('reports every independent rollback failure after confirmed exit', async () => {
    const h = harness()
    h.stopXray.mockRejectedValue(new Error('xray cleanup failed'))
    h.rollbackEarlyAdapterLockdown.mockRejectedValue(new Error('adapter cleanup failed'))
    h.disableKillSwitchIfActive.mockRejectedValue(new Error('firewall cleanup failed'))
    await expect(h.poll()).resolves.toBeUndefined()
    const result = h.onFinish.mock.calls[0][0]
    expect(result.success).toBe(false)
    for (const name of ['xray','adapter','firewall']) {
      expect(result.warning).toContain(`${name} cleanup:`)
      expect(h.logEvent).toHaveBeenCalledWith('error', 'tun', 'startup rollback step failed', expect.objectContaining({ message: `${name} cleanup failed` }))
    }
    expect(result.warning).not.toContain('cleanup failed')
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
