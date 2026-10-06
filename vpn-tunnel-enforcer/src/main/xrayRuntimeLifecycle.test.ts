// AT-02-002/004/005: execute production startup/stop with owned child/socket fixtures.
import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({ child: null as any, socket: null as any,
  removePid: vi.fn(async (..._args: any[]) => {}), writePid: vi.fn(async (..._args: any[]) => {}),
  allow: vi.fn(async () => ({ success: true })), stopPreflight: vi.fn(async () => {}) }))
vi.mock('child_process', () => {
  const api = { spawn: vi.fn(() => { state.removePid.mockClear(); return state.child }) }
  return { ...api, default: api }
})
vi.mock('net', () => {
  const api = { isIP: () => 4, Socket: class extends EventEmitter {
    constructor() { super(); state.socket = this }
    connect = vi.fn(); setTimeout = vi.fn(); destroy = vi.fn()
  } }
  return { ...api, default: api }
})
vi.mock('fs/promises', () => {
  const api = { readFile: vi.fn(), writeFile: vi.fn(async () => {}), rename: vi.fn(async () => {}) }
  return { ...api, default: api }
})
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./runtimeDirSecurity', () => ({ ensureElevatedRuntimeDirHardened: vi.fn(async () => ({ hardened: true })) }))
vi.mock('./vpnProfiles', () => ({ clientFingerprintForDevice: () => 'chrome' }))
vi.mock('./tunController', () => ({ getTunRuntimeDir: () => 'C:\\fixture', getBundledResource: () => 'xray.exe',
  copyResourceIfStale: vi.fn(async () => true), pickFreeLocalPort: vi.fn(async () => 50123) }))
vi.mock('./managedChildProcess', () => ({ writeManagedChildPidFile: state.writePid,
  removeManagedChildPidFile: state.removePid, cleanupManagedChildPidFile: vi.fn(async () => true) }))
vi.mock('./firewallKillSwitch', () => ({ ensureKillSwitchProgramAllowed: state.allow }))
vi.mock('./xrayPreflight', () => ({ runXrayConfigPreflight: vi.fn(async () => {}), stopXrayPreflights: state.stopPreflight }))

const outbound = { type: 'vless', server: '192.0.2.1', server_port: 443, uuid: 'fixture' }
let engine: typeof import('./xrayEngine')
beforeEach(async () => {
  vi.resetModules(); vi.useFakeTimers(); vi.clearAllMocks()
  state.writePid.mockResolvedValue(undefined); state.allow.mockResolvedValue({ success: true })
  state.stopPreflight.mockResolvedValue(undefined)
  const child = Object.assign(new EventEmitter(), { pid: 1234, exitCode: null, signalCode: null, killed: false,
    stdout: new EventEmitter(), stderr: new EventEmitter(), kill: vi.fn(() => { child.killed = true; return true }) })
  state.child = child; state.socket = null
  engine = await import('./xrayEngine')
})
afterEach(async () => { state.child.emit('close', 0); await engine?.stopXray(); vi.useRealTimers() })

async function cancellingStartup() {
  const controller = new AbortController()
  const promise = engine.startXray(outbound, { signal: controller.signal })
  const result = promise.then(() => null, error => error as Error)
  await vi.waitFor(() => expect(state.socket).not.toBeNull())
  controller.abort()
  await vi.waitFor(() => expect(state.child.kill).toHaveBeenCalled())
  return { result }
}

describe('Xray runtime exit ownership', () => {
  it('leaves an orphan PID record for identity-checked startup cleanup when no child handle exists', async () => {
    await engine.stopXray('no child')
    expect(state.removePid).not.toHaveBeenCalled()
  })
  it.each(['exit', 'close'])('waits for delayed %s before deleting PID or finishing cancellation', async event => {
    const { result } = await cancellingStartup()
    const settled = vi.fn(); void result.then(settled)
    await vi.advanceTimersByTimeAsync(100)
    expect(settled).not.toHaveBeenCalled()
    expect(state.removePid).not.toHaveBeenCalled()
    expect(engine.getXrayStatus().pid).toBe(1234)
    state.child.emit(event, 0)
    expect((await result)?.message).toContain('cancelled')
    expect(state.removePid).toHaveBeenCalledWith(expect.any(String), 1234)
    expect(engine.getXrayStatus().pid).toBeNull()
  })
  it.each(['undelivered', 'throws'])('retains PID/child after kill %s and permits a stop retry', async mode => {
    if (mode === 'throws') state.child.kill.mockImplementation(() => { throw new Error('access denied') })
    const { result } = await cancellingStartup()
    await vi.advanceTimersByTimeAsync(1001)
    expect((await result)?.message).toContain('exit not confirmed')
    expect(state.removePid).not.toHaveBeenCalled()
    expect(engine.getXrayStatus().pid).toBe(1234)
    state.child.kill.mockImplementation(() => { state.child.emit('close', 0); return true })
    await engine.stopXray('retry')
    expect(state.child.kill).toHaveBeenCalledTimes(2)
    expect(engine.getXrayStatus().pid).toBeNull()
  })
  it('owns and stops a child when cancellation arrives while PID persistence is pending', async () => {
    let release!: () => void
    state.writePid.mockReturnValue(new Promise<void>(resolve => { release = resolve }))
    const controller = new AbortController()
    const result = engine.startXray(outbound, { signal: controller.signal }).then(() => null, error => error)
    await vi.waitFor(() => expect(state.writePid).toHaveBeenCalledOnce())
    expect(engine.getXrayStatus().pid).toBe(1234)
    controller.abort(); release()
    await vi.waitFor(() => expect(state.child.kill).toHaveBeenCalled())
    state.child.emit('exit', 0)
    expect((await result).message).toContain('cancelled')
    expect(engine.getXrayStatus().pid).toBeNull()
  })
  it('does not mark ready after the child exited during readiness', async () => {
    const result = engine.startXray(outbound).then(() => null, error => error)
    await vi.waitFor(() => expect(state.socket).not.toBeNull())
    state.child.emit('exit', 1)
    state.socket.emit('connect')
    expect(await result).toBeInstanceOf(Error)
    expect(engine.getXrayStatus().running).toBe(false)
  })
  it('confirms ordinary stop even if a previous kill request already set killed=true', async () => {
    const start = engine.startXray(outbound)
    await vi.waitFor(() => expect(state.socket).not.toBeNull())
    state.socket.emit('connect'); await start
    state.child.killed = true
    const stop = engine.stopXray('ordinary')
    const settled = vi.fn(); void stop.then(settled)
    await vi.advanceTimersByTimeAsync(100)
    expect(settled).not.toHaveBeenCalled()
    expect(state.child.kill).toHaveBeenCalledOnce()
    state.child.emit('exit', 0); await stop
    expect(state.removePid).toHaveBeenCalledOnce()
  })
})
