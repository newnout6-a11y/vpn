// AT-00-002/003/007; AT-02-002/004/005: two owned userspace upstreams share one TUN.
// All OS/process/socket boundaries are fixtures; no local VPN or firewall is touched.
import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const fixture = vi.hoisted(() => ({ children: [] as any[], sockets: [] as any[], holdPorts: new Set<number>(),
  rejectAuth: false, writePid: vi.fn(async (..._args: any[]) => {}), removePid: vi.fn(async (..._args: any[]) => {}),
  preflight: vi.fn(async (..._args: any[]) => {}), stopPreflight: vi.fn(async () => {}),
  cleanup: vi.fn(async (..._args: any[]) => true), allow: vi.fn(async () => ({ success: true })),
  beforeSpawn: null as null | (() => void) }))
vi.mock('child_process', () => {
  const api = { spawn: vi.fn(() => {
    fixture.beforeSpawn?.()
    const child = Object.assign(new EventEmitter(), { pid: 5000 + fixture.children.length, exitCode: null, signalCode: null,
      stdout: new EventEmitter(), stderr: new EventEmitter(), kill: vi.fn(() => { child.emit('exit', 0); return true }) })
    fixture.children.push(child)
    return child
  }) }
  return { ...api, default: api }
})
vi.mock('net', () => {
  const api = { isIP: () => 4, Socket: class extends EventEmitter {
    port = 0
    phase = 0
    destroyed = false
    constructor() { super(); fixture.sockets.push(this) }
    connect = vi.fn((port: number) => { this.port = port; queueMicrotask(() => this.emit('connect')) })
    write = vi.fn((_bytes: Buffer) => {
      if (fixture.holdPorts.has(this.port)) return true
      const reply = this.phase++ === 0 ? [5, fixture.rejectAuth ? 0 : 2] : [1, 0]
      queueMicrotask(() => { for (const byte of reply) this.emit('data', Buffer.from([byte])) })
      return true
    })
    setTimeout = vi.fn()
    destroy = vi.fn(() => { this.destroyed = true })
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
vi.mock('./managedChildProcess', () => ({ writeManagedChildPidFile: fixture.writePid,
  removeManagedChildPidFile: fixture.removePid, cleanupManagedChildPidFile: fixture.cleanup }))
vi.mock('./firewallKillSwitch', () => ({ ensureKillSwitchProgramAllowed: fixture.allow }))
vi.mock('./xrayPreflight', () => ({ runXrayConfigPreflight: fixture.preflight, stopXrayPreflights: fixture.stopPreflight }))

const outbound = { type: 'vless', server: '192.0.2.1', server_port: 443, uuid: 'fixture' }
const auth = { username: 'slot-user', password: 'slot-password' }
let engine: typeof import('./xrayEngine')
beforeEach(async () => {
  vi.resetModules(); vi.useFakeTimers(); vi.clearAllMocks()
  fixture.children = []; fixture.sockets = []; fixture.holdPorts.clear(); fixture.rejectAuth = false
  fixture.beforeSpawn = null
  fixture.writePid.mockResolvedValue(undefined); fixture.removePid.mockResolvedValue(undefined)
  fixture.preflight.mockResolvedValue(undefined); fixture.stopPreflight.mockResolvedValue(undefined)
  fixture.cleanup.mockResolvedValue(true); fixture.allow.mockResolvedValue({ success: true })
  engine = await import('./xrayEngine')
})
afterEach(async () => {
  for (const child of fixture.children) child.emit('close', 0)
  await engine.stopXray()
  vi.useRealTimers()
})
async function activeA() {
  await engine.startXrayInSlot('a', outbound, { portOverride: 51001, socksAuth: auth })
  engine.activateXraySlot('a')
  return fixture.children[0]
}

describe('owned Xray upstream slots', () => {
  it('preserves legacy noauth and adds password auth only when explicitly requested', () => {
    const xray = engine.toXrayOutbound(outbound)
    expect(engine.buildXrayConfig(xray, 51001).inbounds[0].settings).toEqual({ udp: true })
    expect(engine.buildXrayConfig(xray, 51001, { socksAuth: auth }).inbounds[0].settings).toEqual({
      udp: true, auth: 'password', accounts: [{ user: auth.username, pass: auth.password }]
    })
  })
  it.each([{ username: '', password: 'secret' }, { username: 'user', password: 'я'.repeat(128) }])(
    'rejects invalid authentication before touching either runtime', async invalid => {
      await expect(engine.startXray(outbound, { socksAuth: invalid })).rejects.toThrow('authentication')
      expect(() => engine.startXrayInSlot('a', outbound, { socksAuth: invalid })).toThrow('authentication')
      expect(fixture.stopPreflight).not.toHaveBeenCalled(); expect(fixture.cleanup).not.toHaveBeenCalled()
      expect(fixture.children).toHaveLength(0)
    })
  it('requires slot authentication, validates slot IDs and refuses activation without readiness', async () => {
    await expect(engine.startXrayInSlot('a', outbound)).rejects.toThrow('authentication')
    expect(() => engine.getXraySlotStatus('foreign' as any)).toThrow('Invalid Xray slot')
    expect(() => engine.activateXraySlot('b')).toThrow('not ready')
  })
  it('does not stop the active slot for an already cancelled cold start', async () => {
    const previous = await activeA(), controller = new AbortController()
    controller.abort()
    await expect(engine.startXray(outbound, { signal: controller.signal })).rejects.toThrow('cancelled')
    expect(previous.kill).not.toHaveBeenCalled(); expect(fixture.stopPreflight).not.toHaveBeenCalled()
    expect(engine.getXrayStatus().running).toBe(true)
  })
  it('authenticates fragmented SOCKS responses before readiness and persists isolated slot files', async () => {
    const result = await engine.startXrayInSlot('a', outbound, { portOverride: 51001, socksAuth: auth })
    expect(result.socksPort).toBe(51001)
    const socket = fixture.sockets[0]
    expect(socket.write.mock.calls[0][0]).toEqual(Buffer.from([5, 1, 2]))
    expect(socket.write.mock.calls[1][0]).toEqual(Buffer.concat([Buffer.from([1, 9]), Buffer.from('slot-user'),
      Buffer.from([13]), Buffer.from('slot-password')]))
    expect(socket.destroy).toHaveBeenCalledOnce()
    expect(fixture.writePid).toHaveBeenCalledWith(expect.stringMatching(/xray-a\.pid$/), expect.objectContaining({
      pid: 5000, configPath: expect.stringMatching(/xray-a\.json$/)
    }))
    expect(engine.getActiveXraySlot()).toBeNull()
    engine.activateXraySlot('a')
    expect(engine.getXrayStatus()).toMatchObject({ running: true, pid: 5000, socksPort: 51001 })
  })
  it('starts and switches the candidate without stopping the selected upstream', async () => {
    const previous = await activeA()
    fixture.cleanup.mockClear()
    await engine.startXrayInSlot('b', { ...outbound, server: '192.0.2.2' }, { portOverride: 51002, socksAuth: auth })
    expect(fixture.cleanup).toHaveBeenCalledExactlyOnceWith(expect.stringMatching(/xray-b\.pid$/), 'xray-engine', expect.any(Function))
    expect(previous.kill).not.toHaveBeenCalled()
    expect(engine.getXrayStatus().pid).toBe(previous.pid)
    expect(engine.getXrayDialTarget()).toEqual({ host: '192.0.2.1', port: 443 })
    engine.activateXraySlot('b')
    expect(engine.getXrayStatus()).toMatchObject({ running: true, pid: 5001, socksPort: 51002 })
    expect(engine.getXrayDialTarget()).toEqual({ host: '192.0.2.2', port: 443 })
    await engine.stopXraySlot('a', 'commit completed')
    expect(previous.kill).toHaveBeenCalledOnce()
    expect(engine.getXrayStatus().running).toBe(true)
    expect(fixture.stopPreflight).not.toHaveBeenCalled()
  })
  it('preserves startXray cold-start compatibility while selecting the requested authenticated slot', async () => {
    await engine.startXray(outbound, { slot: 'a', portOverride: 51001, socksAuth: auth })
    expect(engine.getActiveXraySlot()).toBe('a')
    expect(engine.getXrayStatus()).toMatchObject({ running: true, pid: 5000, socksPort: 51001 })
    expect(fixture.writePid).toHaveBeenCalledWith(expect.stringMatching(/xray-a\.pid$/), expect.any(Object))
  })
  it.each(['legacy', 'b'] as const)('reaps an owned crashed %s runtime without an in-memory handle before a cold slot-a spawn', async crashed => {
    const pidName = crashed === 'legacy' ? 'xray.pid' : 'xray-b.pid'
    const orphan = { alive: true, kill: vi.fn() }
    orphan.kill.mockImplementation(() => { orphan.alive = false })
    fixture.cleanup.mockImplementation(async (pidPath, owner) => {
      expect(owner).toBe('xray-engine')
      if (String(pidPath).endsWith(pidName) && orphan.alive) orphan.kill()
      return true
    })
    fixture.beforeSpawn = () => expect(orphan.alive).toBe(false)
    expect(engine.getXraySlotStatus('b').pid).toBeNull()
    expect(engine.getXrayStatus().pid).toBeNull()
    await engine.startXray(outbound, { slot: 'a', portOverride: 51001, socksAuth: auth })
    expect(orphan.kill).toHaveBeenCalledOnce()
    expect(fixture.cleanup.mock.calls.slice(0, 3).map(call => String(call[0]).split(/[\\/]/).at(-1))).toEqual([
      'xray.pid', 'xray-a.pid', 'xray-b.pid'
    ])
    expect(engine.getXrayStatus()).toMatchObject({ running: true, pid: 5000 })
  })
  it('also reconciles slot PID namespaces before a legacy cold spawn', async () => {
    await engine.startXray(outbound, { portOverride: 51003 })
    expect(fixture.cleanup.mock.calls.slice(0, 3).map(call => String(call[0]).split(/[\\/]/).at(-1))).toEqual([
      'xray.pid', 'xray-a.pid', 'xray-b.pid'
    ])
    expect(engine.getActiveXraySlot()).toBeNull()
    expect(engine.getXrayStatus().running).toBe(true)
  })
  it.each(['foreign identity', 'unconfirmed exit', 'rejected read', 'missing receipt'] as const)(
    'refuses cold launch after %s in a different PID namespace', async outcome => {
      fixture.cleanup.mockImplementation(async path => {
        if (!String(path).endsWith('xray-b.pid')) return true
        if (outcome === 'rejected read') throw new Error('orphan lookup refused')
        return outcome === 'missing receipt' ? undefined as any : false
      })
      await expect(engine.startXray(outbound, { slot: 'a', portOverride: 51001, socksAuth: auth })).rejects.toThrow(
        outcome === 'rejected read' ? 'orphan lookup refused' : 'cleanup not confirmed')
      expect(fixture.children).toHaveLength(0); expect(fixture.preflight).not.toHaveBeenCalled()
      expect(fixture.writePid).not.toHaveBeenCalled()
    })
  it.each(['cancel', 'stop'] as const)('fences late orphan reconciliation after %s and excludes concurrent slot staging', async action => {
    let release!: (value: boolean) => void
    fixture.cleanup.mockReturnValueOnce(new Promise<boolean>(resolve => { release = resolve }))
    const controller = new AbortController()
    const start = engine.startXray(outbound, { slot: 'a', portOverride: 51001, socksAuth: auth, signal: controller.signal }).catch(error => error)
    await vi.waitFor(() => expect(fixture.cleanup).toHaveBeenCalledOnce())
    await expect(engine.startXrayInSlot('b', outbound, { portOverride: 51002, socksAuth: auth })).rejects.toThrow('operation in progress')
    let stop: Promise<void> | undefined
    if (action === 'cancel') controller.abort()
    else stop = engine.stopXray('stop during crash recovery')
    release(true)
    await stop
    expect((await start).message).toContain('cancelled')
    expect(fixture.children).toHaveLength(0); expect(fixture.cleanup).toHaveBeenCalledOnce()
  })
  it('refuses a candidate port already held by the selected slot', async () => {
    const previous = await activeA()
    await expect(engine.startXrayInSlot('b', outbound, { portOverride: 51001, socksAuth: auth })).rejects.toThrow('owned by another slot')
    expect(fixture.children).toHaveLength(1); expect(previous.kill).not.toHaveBeenCalled()
  })
  it('cancels a held candidate and waits for its exit while the selected upstream stays ready', async () => {
    const previous = await activeA()
    fixture.holdPorts.add(51002)
    const start = engine.startXrayInSlot('b', outbound, { portOverride: 51002, socksAuth: auth }).catch(error => error)
    await vi.waitFor(() => expect(fixture.children).toHaveLength(2))
    const candidate = fixture.children[1]
    candidate.kill.mockImplementation(() => true)
    const stop = engine.stopXraySlot('b', 'cancel candidate')
    const settled = vi.fn(); void stop.then(settled)
    await vi.advanceTimersByTimeAsync(100)
    expect(settled).not.toHaveBeenCalled()
    expect(candidate.kill).toHaveBeenCalledOnce()
    expect(previous.kill).not.toHaveBeenCalled()
    expect(engine.getXrayStatus().running).toBe(true)
    candidate.emit('exit', 0)
    await stop
    expect((await start).message).toContain('cancelled')
    expect(engine.getXraySlotStatus('b').pid).toBeNull()
    expect(engine.getXrayStatus().pid).toBe(previous.pid)
  })
  it('rejects a foreign noauth listener and never selects it', async () => {
    const previous = await activeA()
    fixture.rejectAuth = true
    const start = engine.startXrayInSlot('b', outbound, { portOverride: 51002, socksAuth: auth }).catch(error => error)
    await vi.advanceTimersByTimeAsync(3600)
    expect((await start).message).toContain('authentication required')
    expect(engine.getActiveXraySlot()).toBe('a')
    expect(previous.kill).not.toHaveBeenCalled()
    expect(() => engine.activateXraySlot('b')).toThrow('not ready')
  })
  it('does not activate a child that exited before authenticated readiness', async () => {
    await activeA(); fixture.holdPorts.add(51002)
    const start = engine.startXrayInSlot('b', outbound, { portOverride: 51002, socksAuth: auth }).catch(error => error)
    await vi.waitFor(() => expect(fixture.sockets).toHaveLength(2))
    fixture.children[1].emit('exit', 1)
    fixture.sockets[1].emit('data', Buffer.from([5, 2]))
    fixture.sockets[1].emit('data', Buffer.from([1, 0]))
    expect((await start).message).toContain('exited')
    expect(engine.getXrayStatus().running).toBe(true)
    expect(() => engine.activateXraySlot('b')).toThrow('not ready')
  })
  it('cancels pending preflight and rejects late completion without spawning a candidate', async () => {
    const previous = await activeA()
    let release!: () => void
    fixture.preflight.mockReturnValueOnce(new Promise<void>(resolve => { release = resolve }))
    const start = engine.startXrayInSlot('b', outbound, { portOverride: 51002, socksAuth: auth }).catch(error => error)
    await vi.waitFor(() => expect(fixture.preflight).toHaveBeenCalledTimes(2))
    const stop = engine.stopXraySlot('b')
    release(); await stop
    expect((await start).message).toContain('cancelled')
    expect(fixture.children).toHaveLength(1); expect(previous.kill).not.toHaveBeenCalled()
  })
  it('refuses an unconfirmed slot orphan cleanup without disturbing the active slot', async () => {
    const previous = await activeA(); fixture.cleanup.mockResolvedValueOnce(false)
    await expect(engine.startXrayInSlot('b', outbound, { portOverride: 51002, socksAuth: auth })).rejects.toThrow('cleanup not confirmed')
    expect(fixture.children).toHaveLength(1); expect(previous.kill).not.toHaveBeenCalled()
  })
  it('requires durable candidate PID and confirmed firewall permission', async () => {
    const previous = await activeA()
    fixture.writePid.mockRejectedValueOnce(new Error('cannot persist candidate'))
    await expect(engine.startXrayInSlot('b', outbound, { portOverride: 51002, socksAuth: auth })).rejects.toThrow('cannot persist candidate')
    fixture.allow.mockResolvedValueOnce({ success: false })
    await expect(engine.startXrayInSlot('b', outbound, { portOverride: 51002, socksAuth: auth })).rejects.toThrow('firewall permission')
    expect(previous.kill).not.toHaveBeenCalled(); expect(engine.getXrayStatus().running).toBe(true)
  })
  it('drains both slots on legacy cold start and preserves the legacy status contract', async () => {
    await activeA()
    await engine.startXrayInSlot('b', outbound, { portOverride: 51002, socksAuth: auth })
    await engine.startXray(outbound, { portOverride: 51003 })
    expect(fixture.children[0].kill).toHaveBeenCalledOnce(); expect(fixture.children[1].kill).toHaveBeenCalledOnce()
    expect(engine.getActiveXraySlot()).toBeNull()
    expect(engine.getXrayStatus()).toMatchObject({ running: true, pid: 5002, socksPort: 51003 })
  })
  it('attempts every owned exit even if one fails and retains only its unresolved handle for retry', async () => {
    const previous = await activeA()
    await engine.startXrayInSlot('b', outbound, { portOverride: 51002, socksAuth: auth })
    previous.kill.mockImplementation(() => true)
    const stop = engine.stopXray().catch(error => error)
    await vi.advanceTimersByTimeAsync(1001)
    expect((await stop).message).toContain('exit not confirmed')
    expect(engine.getXraySlotStatus('a').pid).toBe(previous.pid)
    expect(engine.getXraySlotStatus('b').pid).toBeNull()
    previous.kill.mockImplementation(() => { previous.emit('close', 0); return true })
    await engine.stopXray('retry all')
    expect(engine.getXraySlotStatus('a').pid).toBeNull()
  })
})
