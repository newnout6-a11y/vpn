// AT-06-008 / F-076: a rule changed while the tunnel is still starting must not leave the stale bypass active.
import { beforeEach, describe, expect, it, vi } from 'vitest'

const tun = vi.hoisted(() => ({
  running: false,
  applied: null as { names: string[]; paths: string[] } | null,
  statusCallbacks: [] as Array<(status: string) => void>,
  restart: vi.fn()
}))
const pathReads = vi.hoisted(() => ({ access: vi.fn(), realpath: vi.fn() }))

vi.mock('fs/promises', () => ({
  access: pathReads.access,
  realpath: pathReads.realpath,
  readdir: vi.fn().mockResolvedValue([])
}))

vi.mock('electron', () => ({
  ipcMain: { handle: vi.fn() },
  dialog: { showOpenDialog: vi.fn() },
  app: { getPath: () => '/tmp/test' },
  BrowserWindow: { getAllWindows: () => [] }
}))

vi.mock('electron-store', () => {
  const data: Record<string, any> = { splitTunnelApps: [], splitTunnelEnabled: true }
  return {
    default: class MockStore {
      get(key: string) { return data[key] }
      set(key: string, value: any) { data[key] = value }
    }
  }
})

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

vi.mock('./tunController', () => ({
  tunController: {
    getStatus: () => ({ running: tun.running }),
    // Production returns a defensive copy on every read.
    getAppliedSplitTunnelRules: () => tun.applied ? structuredClone(tun.applied) : null,
    restartWithLastOptions: tun.restart,
    onStatusChange: (cb: (status: string) => void) => { tun.statusCallbacks.push(cb) }
  }
}))

import { ipcMain } from 'electron'
import { getDirectProcessTargets, registerSplitTunnelHandlers, splitTunneling } from './splitTunneling'

function ipcHandler(channel: string): (...args: any[]) => Promise<any> {
  const call = vi.mocked(ipcMain.handle).mock.calls.find(([name]) => name === channel)
  if (!call) throw new Error(`no handler for ${channel}`)
  return call[1] as any
}

function emitStatus(status: string): void {
  for (const cb of tun.statusCallbacks) cb(status)
}

// Simulates start(): snapshot of the rules at the moment the config is generated.
async function snapshotRules(): Promise<void> {
  tun.applied = await getDirectProcessTargets()
}

describe('split tunneling rule change during tunnel start', () => {
  beforeEach(async () => {
    pathReads.access.mockReset().mockResolvedValue(undefined)
    pathReads.realpath.mockReset().mockImplementation(async (path: string) => path)
    tun.running = false
    tun.applied = null
    tun.restart.mockReset()
    tun.restart.mockImplementation(async () => {
      await snapshotRules()
      return { success: true }
    })
    for (const app of splitTunneling.getApps()) await splitTunneling.removeApp(app.id)
    if (tun.statusCallbacks.length === 0) registerSplitTunnelHandlers()
  })

  it('re-applies when a direct rule is revoked after start read the rules', async () => {
    const curl = await splitTunneling.addProcessName('curl')
    await snapshotRules()
    expect(tun.applied?.names).toEqual(['curl.exe'])

    // The user revokes the bypass while the tunnel is still coming up: the hot reload is skipped.
    await ipcHandler('split-tunnel:set-rule')({}, curl.id, 'vpn')
    expect(tun.restart).not.toHaveBeenCalled()

    tun.running = true
    expect(await splitTunneling.reapplyIfRulesChanged()).toBe(true)
    expect(tun.restart).toHaveBeenCalledTimes(1)
    expect(tun.applied?.names).toEqual([])
  })

  it('reacts to the running status notification', async () => {
    await splitTunneling.addProcessName('git')
    tun.applied = { names: [], paths: [] }
    tun.running = true
    emitStatus('running')
    await vi.waitFor(() => expect(tun.restart).toHaveBeenCalledTimes(1))
    expect(tun.applied?.names).toEqual(['git.exe'])
  })

  it('does not restart when the rules the start applied are still current', async () => {
    await splitTunneling.addProcessName('wget')
    await snapshotRules()
    tun.running = true
    expect(await splitTunneling.reapplyIfRulesChanged()).toBe(false)
    emitStatus('running')
    await Promise.resolve()
    expect(tun.restart).not.toHaveBeenCalled()
  })

  it('does nothing while the tunnel is not running or the start could not read the rules', async () => {
    await splitTunneling.addProcessName('ssh')
    tun.applied = { names: [], paths: [] }
    expect(await splitTunneling.reapplyIfRulesChanged()).toBe(false)
    tun.running = true
    tun.applied = null
    expect(await splitTunneling.reapplyIfRulesChanged()).toBe(false)
    expect(tun.restart).not.toHaveBeenCalled()
  })

  it('catches a change made while a rule restart is already in flight', async () => {
    const tool = await splitTunneling.addProcessName('yt-dlp')
    await snapshotRules()
    tun.running = true
    let releaseFirst!: () => void
    tun.restart.mockImplementationOnce(async () => {
      await snapshotRules()
      await new Promise<void>(resolve => { releaseFirst = resolve })
      return { success: true }
    })

    const removal = ipcHandler('split-tunnel:remove-app')({}, tool.id)
    await vi.waitFor(() => expect(tun.restart).toHaveBeenCalledTimes(1))
    // The in-flight restart already read the store; this change lands after it.
    await splitTunneling.addProcessName('aria2c')
    releaseFirst()
    await removal

    await vi.waitFor(() => expect(tun.restart).toHaveBeenCalledTimes(2))
    expect(tun.applied?.names).toEqual(['aria2c.exe'])
  })

  it.each(['failure', 'throw'])('does not retry recursively after restart %s (AT-06-008)', async outcome => {
    await splitTunneling.addProcessName('curl')
    tun.applied = { names: [], paths: [] }
    tun.running = true
    let attempts = 0
    tun.restart.mockImplementation(async () => {
      // Bound the broken implementation so the regression itself cannot hang.
      if (++attempts === 3) tun.running = false
      if (outcome === 'throw') throw new Error('restart fixture failure')
      return { success: false, error: 'restart fixture failure' }
    })

    await splitTunneling.reapplyIfRulesChanged()
    expect(tun.restart).toHaveBeenCalledTimes(1)

    // A later explicit request can retry after the underlying failure is fixed.
    tun.running = true
    tun.restart.mockImplementation(async () => { await snapshotRules(); return { success: true } })
    await splitTunneling.reapplyIfRulesChanged()
    expect(tun.restart).toHaveBeenCalledTimes(2)
    expect(tun.applied?.names).toEqual(['curl.exe'])
  })

  it.each(['stop', 'new-rules'] as const)('discards an asynchronous path read after %s', async change => {
    const app = await splitTunneling.addApp('C:\\Fixture\\tool.exe')
    await splitTunneling.setRule(app.id, 'direct')
    tun.applied = { names: [], paths: [] }
    tun.running = true
    let release!: () => void
    pathReads.access.mockImplementationOnce(() => new Promise<void>(done => { release = done }))
    const reading = splitTunneling.reapplyIfRulesChanged()
    await vi.waitFor(() => expect(release).toBeTypeOf('function'))
    if (change === 'stop') tun.running = false
    else tun.applied = { names: ['new-generation.exe'], paths: [] }
    release()
    expect(await reading).toBe(false)
    expect(tun.restart).not.toHaveBeenCalled()
  })

  it('reads each installed path only once for both matching lists (AT-06-008)', async () => {
    const app = await splitTunneling.addApp('C:\\Fixture\\tool.exe')
    await splitTunneling.setRule(app.id, 'direct')
    await splitTunneling.addProcessName('curl')
    pathReads.access.mockClear()
    pathReads.realpath.mockClear()
    expect(await getDirectProcessTargets()).toEqual({ names: ['curl.exe'], paths: ['C:\\Fixture\\tool.exe'] })
    expect(pathReads.access).toHaveBeenCalledTimes(1)
    expect(pathReads.realpath).toHaveBeenCalledTimes(1)
  })
})
