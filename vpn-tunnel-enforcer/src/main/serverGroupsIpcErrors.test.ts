// AT-00-004/005, F-074/F-143: real subscription handler, guard and operation registry.
import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { IPC_VERSION, IpcFault, ipcError, type IpcErrorCategory } from '../shared/ipc-result'

const state = vi.hoisted(() => ({
  handlers: new Map<string, (...args: any[]) => Promise<any>>(),
  stores: new Map<string, Record<string, any>>(), resolve: vi.fn(),
  storeFault: undefined as unknown
}))
vi.mock('electron', () => ({ ipcMain: { handle: (channel: string, handler: (...args: any[]) => Promise<any>) => state.handlers.set(channel, handler) } }))
vi.mock('electron-store', () => ({ default: class {
  name: string
  constructor(options: { name: string; defaults?: Record<string, unknown> }) {
    this.name = options.name
    state.stores.set(this.name, structuredClone(options.defaults ?? {}))
  }
  get(key: string) {
    if (state.storeFault) throw state.storeFault
    return state.stores.get(this.name)?.[key]
  }
  set(key: string, value: unknown) { state.stores.get(this.name)![key] = value }
  get path() { return `/tmp/${this.name}.json` }
  get store() { return state.stores.get(this.name)! }
  set store(value: Record<string, any>) { state.stores.set(this.name, value) }
} }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({}) } }))
vi.mock('./vpnProfiles', () => ({
  resolveVpnProfiles: (...args: unknown[]) => state.resolve(...args),
  normalizeClientDevice: (device: unknown) => device ?? 'pc',
  applyClientDeviceToOutbound: (outbound: unknown) => outbound,
  clientFingerprintForDevice: () => 'chrome'
}))
vi.mock('./ipcLogging', () => ({ compactForIpcLog: () => '[redacted]' }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
import { installTrustedIpcBoundary } from './ipcSecurity'
import { serverGroups, registerServerGroupsHandlers, refreshDueServerGroups } from './serverGroups'
import { operations } from './operations'
import { logEvent } from './appLogger'

class Sender extends EventEmitter { isDestroyed() { return false } }
let sender: Sender, groupId: string, saved: string
const invoke = (channel: string, ...args: unknown[]) => state.handlers.get(channel)!({ sender }, ...args)
const raw = 'FAKE-SECRET at C:\\private\\credentials.json\n    at subscriptionHandler (C:\\private\\main.js:1:2)'
const failures: Array<[IpcErrorCategory, () => unknown]> = [
  ['network', () => Object.assign(new Error(raw), { code: 'ECONNREFUSED' })],
  ['permission', () => Object.assign(new Error(raw), { code: 'EACCES' })],
  ['validation', () => Object.assign(new IpcFault('validation'), { message: raw })],
  ['conflict', () => Object.assign(new IpcFault('conflict'), { message: raw })],
  ['internal', () => new Error(raw)],
  ['cancelled', () => Object.assign(new Error(raw), { name: 'AbortError' })],
  ['timeout', () => Object.assign(new Error(raw), { code: 'ETIMEDOUT' })]
]
function expectFailure(response: any, category: IpcErrorCategory) {
  expect(response).toEqual({ version: IPC_VERSION, correlationId: expect.stringMatching(/^ipc_[0-9a-f]{32}$/), ok: false, error: ipcError(category) })
  expect(JSON.stringify(response)).not.toMatch(/FAKE-SECRET|\bat |[A-Z]:[\\/]/)
  expect(JSON.stringify(state.stores.get('server-picker'))).toBe(saved)
  expect(JSON.stringify(state.stores.get('server-groups'))).not.toContain('FAKE-SECRET')
  expect(JSON.stringify(vi.mocked(logEvent).mock.calls)).not.toContain('FAKE-SECRET')
  const operation = operations.list().find(item => item.correlationId === response.correlationId)!
  expect(operation).toMatchObject({ kind: 'refresh', status: 'error', category, owner: 'manual', source: 'ipc' })
  expect(operations.isBusy(`refresh:${groupId}`)).toBe(false)
  expect(sender.eventNames()).toEqual([])
}
beforeEach(() => {
  state.storeFault = undefined; state.resolve.mockReset(); state.handlers.clear()
  state.stores.get('server-groups')!.groups = []
  state.stores.get('server-picker')!.profiles = []
  sender = new Sender()
  groupId = serverGroups.createGroup({ name: 'Subscription', source: 'subscription', sourceUrl: 'https://sub.example.test/list', importedAt: 1, status: 'active', lastFetchedAt: 1 }).id
  state.stores.get('server-picker')!.profiles = [{ id: 'saved', groupId, name: 'Saved', protocol: 'vless', server: 'saved.example.test', port: 443, enabled: true }]
  state.stores.get('server-picker')!.activeProfileId = 'saved'
  saved = JSON.stringify(state.stores.get('server-picker'))
  vi.mocked(logEvent).mockClear()
  installTrustedIpcBoundary(); registerServerGroupsHandlers()
})
afterEach(async () => {
  state.storeFault = undefined; sender.emit('destroyed')
  await operations.close(); operations.resumeAdmission()
})
describe('subscription domain taxonomy (AT-00-004/005)', () => {
  it.each(failures)('maps a caught resolver %s fault into an outer error and matching history', async (category, create) => {
    state.resolve.mockRejectedValue(create())
    const response = await invoke('groups:refresh', groupId)
    expectFailure(response, category)
    expect(serverGroups.getGroup(groupId)).toMatchObject({ lastFetchedAt: 1, lastFetchError: ipcError(category).message })
    expect(serverGroups.getGroup(groupId)?.status).toBe(category === 'network' || category === 'timeout' ? 'unreachable' : 'active')
    expect(await invoke('groups:list')).toMatchObject({ ok: true, result: [expect.objectContaining({ lastFetchError: ipcError(category).message })] })
  })
  it.each(failures)('maps a store %s fault without reflecting exception data', async (category, create) => {
    state.storeFault = create()
    const response = await invoke('groups:refresh', groupId)
    state.storeFault = undefined
    expectFailure(response, category)
    expect(state.resolve).not.toHaveBeenCalled()
  })
  it('rejects a missing group as conflict and a manual group as validation', async () => {
    expectFailure(await invoke('groups:refresh', 'missing'), 'conflict')
    const manual = serverGroups.createGroup({ name: 'Manual', source: 'manual', importedAt: 1, status: 'active' })
    expectFailure(await invoke('groups:refresh', manual.id), 'validation')
    expect(state.resolve).not.toHaveBeenCalled()
  })
  it('rejects an empty provider list without archiving saved profiles or claiming success', async () => {
    state.resolve.mockResolvedValue({ profiles: [], source: 'subscription', fetched: true })
    expectFailure(await invoke('groups:refresh', groupId), 'validation')
    expect(serverGroups.getGroup(groupId)).toMatchObject({ status: 'expired', lastFetchError: 'Подписка вернула пустой список профилей' })
  })
  it.each(failures)('keeps all saved device variants after a secondary %s fault', async (category, create) => {
    const profiles = state.stores.get('server-picker')!.profiles
    profiles.push({ ...profiles[0], id: 'android', clientDevice: 'android' })
    saved = JSON.stringify(state.stores.get('server-picker'))
    state.resolve.mockResolvedValueOnce({ profiles: [{ name: 'Fresh', outbound: { type: 'vless', server: 'fresh.example.test', server_port: 443 } }], source: 'subscription', fetched: true })
      .mockRejectedValueOnce(create())
    expectFailure(await invoke('groups:refresh', groupId), category)
    expect(state.resolve).toHaveBeenCalledTimes(2)
  })
  it('classifies invalid refresh policies and missing groups without fetching', async () => {
    for (const minutes of [0, 1441, 1.5]) {
      expect(await invoke('groups:set-refresh-policy', groupId, minutes)).toMatchObject({ ok: false, error: ipcError('validation') })
    }
    expect(await invoke('groups:set-refresh-policy', 'missing', 15)).toMatchObject({ ok: false, error: ipcError('conflict') })
    expect(state.resolve).not.toHaveBeenCalled()
  })
  it('preserves a newer expiry status when an in-flight request has a local failure', async () => {
    let reject!: (reason: unknown) => void
    state.resolve.mockImplementation(() => new Promise((_done, fail) => { reject = fail }))
    const run = invoke('groups:refresh', groupId)
    await vi.waitFor(() => expect(state.resolve).toHaveBeenCalledOnce())
    serverGroups.updateGroup(groupId, { status: 'expired' })
    reject(new Error(raw))
    expectFailure(await run, 'internal')
    expect(serverGroups.getGroup(groupId)?.status).toBe('expired')
  })
  it('continues an automatic sweep after a typed network error and an empty response', async () => {
    const { id: _id, ...original } = serverGroups.getGroup(groupId)!
    serverGroups.createGroup(original)
    state.resolve.mockRejectedValueOnce(Object.assign(new Error(raw), { code: 'ENOTFOUND' }))
      .mockResolvedValueOnce({ profiles: [], source: 'subscription', fetched: true })
    expect(await refreshDueServerGroups()).toEqual({ refreshed: 0, failed: 2 })
    expect(JSON.stringify(state.stores.get('server-picker'))).toBe(saved)
    expect(JSON.stringify(vi.mocked(logEvent).mock.calls)).not.toContain('FAKE-SECRET')
  })
})
