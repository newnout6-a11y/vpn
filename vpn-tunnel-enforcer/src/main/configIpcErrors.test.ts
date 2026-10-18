// AT-00-004, F-074: real config handlers and production IPC boundary; file/store/dialog faults.
import { EventEmitter } from 'node:events'
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { IPC_VERSION, IpcFault, ipcError, type IpcErrorCategory } from '../shared/ipc-result'

const state = vi.hoisted(() => ({
  handlers: new Map<string, (...args: any[]) => Promise<any>>(),
  selection: '', destination: '', fault: undefined as unknown,
  failDialog: false, failStore: false, failSetKey: '',
  stores: new Map<string, Record<string, unknown>>()
}))
vi.mock('electron', () => ({
  ipcMain: { handle: (channel: string, handler: (...args: any[]) => Promise<any>) => state.handlers.set(channel, handler) },
  dialog: {
    showOpenDialog: vi.fn(async () => {
      if (state.failDialog) throw state.fault
      return { canceled: !state.selection, filePaths: state.selection ? [state.selection] : [] }
    }),
    showSaveDialog: vi.fn(async () => {
      if (state.failDialog) throw state.fault
      return { canceled: !state.destination, filePath: state.destination }
    })
  }
}))
vi.mock('electron-store', () => ({ default: class {
  name: string
  constructor(options: { name: string; defaults: Record<string, unknown> }) {
    this.name = options.name; state.stores.set(this.name, structuredClone(options.defaults))
  }
  get(key: string) {
    if (state.failStore) throw state.fault
    return state.stores.get(this.name)?.[key]
  }
  set(key: string, value: unknown) {
    if (state.failSetKey === key) { state.failSetKey = ''; throw state.fault }
    state.stores.get(this.name)![key] = value
  }
} }))
vi.mock('./sharedStores', () => ({
  serverPickerStore: { get: () => [], set: vi.fn() },
  serverGroupsStore: { get: () => [], set: vi.fn() },
  granularKillSwitchStore: { get: (key: string) => key === 'killSwitchLevel' ? 'off' : [], set: vi.fn() }
}))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./ipcLogging', () => ({ compactForIpcLog: () => '[redacted]' }))
import { installTrustedIpcBoundary } from './ipcSecurity'
import { collectCurrentConfig, registerConfigManagerIpcHandlers } from './configManager'
import { logEvent } from './appLogger'

class Sender extends EventEmitter { isDestroyed() { return false } }
let sender: Sender, directory: string
const invoke = (channel: string, ...args: unknown[]) => state.handlers.get(channel)!({ sender }, ...args)
const raw = 'FAKE-SECRET at C:\\private\\credentials.json\n    at featureHandler (C:\\private\\main.js:1:2)'
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
  expect(response).toEqual({ version: IPC_VERSION, correlationId: expect.stringMatching(/^[\da-f-]{36}$/), ok: false, error: ipcError(category) })
  expect(JSON.stringify(response)).not.toMatch(/FAKE-SECRET|\bat |[A-Z]:[\\/]/)
  const errors = vi.mocked(logEvent).mock.calls.filter(([level]) => level === 'error')
  expect(JSON.stringify(errors)).not.toContain('FAKE-SECRET')
}
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), 'vpnte-config-errors-'))
  sender = new Sender(); state.fault = undefined; state.failDialog = false; state.failStore = false; state.failSetKey = ''
  state.stores.get('notification-prefs')!.notificationPrefs = { ...collectCurrentConfig().notifications, sound: true }
  state.selection = join(directory, 'selected.json'); state.destination = join(directory, 'exported.json')
  writeFileSync(state.selection, JSON.stringify(collectCurrentConfig()))
  state.handlers.clear(); vi.mocked(logEvent).mockClear()
  installTrustedIpcBoundary(); registerConfigManagerIpcHandlers()
})
afterEach(() => { sender.emit('destroyed'); state.failStore = false; rmSync(directory, { recursive: true, force: true }) })

describe('config domain error envelopes (AT-00-004)', () => {
  it.each(failures)('maps %s at each real feature handler without exception text', async (category, create) => {
    // Capture native-dialog selection before injecting a store fault.
    expect((await invoke('config:browse-import')).ok).toBe(true)
    state.fault = create(); state.failStore = true
    expectFailure(await invoke('config:import', state.selection), category)
    expectFailure(await invoke('config:import-apply', state.selection, ['notifications'], 'replace'), category)
    state.failStore = false; state.failDialog = true
    expectFailure(await invoke('config:export', 'redacted'), category)
    expectFailure(await invoke('config:browse-import'), category)
    expect(existsSync(state.destination)).toBe(false)
  })
  it.each(['{broken', JSON.stringify({ version: raw }), ...['notifications', 'rotation', 'killSwitch'].map(section => JSON.stringify({ version: '2.0', [section]: [] }))])('maps malformed selected JSON to validation without reflecting its contents: %s', async content => {
    writeFileSync(state.selection, content)
    expect((await invoke('config:browse-import')).ok).toBe(true)
    expectFailure(await invoke('config:import', state.selection), 'validation')
    expectFailure(await invoke('config:import-apply', state.selection, ['notifications'], 'replace'), 'validation')
  })
  it('classifies missing native-selection authority as permission and keeps cancelled browse nullable', async () => {
    expectFailure(await invoke('config:import', state.selection), 'permission')
    state.selection = ''
    expect(await invoke('config:browse-import')).toMatchObject({ ok: true, result: null })
  })
  it('classifies a cancelled save as cancelled without a file or success result', async () => {
    state.destination = ''
    expectFailure(await invoke('config:export', 'redacted'), 'cancelled')
    expect(existsSync(join(directory, 'exported.json'))).toBe(false)
  })
  it('validates and applies a partial import, preserving omitted sections', async () => {
    const before = collectCurrentConfig()
    const notifications = { ...before.notifications, sound: false }
    writeFileSync(state.selection, JSON.stringify({ version: '2.0', notifications }))
    expect(await invoke('config:browse-import')).toMatchObject({ ok: true, result: state.selection })
    expect(await invoke('config:import', state.selection)).toMatchObject({ ok: true, result: { success: true, sections: ['notifications'], conflicts: [] } })
    expect(await invoke('config:import-apply', state.selection, ['notifications'], 'replace')).toMatchObject({ ok: true, result: { success: true } })
    expect(collectCurrentConfig()).toEqual({ ...before, exportedAt: expect.any(Number), notifications })
    expectFailure(await invoke('config:import', state.selection), 'permission')
    expect(await invoke('config:export', 'redacted')).toMatchObject({ ok: true, result: { success: true, path: state.destination } })
    expect(existsSync(state.destination)).toBe(true)
  })
  it.each([[], ['dns'], ['notifications', 'missing']].map(sections => [sections]))('rejects empty, absent or unknown selected sections before writing: %j', async sections => {
    const before = structuredClone(state.stores)
    writeFileSync(state.selection, JSON.stringify({ version: '2.0', notifications: collectCurrentConfig().notifications }))
    await invoke('config:browse-import')
    expectFailure(await invoke('config:import-apply', state.selection, sections, 'replace'), 'validation')
    expect(state.stores).toEqual(before)
    expectFailure(await invoke('config:import', state.selection), 'permission')
  })
  it('restores already written sections when a later store write fails and consumes authority', async () => {
    const before = structuredClone(state.stores)
    const incoming = structuredClone(collectCurrentConfig())
    incoming.notifications.sound = false
    incoming.dns.push({ ...incoming.dns[0], id: 'custom', isBuiltin: false })
    writeFileSync(state.selection, JSON.stringify(incoming))
    await invoke('config:browse-import')
    state.fault = Object.assign(new Error(raw), { code: 'EACCES' }); state.failSetKey = 'notificationPrefs'
    expectFailure(await invoke('config:import-apply', state.selection, ['dns', 'notifications'], 'replace'), 'permission')
    expect(state.stores).toEqual(before)
    expectFailure(await invoke('config:import', state.selection), 'permission')
  })
})
