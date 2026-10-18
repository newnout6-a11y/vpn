// AT-00-004, F-074: real config handlers and production IPC boundary; file/store/dialog faults.
import { EventEmitter } from 'node:events'
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fstatSync } from 'fs'
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
vi.mock('fs', async importOriginal => {
  const actual = await importOriginal<typeof import('fs')>()
  return { ...actual, fstatSync: vi.fn(actual.fstatSync) }
})
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
  expect(response).toEqual({ version: IPC_VERSION, correlationId: expect.stringMatching(/^ipc_[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}$/), ok: false, error: ipcError(category) })
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
  it('rejects malformed rotation without breaking a subsequent valid import', async () => {
    state.stores.get('profile-rotation')!.rotation = { ...collectCurrentConfig().rotation, enabled: true, profileIds: ['kept'] }
    const before = structuredClone(state.stores)
    writeFileSync(state.selection, JSON.stringify({ version: '2.0', rotation: {} }))
    await invoke('config:browse-import')
    expectFailure(await invoke('config:import', state.selection), 'validation')
    expectFailure(await invoke('config:import-apply', state.selection, ['rotation'], 'replace'), 'validation')
    expect(state.stores).toEqual(before)
    writeFileSync(state.selection, JSON.stringify({ version: '2.0', notifications: collectCurrentConfig().notifications }))
    await invoke('config:browse-import')
    expect(await invoke('config:import', state.selection)).toMatchObject({ ok: true })
    expect(await invoke('config:import-apply', state.selection, ['notifications'], 'replace')).toMatchObject({ ok: true })
    expect(state.stores.get('profile-rotation')!.rotation).toEqual(before.get('profile-rotation')!.rotation)
  })
  it.each(['file-too-large', 'file-not-regular', 'file-changed'])('records a bounded reason for %s without granting authority', async validationCode => {
    const actual = await vi.importActual<typeof import('fs')>('fs')
    if (validationCode === 'file-too-large') writeFileSync(state.selection, 'x'.repeat(16 * 1024 * 1024 + 1))
    if (validationCode === 'file-not-regular') {
      vi.mocked(fstatSync).mockImplementationOnce(fd => Object.assign(actual.fstatSync(fd), { isFile: () => false }))
    }
    if (validationCode === 'file-changed') {
      vi.mocked(fstatSync).mockImplementationOnce(fd => actual.fstatSync(fd))
        .mockImplementationOnce(fd => Object.assign(actual.fstatSync(fd), { mtimeMs: 0 }))
    }
    const reason = validationCode === 'file-changed' ? 'conflict' : 'validation'
    expectFailure(await invoke('config:browse-import'), reason)
    expect(logEvent).toHaveBeenCalledWith('warn', 'config-manager', 'import rejected', { reason, validationCode })
    expectFailure(await invoke('config:import', state.selection), 'permission')
    expect(sender.listenerCount('destroyed')).toBe(0)
  })
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
  it.each([undefined, null])('keeps system DNS after a successful DNS import with active selection %j', async activeDnsProfileId => {
    state.stores.get('dns-profiles')!.activeProfileId = null
    const incoming = { version: '2.0', dns: collectCurrentConfig().dns, activeDnsProfileId }
    writeFileSync(state.selection, JSON.stringify(incoming))
    await invoke('config:browse-import')
    expect(await invoke('config:import-apply', state.selection, ['dns'], 'replace')).toMatchObject({ ok: true })
    expect(collectCurrentConfig().activeDnsProfileId).toBeNull()
  })
  it('restores an explicitly imported system DNS choice over an existing custom selection', async () => {
    const dns = collectCurrentConfig().dns
    state.stores.get('dns-profiles')!.activeProfileId = dns[0].id
    writeFileSync(state.selection, JSON.stringify({ version: '2.0', dns, activeDnsProfileId: null }))
    await invoke('config:browse-import')
    expect(await invoke('config:import-apply', state.selection, ['dns'], 'replace')).toMatchObject({ ok: true })
    expect(collectCurrentConfig().activeDnsProfileId).toBeNull()
  })
  it('keeps cancelled saves out of error-level logs at every layer', async () => {
    state.destination = ''
    expectFailure(await invoke('config:export', 'redacted'), 'cancelled')
    expect(vi.mocked(logEvent).mock.calls.filter(([level]) => level === 'error')).toEqual([])
  })
  it.each(['EACCES', 'ENOSPC', 'EIO'])('retains bounded store diagnostics %s without exception text', async code => {
    await invoke('config:browse-import')
    state.failStore = true; state.fault = Object.assign(new Error(raw), { code })
    await invoke('config:import', state.selection)
    expect(logEvent).toHaveBeenCalledWith('error', 'config-manager', 'import validation failed', { reason: code === 'EACCES' ? 'permission' : 'internal', ioCode: code })
    expect(JSON.stringify(vi.mocked(logEvent).mock.calls)).not.toContain('FAKE-SECRET')
  })
  it('omits arbitrary exception codes from diagnostic metadata', async () => {
    await invoke('config:browse-import')
    state.failStore = true; state.fault = Object.assign(new Error(raw), { code: 'FAKE-SECRET-CODE' })
    expectFailure(await invoke('config:import', state.selection), 'internal')
    expect(logEvent).toHaveBeenCalledWith('error', 'config-manager', 'import validation failed', { reason: 'internal' })
    expect(JSON.stringify(vi.mocked(logEvent).mock.calls)).not.toContain('FAKE-SECRET')
  })
  it.each([
    ['null', 'not-object'], ['{}', 'missing-version'], ['{"version":"FAKE-SECRET"}', 'incompatible-version'],
    ['{"version":"2.0"}', 'no-sections'], ['{"version":"2.0","dns":{}}', 'section-type:dns'],
    ['{"version":"2.0","profiles":[null]}', 'profile-entry'], ['{broken', 'invalid-json']
  ])('records a stable validation reason for %s without file contents', async (content, validationCode) => {
    writeFileSync(state.selection, content); await invoke('config:browse-import')
    expectFailure(await invoke('config:import', state.selection), 'validation')
    expect(logEvent).toHaveBeenCalledWith('warn', 'config-manager', 'import rejected', { reason: 'validation', validationCode })
    expect(JSON.stringify(vi.mocked(logEvent).mock.calls)).not.toContain('FAKE-SECRET')
  })
})
