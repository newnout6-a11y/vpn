import { beforeAll, describe, expect, it, vi } from 'vitest'
import { IPC_REQUESTS, type IpcArgumentSchema, type IpcChannel, assertIpcRequest } from '../shared/ipc-contract'
import { IPC_ERRORS, IpcFault, IpcRemoteError, IpcValidationError, unwrapIpcResult, type IpcResult } from '../shared/ipc-result'
const state = vi.hoisted(() => ({ handlers: new Map<string, (...args: unknown[]) => Promise<IpcResult<unknown>>>() }))
vi.mock('electron', () => ({ app: { isPackaged: true }, ipcMain: {
  handle: (channel: string, fn: (...args: unknown[]) => Promise<IpcResult<unknown>>) => state.handlers.set(channel, fn)
} }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
import { ipcMain } from 'electron'
import { logEvent } from './appLogger'
import { installTrustedIpcBoundary, registerTrustedRenderer } from './ipcSecurity'

function example(schema: IpcArgumentSchema): unknown {
  if (schema.optional) return undefined
  if (schema.nullable) return null
  switch (schema.type) {
    case 'string': return 'value'
    case 'boolean': return false
    case 'enum': return schema.values![0]
    case 'integer': case 'number': return schema.min ?? 1
    case 'strings': return Array.from({ length: schema.min ?? 0 }, () => 'value')
    case 'array': return Array.from({ length: schema.min ?? 0 }, () => example(schema.items!))
    case 'object': return Object.fromEntries(Object.entries(schema.fields ?? {}).map(([key, field]) => [key, example(field)]))
    case 'json-object': return {}
  }
}
const channels = Object.keys(IPC_REQUESTS) as IpcChannel[]
const url = 'file:///C:/app/out/renderer/index.html'
const frame = { url }, sender = { id: 23, mainFrame: frame }
const event = { sender, senderFrame: frame }
beforeAll(() => { installTrustedIpcBoundary(); registerTrustedRenderer(sender as never, url) })

// Real guard, malformed nested fields: no feature handler may observe these inputs.
const invalidObjects: Array<[IpcChannel, unknown[]]> = [
  ['save-settings', [{ autoStart: 'false' }]],
  ['save-settings', [{ disableGeoLookup: 'false' }]],
  ['save-settings', [{ strictAdapterLockdown: 'false' }]],
  ['save-settings', [{ connectionMode: 'other' }]],
  ['save-settings', [{ proxyEngine: 'mihomo' }]],
  ['save-settings', [{ checkInterval: '5000' }]],
  ['save-settings', [{ directVpnSelectedIndex: '0' }]],
  ['save-settings', [{ directVpnCachedAt: 'yesterday' }]],
  ['save-settings', [{ directVpnCachedProfiles: {} }]],
  ['save-settings', [{ directVpnCachedProfiles: [{ name: 'Profile', protocol: 'vless', outbound: [] }] }]],
  ['save-settings', [{ directVpnCachedProfiles: [{ name: 'Profile', protocol: false, outbound: {} }] }]],
  ['save-settings', [{ directVpnCachedProfiles: [{ name: 'Profile', outbound: {} }] }]],
  ['save-settings', [{ unknown: true }]],
  ['scheduler:create', [{ name: 'Work', enabled: 'yes', days: [1], startTime: '09:00', endTime: '18:00', profileId: '', mode: 'hard' }]],
  ['scheduler:create', [{ name: 'Work', enabled: true, days: ['1'], startTime: '09:00', endTime: '18:00', profileId: '', mode: 'hard' }]],
  ['scheduler:update', ['id', { days: [7] }]],
  ['scheduler:update', ['id', { mode: 'other' }]],
  ['scheduler:update', ['id', { enabled: true, unknown: true }]],
  ['scheduler:update', ['id', { days: new Array(1) }]],
  ['rotation:set-config', [{ intervalMinutes: '30' }]],
  ['rotation:set-config', [{ profileIds: ['id', false] }]],
  ['rotation:set-config', [{ currentIndex: 0.5 }]],
  ['rotation:set-config', [{ nextRotationAt: -1 }]],
  ['rotation:set-config', [{ profileIds: new Array(1) }]],
  ['rotation:set-config', [{ profileIds: Array.from({ length: 1001 }, () => 'id') }]],
  ['kill-switch:add-exception', [{ type: 'other', value: 'app.exe', label: 'App' }]],
  ['kill-switch:add-exception', [{ type: 'app', value: 'app.exe', label: false }]],
  ['dns:create', [{ name: 'DNS', primary: '1.1.1.1', secondary: '', type: 'udp' }]],
  ['dns:update', ['id', { primary: ['1.1.1.1'] }]],
  ['dns:update', ['id', { isBuiltin: 'yes' }]],
  ['dns:update', ['id', { unknown: true }]],
  ['domain-routing:add', [{ pattern: 'example.test', action: 'direct', priority: '1' }]],
  ['domain-routing:update', ['id', { action: 'other' }]],
  ['connection-history:filter', [{ levels: ['not-a-reason'] }]],
  ['connection-history:filter', [{ dateFrom: 'yesterday' }]],
  ['notifications:set-prefs', [{ vpnConnect: 'yes' }]],
  ['notifications:set-prefs', [{ method: 'toast' }]],
  ['theme:create', [{ name: 'Theme', mode: 'dark', colors: { background: 123 } }]],
  ['theme:create', [{ name: 'Theme', mode: 'dark', colors: {} }]],
  ['server:live-check-history', [{ profileId: ['id'] }]],
]
const legacyColors = { background: '#101010', sidebar: '#111111', cardBackground: '#222222', accent: '#123456',
  text: '#ffffff', textSecondary: '#aaaaaa', border: '#333333' }
const validObjects: Array<[IpcChannel, unknown[]]> = [
  ['save-settings', [{}]],
  ['save-settings', [{ autoStart: false, firstRunComplete: true, proxyEngine: 'auto', directVpnCachedAt: null }]],
  ['save-settings', [{ checkInterval: -5, deepTrafficInspectionMaxSizeMb: 5000, directVpnSelectedIndex: 0.5 }]],
  ['save-settings', [{ directVpnCachedProfiles: [{ name: 'Profile', protocol: 'vless', outbound: {
    type: 'vless', server: 'example.test', server_port: 443, tls: { enabled: true, server_name: undefined }, tags: [null, false, 1, 'test']
  } }] }]],
  ['scheduler:create', [{ name: 'Work', enabled: true, days: [0, 6], startTime: '09:00', endTime: '18:00', profileId: '', mode: 'hard' }]],
  ['scheduler:update', ['id', {}]], ['scheduler:update', ['id', { id: 'ignored-by-service', enabled: false }]],
  ['rotation:set-config', [{ intervalMinutes: -5, profileIds: [], currentIndex: 0, nextRotationAt: null }]],
  ['rotation:set-config', [{ intervalMinutes: 5000, enabled: false }]],
  ['rotation:set-config', [{ profileIds: Array.from({ length: 1000 }, () => 'id') }]],
  ['kill-switch:add-exception', [{ type: 'ip', value: '1.1.1.1', label: 'DNS' }]],
  ['dns:create', [{ name: 'DNS', primary: '1.1.1.1', type: 'plain' }]],
  ['dns:create', [{ name: 'DNS', primary: '1.1.1.1', type: 'plain', secondary: null }]],
  ['dns:update', ['id', { name: 'New DNS', id: 'ignored-by-service', isBuiltin: false }]],
  ['domain-routing:add', [{ pattern: 'example.test', action: 'direct', priority: 1 }]],
  ['domain-routing:add', [{ pattern: `https://example.test/${'x'.repeat(300)}`, action: 'direct', priority: 1 }]],
  ['domain-routing:update', ['id', { pattern: '*.example.test', priority: 0 }]],
  ['connection-history:filter', [{ levels: ['user', 'crash'], dateFrom: 0, text: '' }]],
  ['notifications:set-prefs', [{ method: 'both', sound: false }]],
  ['theme:create', [{ name: 'Legacy theme', mode: 'dark', colors: legacyColors }]],
  ['theme:create', [{ name: 'Full theme', mode: 'light', colors: { ...legacyColors, cardElevated: '#444444',
    textMuted: '#999999', borderStrong: '#555555', success: '#00ff00', warning: '#ffff00', danger: '#ff0000' } }]],
  ['server:live-check-history', [{ profileId: 'id', host: 'example.test' }]],
]

describe('wire contracts on every registered channel (AT-00-001/004; F-138/F-074)', () => {
  it.each(validObjects)('%s preserves supported object inputs and feature defaults (%j)', async (channel, args) => {
    const effect = vi.fn(() => 'accepted')
    ipcMain.handle(channel, effect)
    expect(unwrapIpcResult(await state.handlers.get(channel)!(event, ...args))).toBe('accepted')
    expect(effect).toHaveBeenCalledExactlyOnceWith(event, ...args)
    // New contracts are closed: misspelled keys never reach the feature service.
    const index = args.length - 1
    const invalid = [...args]
    invalid[index] = { ...args[index] as object, unexpectedField: true }
    expect(await state.handlers.get(channel)!(event, ...invalid)).toMatchObject({ ok: false, error: { category: 'validation' } })
    expect(effect).toHaveBeenCalledTimes(1)
  })
  it.each(invalidObjects)('%s rejects invalid nested fields before effects (%j)', async (channel, args) => {
    const effect = vi.fn()
    ipcMain.handle(channel, effect)
    expect(await state.handlers.get(channel)!(event, ...args)).toMatchObject({ ok: false, error: { category: 'validation' } })
    expect(effect).not.toHaveBeenCalled()
  })
  it.each(channels)('%s validates before dispatch and returns a versioned envelope', async channel => {
    const effect = vi.fn(() => ({ domainResult: { ok: false } }))
    ipcMain.handle(channel, effect)
    const handler = state.handlers.get(channel)!
    const args = IPC_REQUESTS[channel].args.map(example)
    const response = await handler(event, ...args)
    expect(unwrapIpcResult(response)).toEqual({ domainResult: { ok: false } })
    expect(effect).toHaveBeenCalledTimes(1)
    const extra = [...args, 'unexpected']
    expect(await handler(event, ...extra)).toMatchObject({ version: 1, ok: false, error: { category: 'validation' } })
    for (let index = 0; index < args.length; index++) {
      const invalid = [...args]
      invalid[index] = IPC_REQUESTS[channel].args[index].type === 'object' ? [] : {}
      expect(await handler(event, ...invalid)).toMatchObject({ ok: false, error: { category: 'validation' } })
    }
    expect(effect).toHaveBeenCalledTimes(1)
    const failure = await handler({ ...event, senderFrame: { url } }, ...args)
    expect(failure).toMatchObject({ ok: false, error: { category: 'permission' } })
    expect(effect).toHaveBeenCalledTimes(1)
    expect(logEvent).toHaveBeenCalledWith('warn', 'ipc-security', 'IPC request rejected', expect.objectContaining({ correlationId: failure.correlationId }))
  })
  it.each(channels)('%s sanitizes every error category', async channel => {
    const errors = {
      validation: new IpcValidationError('raw-secret C:\\private\\file'),
      permission: Object.assign(new Error('raw-secret'), { code: 'EACCES' }),
      network: Object.assign(new Error('raw-secret'), { code: 'ECONNREFUSED' }),
      conflict: new IpcFault('conflict'), internal: new Error('raw-secret at C:\\private\\file:1'),
      cancelled: Object.assign(new Error('raw-secret'), { name: 'AbortError' }),
      timeout: Object.assign(new Error('raw-secret'), { code: 'ETIMEDOUT' })
    }
    for (const [category, error] of Object.entries(errors)) {
      ipcMain.handle(channel, () => { throw error })
      const response = await state.handlers.get(channel)!(event, ...IPC_REQUESTS[channel].args.map(example))
      expect(response).toMatchObject({ ok: false, error: { category, ...IPC_ERRORS[category as keyof typeof IPC_ERRORS] } })
      expect(JSON.stringify(response)).not.toMatch(/raw-secret|C:\\private|at /)
      expect(() => unwrapIpcResult(response)).toThrow(IpcRemoteError)
    }
  })
  it('rejects registration drift and unsafe names', () => {
    expect(() => ipcMain.handle('unknown:channel', vi.fn())).toThrow(IpcValidationError)
    expect(() => assertIpcRequest('__proto__', [])).toThrow(IpcValidationError)
  })
  it('contains exceptions with hostile code/name getters inside the safe envelope', async () => {
    for (const error of [Object.defineProperty({}, 'code', { get() { throw new Error('raw-secret') } }),
      Object.defineProperty(new Error(), 'name', { get() { throw new Error('raw-secret') } })]) {
      ipcMain.handle('get-settings', () => { throw error })
      await expect(state.handlers.get('get-settings')!(event)).resolves.toMatchObject({ ok: false, error: { category: 'internal' } })
    }
  })
  it.each([undefined, null, {}, { version: 2, ok: true, result: 1 }, { version: 1, ok: true, result: 1, correlationId: 'wrong' }])('rejects malformed wire response %j', value => {
    expect(() => unwrapIpcResult(value)).toThrow(IpcRemoteError)
  })
})
