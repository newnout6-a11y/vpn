// AT-01-008/011; F-144; AC-SET-CFG-001…003, AC-SRV-EXP-001…003.
import { mkdtempSync, readFileSync, existsSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({ handlers: new Map<string, Function>(),
  profiles: [] as any[], groups: [] as any[], prompt: vi.fn(), save: vi.fn() }))
vi.mock('electron', () => ({ ipcMain: { handle: (channel: string, handler: Function) => state.handlers.set(channel, handler) },
  BrowserWindow: { fromWebContents: () => null }, dialog: { showMessageBox: state.prompt, showSaveDialog: state.save } }))
vi.mock('electron-store', () => ({ default: class {
  constructor(private options: { defaults: Record<string, unknown> }) {}
  get(key: string) { return this.options.defaults[key] }
} }))
vi.mock('./sharedStores', () => ({ serverPickerStore: { get: () => state.profiles }, serverGroupsStore: { get: () => state.groups },
  granularKillSwitchStore: { get: (key: string) => key === 'killSwitchLevel' ? 'off' : [] } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
import { registerConfigManagerIpcHandlers, collectCurrentConfig } from './configManager'
import { redactConfigExport } from './configExportPolicy'
import { NATIVE_XRAY_FIELD } from './nativeXrayProfile'

let directory: string, destination: string
let sender: { isDestroyed: () => boolean }
const invoke = (...args: unknown[]) => state.handlers.get('config:export')!({ sender }, ...args)
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), 'vpnte-export-')); destination = join(directory, 'config.json')
  sender = { isDestroyed: () => false }
  state.profiles = [{ id: 'p1', name: 'Profile', protocol: 'vless', server: 'vpn.test', port: 443,
    outbound: { type: 'vless', uuid: 'FAKE-UUID', password: 'FAKE-PASS', tls: { reality: { public_key: 'FAKE-PBK', short_id: 'FAKE-SID' } },
      unknown_future_field: 'FAKE-FUTURE', nested: { username: 'FAKE-USER', headers: { Authorization: 'FAKE-AUTH' } } },
    sourceUri: 'vless://FAKE-UUID@vpn.test:443' }]
  state.groups = [{ id: 'g1', name: 'Group', sourceUrl: 'https://sub.test/FAKE-SUBSCRIPTION', profileIds: ['p1'] }]
  state.prompt.mockReset().mockResolvedValue({ response: 0 })
  state.save.mockReset().mockResolvedValue({ canceled: false, filePath: destination })
  registerConfigManagerIpcHandlers()
})
afterEach(() => rmSync(directory, { recursive: true, force: true }))
describe('main configuration export authority', () => {
  it('defaults to masking every credential and keeps IDs/references without changing stores', async () => {
    const before = JSON.stringify(collectCurrentConfig())
    expect((await invoke()).success).toBe(true)
    const raw = readFileSync(destination, 'utf8'); const exported = JSON.parse(raw)
    expect(raw).not.toContain('FAKE-')
    expect(exported.profiles[0].outbound.uuid).toBe('REDACTED')
    expect(exported.profiles[0].id).toBe('p1')
    expect(exported.serverGroups[0].profileIds).toEqual(['p1'])
    expect(exported.profiles[0].outbound.type).toBe('vless')
    expect(state.prompt).not.toHaveBeenCalled()
    expect(JSON.stringify(collectCurrentConfig()).replace(/"exportedAt":\d+/, '')).toBe(before.replace(/"exportedAt":\d+/, ''))
  })
  it('cancelling consent does not open a save dialog or write any file', async () => {
    expect(await invoke('secrets')).toEqual({ success: false, error: 'Export cancelled' })
    expect(state.save).not.toHaveBeenCalled(); expect(existsSync(destination)).toBe(false)
  })
  it('only native consent authorizes a full export; no payload containing secrets returns over IPC', async () => {
    state.prompt.mockResolvedValue({ response: 1 })
    const result = await invoke('secrets')
    expect(result).toEqual({ success: true, path: destination })
    expect(JSON.stringify(result)).not.toContain('FAKE-')
    expect(readFileSync(destination, 'utf8')).toContain('FAKE-UUID')
    expect(state.prompt.mock.calls[0][0]).toMatchObject({ defaultId: 0, cancelId: 0 })
  })
  it.each([true, { confirmed: true }, 'full', null, 1])('rejects a fabricated export mode: %j', async mode => {
    await expect(invoke(mode)).rejects.toThrow('Invalid IPC payload')
    expect(state.prompt).not.toHaveBeenCalled(); expect(state.save).not.toHaveBeenCalled()
  })
  it('does not write after the requesting window closes during native save', async () => {
    state.prompt.mockResolvedValue({ response: 1 })
    state.save.mockImplementation(async () => { sender.isDestroyed = () => true; return { canceled: false, filePath: destination } })
    expect((await invoke('secrets')).success).toBe(false)
    expect(existsSync(destination)).toBe(false)
  })
  it.each([
    { future: { type: 'FAKE-NESTED', path: 'FAKE-PATH' } },
    { future: [{ server: 'FAKE-ARRAY', id: 'FAKE-ID' }] },
    { server: { type: 'FAKE-TYPE-CONFUSION' } },
    { alpn: [{ type: 'FAKE-ALPN' }] }
  ])('unknown containers and malformed public fields fail closed (AT-01-008/011): %j', fields => {
    Object.assign(state.profiles[0].outbound, fields)
    expect(JSON.stringify(redactConfigExport(collectCurrentConfig()))).not.toContain('FAKE-')
  })
  it('unknown profile/group/config fields have no implicit disclosure policy (AT-01-008/011)', async () => {
    state.profiles[0].future = { id: 'FAKE-PROFILE', name: 'FAKE-NAME' }
    state.groups[0].future = [{ path: 'FAKE-GROUP' }]
    const config = { ...collectCurrentConfig(), future: { value: 'FAKE-ROOT' } }
    expect(JSON.stringify(redactConfigExport(config))).not.toContain('FAKE-')
    expect((await invoke()).success).toBe(true)
    expect(readFileSync(destination, 'utf8')).not.toContain('FAKE-')
  })
  it('preserves distinct UUID-shaped application IDs and references (AT-01-008/011)', () => {
    const profileId = '11111111-1111-4111-8111-111111111111'
    const secondId = '22222222-2222-4222-8222-222222222222'
    const groupId = '33333333-3333-4333-8333-333333333333'
    state.profiles[0].id = profileId; state.profiles[0].groupId = groupId
    state.profiles.push({ ...state.profiles[0], id: secondId })
    state.groups[0].id = groupId; state.groups[0].profileIds = [profileId, secondId]
    const config = collectCurrentConfig()
    config.rotation.profileIds = [profileId, secondId]
    config.schedules = [{ id: 'schedule', name: 'Daily', enabled: true, days: [1], startTime: '08:00', endTime: '09:00', profileId, mode: 'hard' }]
    const exported = redactConfigExport(config)
    expect(exported.profiles.map(profile => profile.id)).toEqual([profileId, secondId])
    expect(exported.profiles[0].groupId).toBe(groupId)
    expect(exported.serverGroups[0].id).toBe(groupId)
    expect(exported.rotation.profileIds).toEqual([profileId, secondId])
    expect(exported.schedules[0].profileId).toBe(profileId)
    expect(exported.profiles[0].outbound!.uuid).toBe('REDACTED')
  })
  it('keeps reviewed public settings in every section while masking credentials (AT-01-008/011)', () => {
    state.profiles = [{ id: 'p1', groupId: 'g1', name: 'Profile', protocol: 'vless', server: 'vpn.test', port: 443, status: 'unknown',
      outbound: { type: 'vless', server: 'vpn.test', server_port: 443, uuid: 'FAKE-UUID',
        tls: { enabled: true, server_name: 'vpn.test', alpn: ['h2'], utls: { enabled: true, fingerprint: 'chrome' },
          reality: { enabled: true, public_key: 'FAKE-PBK' } },
        transport: { type: 'ws', path: '/socket', headers: { Authorization: 'FAKE-AUTH' } },
        multiplex: { enabled: true, max_connections: 8, padding: false } } }]
    state.groups = [{ id: 'g1', name: 'Group', source: 'manual', importedAt: 1 }]
    const config = collectCurrentConfig()
    config.schedules = [{ id: 's1', name: 'Daily', enabled: true, days: [1, 2], startTime: '08:00', endTime: '09:00', profileId: 'p1', mode: 'hard' }]
    config.splitTunnel = [{ id: 'a1', name: 'App', path: 'C:\\Program Files\\App\\app.exe', icon: null, rule: 'direct', kind: 'app' }]
    config.domainRouting = [{ id: 'r1', pattern: '*.example.test', action: 'vpn', priority: 1, hitCount: 0 }]
    config.themes = [{ id: 't1', name: 'Custom', mode: 'dark', isCustom: true,
      colors: { background: '#111111', sidebar: '#111111', cardBackground: '#222222', cardElevated: '#333333', accent: '#445566',
        text: '#ffffff', textSecondary: '#dddddd', textMuted: '#cccccc', border: '#444444', borderStrong: '#555555',
        success: '#00ff00', warning: '#ffff00', danger: '#ff0000' } }]
    config.activeDnsProfileId = config.dns[0].id
    config.rotation.profileIds = ['p1']
    config.killSwitch.exceptions = [{ id: 'e1', type: 'ip', value: '192.0.2.1', label: 'Test' }]
    const before = JSON.stringify(config)
    const expected = JSON.parse(before)
    expected.profiles[0].outbound.uuid = 'REDACTED'
    expected.profiles[0].outbound.tls.reality.public_key = 'REDACTED'
    expected.profiles[0].outbound.transport.headers = 'REDACTED'
    expect(redactConfigExport(config)).toEqual(expected)
    expect(JSON.stringify(config)).toBe(before)
  })
  it('does not authorize inherited policy keys or unknown outbound IDs (AT-01-008/011)', () => {
    Object.assign(state.profiles[0].outbound, JSON.parse('{"constructor":{"type":"FAKE-CONSTRUCTOR"},"__proto__":{"server":"FAKE-PROTOTYPE"},"id":"FAKE-AUTH-ID"}'))
    expect(JSON.stringify(redactConfigExport(collectCurrentConfig()))).not.toContain('FAKE-')
    expect(Object.getPrototypeOf(redactConfigExport(collectCurrentConfig()).profiles[0].outbound)).toBe(Object.prototype)
  })
  it('future outbound fields fail closed, including arrays and native core graphs', () => {
    state.profiles[0].outbound.peers = [{ strangeCredential: 'FAKE-SECRET' }]
    state.profiles[0].outbound[NATIVE_XRAY_FIELD] = { arbitrary: 'FAKE-NATIVE', type: 'FAKE-NATIVE-TYPE' }
    expect(JSON.stringify(redactConfigExport(collectCurrentConfig()))).not.toContain('FAKE-')
  })
})
