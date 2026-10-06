// AT-01-003/004/008: main-native selection is the authority, never a renderer pathname.
import { EventEmitter } from 'events'
import { mkdtempSync, writeFileSync, renameSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({
  handlers: new Map<string, Function>(), selection: [] as string[],
  stores: new Map<string, Record<string, any>>()
}))
vi.mock('electron', () => ({
  ipcMain: { handle: (channel: string, handler: Function) => state.handlers.set(channel, handler) },
  dialog: {
    showOpenDialog: vi.fn(async () => ({ canceled: state.selection.length === 0, filePaths: state.selection })),
    showSaveDialog: vi.fn(async () => ({ canceled: true }))
  }
}))
vi.mock('electron-store', () => ({ default: class {
  name: string
  constructor(options: { name: string; defaults: Record<string, any> }) {
    this.name = options.name
    state.stores.set(this.name, structuredClone(options.defaults))
  }
  get(key: string) { return state.stores.get(this.name)?.[key] }
  set(key: string, value: any) { state.stores.get(this.name)![key] = value }
} }))
vi.mock('./sharedStores', () => ({
  serverPickerStore: { get: () => [], set: vi.fn() },
  serverGroupsStore: { get: () => [], set: vi.fn() },
  granularKillSwitchStore: { get: (key: string) => key === 'killSwitchLevel' ? 'off' : [], set: vi.fn() }
}))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./ipcLogging', () => ({ compactForIpcLog: () => '[redacted]' }))
import { dialog } from 'electron'
import { collectCurrentConfig, registerConfigManagerIpcHandlers } from './configManager'
let directory: string
class Sender extends EventEmitter {
  destroyed = false
  isDestroyed() { return this.destroyed }
  destroy() { this.destroyed = true; this.emit('destroyed') }
}
let sender: Sender
const invoke = (channel: string, owner: Sender, ...args: unknown[]) => state.handlers.get(channel)!({ sender: owner }, ...args)
function selected(name = 'config.json', sound = false) {
  const file = join(directory, name)
  const config = structuredClone(collectCurrentConfig()); config.notifications.sound = sound
  writeFileSync(file, JSON.stringify(config)); state.selection = [file]
  return file
}
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), 'vpnte-config-capability-'))
  sender = new Sender(); state.selection = []; state.handlers.clear()
  vi.mocked(dialog.showOpenDialog).mockReset().mockImplementation(async () => ({ canceled: state.selection.length === 0, filePaths: state.selection }))
  state.stores.get('notification-prefs')!.notificationPrefs.sound = true
  registerConfigManagerIpcHandlers()
})
afterEach(() => { sender.destroy(); rmSync(directory, { recursive: true, force: true }); vi.useRealTimers() })
describe('configuration native-selection capability', () => {
  it('rejects arbitrary paths and cannot accept a renderer-supplied raw snapshot', async () => {
    const file = selected()
    await expect(invoke('config:import', sender, file, JSON.stringify(collectCurrentConfig()))).rejects.toThrow('native-dialog')
    await expect(invoke('config:import-apply', sender, file, ['notifications'], 'replace')).rejects.toThrow('native-dialog')
    expect(collectCurrentConfig().notifications.sound).toBe(true)
  })
  it('binds to the exact sender and pathname; apply is single-use', async () => {
    const file = selected(); await invoke('config:browse-import', sender)
    await expect(invoke('config:import', new Sender(), file)).rejects.toThrow('native-dialog')
    await expect(invoke('config:import', sender, file + '.other')).rejects.toThrow('native-dialog')
    expect((await invoke('config:import', sender, file)).success).toBe(true)
    expect((await invoke('config:import-apply', sender, file, ['notifications'], 'replace')).success).toBe(true)
    expect(collectCurrentConfig().notifications.sound).toBe(false)
    await expect(invoke('config:import-apply', sender, file, ['notifications'], 'replace')).rejects.toThrow('native-dialog')
  })
  it('validates and applies the captured bytes even after pathname replacement', async () => {
    const file = selected(); await invoke('config:browse-import', sender)
    expect((await invoke('config:import', sender, file)).success).toBe(true)
    renameSync(file, file + '.old'); writeFileSync(file, 'not the selected configuration')
    expect((await invoke('config:import', sender, file)).success).toBe(true)
    expect((await invoke('config:import-apply', sender, file, ['notifications'], 'replace')).success).toBe(true)
    expect(collectCurrentConfig().notifications.sound).toBe(false)
  })
  it('expires even if the timer callback has not run yet', async () => {
    vi.useFakeTimers()
    const file = selected(); await invoke('config:browse-import', sender)
    vi.setSystemTime(Date.now() + 60_000)
    await expect(invoke('config:import', sender, file)).rejects.toThrow('native-dialog')
    expect(sender.listenerCount('destroyed')).toBe(0)
  })
  it('clears captured secrets and listeners on renderer destruction', async () => {
    const file = selected(); await invoke('config:browse-import', sender)
    sender.destroy()
    await expect(invoke('config:import', sender, file)).rejects.toThrow('native-dialog')
    expect(sender.listenerCount('destroyed')).toBe(0)
  })
  it('a canceled replacement dialog revokes the previous capability', async () => {
    const file = selected(); await invoke('config:browse-import', sender)
    state.selection = []
    expect(await invoke('config:browse-import', sender)).toBeNull()
    await expect(invoke('config:import', sender, file)).rejects.toThrow('native-dialog')
  })
  it('late older dialogs cannot replace the newest selected snapshot', async () => {
    const olderFile = selected('older.json', true)
    const newerFile = selected('newer.json', false)
    let finishOlder!: (result: { canceled: boolean; filePaths: string[] }) => void
    vi.mocked(dialog.showOpenDialog).mockImplementationOnce(() => new Promise(resolve => { finishOlder = resolve }))
    const older = invoke('config:browse-import', sender)
    expect(await invoke('config:browse-import', sender)).toBe(newerFile)
    finishOlder({ canceled: false, filePaths: [olderFile] })
    expect(await older).toBeNull()
    await expect(invoke('config:import', sender, olderFile)).rejects.toThrow('native-dialog')
    expect((await invoke('config:import-apply', sender, newerFile, ['notifications'], 'replace')).success).toBe(true)
    expect(collectCurrentConfig().notifications.sound).toBe(false)
  })
  it('does not grant a capability after the requesting renderer closes during a dialog', async () => {
    const file = selected()
    vi.mocked(dialog.showOpenDialog).mockImplementationOnce(async () => {
      sender.destroy(); return { canceled: false, filePaths: [file] }
    })
    await expect(invoke('config:browse-import', sender)).rejects.toThrow('renderer closed')
    await expect(invoke('config:import', sender, file)).rejects.toThrow('native-dialog')
  })
  it('rejects oversized and non-regular files before validation', async () => {
    const file = join(directory, 'large.json'); writeFileSync(file, 'x'.repeat(16 * 1024 * 1024 + 1))
    state.selection = [file]
    await expect(invoke('config:browse-import', sender)).rejects.toThrow('16 MiB')
    state.selection = [directory]
    await expect(invoke('config:browse-import', sender)).rejects.toThrow('regular file')
    expect(sender.listenerCount('destroyed')).toBe(0)
  })
  it('consumes the capability even if JSON validation fails on apply', async () => {
    const file = selected(); writeFileSync(file, '{broken')
    await invoke('config:browse-import', sender)
    expect((await invoke('config:import-apply', sender, file, ['notifications'], 'replace')).success).toBe(false)
    await expect(invoke('config:import', sender, file)).rejects.toThrow('native-dialog')
  })
  it('default export uses the masked variant and a cancelled save creates nothing (AT-01-008)', async () => {
    expect((await invoke('config:export', sender)).success).toBe(false)
    expect(dialog.showSaveDialog).toHaveBeenCalledWith(expect.objectContaining({
      title: 'Экспорт конфигурации без секретов', buttonLabel: 'Сохранить'
    }))
  })
})
