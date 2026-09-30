// AT-01-003/004: native file-selection capabilities, independent of the IPC origin tests.
import { EventEmitter } from 'events'
import { mkdtempSync, writeFileSync, renameSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({ handlers: new Map<string, Function>(), rules: [] as any[], selection: [] as string[] }))
vi.mock('electron', () => ({
  ipcMain: { handle: (name: string, handler: Function) => state.handlers.set(name, handler) },
  dialog: { showOpenDialog: vi.fn(async () => ({ canceled: state.selection.length === 0, filePaths: state.selection })) }
}))
vi.mock('electron-store', () => ({ default: class {
  get() { return state.rules }
  set(_key: string, value: any[]) { state.rules = value }
} }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./tunController', () => ({ tunController: { getStatus: () => ({ running: false }) } }))
import { registerDomainRoutingIpcHandlers } from './domainRouting'
let directory = ''
let sender: EventEmitter
function invoke(channel: string, owner: EventEmitter, ...args: unknown[]) {
  return state.handlers.get(channel)!({ sender: owner }, ...args)
}
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), 'vpnte-import-capability-'))
  sender = new EventEmitter(); state.rules = []; state.selection = []; state.handlers.clear()
  registerDomainRoutingIpcHandlers()
})
afterEach(() => { sender.emit('destroyed'); rmSync(directory, { recursive: true, force: true }); vi.useRealTimers() })
describe('domain import native selection boundary', () => {
  it('rejects arbitrary renderer paths without opening or importing them', async () => {
    const file = join(directory, 'secret.txt'); writeFileSync(file, 'secret.test')
    await expect(invoke('domain-routing:import', sender, file)).rejects.toThrow('native-dialog')
    expect(state.rules).toEqual([])
  })
  it('accepts the selected file exactly once and rejects cross-window reuse', async () => {
    const file = join(directory, 'domains.txt'); writeFileSync(file, 'trusted.test')
    state.selection = [file]
    expect(await invoke('domain-routing:browse-file', sender)).toBe(file)
    await expect(invoke('domain-routing:import', new EventEmitter(), file)).rejects.toThrow('native-dialog')
    await invoke('domain-routing:import', sender, file)
    expect(state.rules.map(r => r.pattern)).toEqual(['trusted.test'])
    await expect(invoke('domain-routing:import', sender, file)).rejects.toThrow('native-dialog')
  })
  it('reads the opened selection, not a substituted pathname', async () => {
    const file = join(directory, 'domains.txt'); writeFileSync(file, 'trusted.test')
    state.selection = [file]; await invoke('domain-routing:browse-file', sender)
    renameSync(file, file + '.old'); writeFileSync(file, 'private.test')
    await invoke('domain-routing:import', sender, file)
    expect(state.rules.map(r => r.pattern)).toEqual(['trusted.test'])
  })
  it('expires selection capabilities without retaining an open file', async () => {
    vi.useFakeTimers()
    const file = join(directory, 'domains.txt'); writeFileSync(file, 'trusted.test')
    state.selection = [file]; await invoke('domain-routing:browse-file', sender)
    await vi.advanceTimersByTimeAsync(60_000)
    await expect(invoke('domain-routing:import', sender, file)).rejects.toThrow('native-dialog')
  })
  it('invalidates selection when the renderer is destroyed', async () => {
    const file = join(directory, 'domains.txt'); writeFileSync(file, 'trusted.test')
    state.selection = [file]; await invoke('domain-routing:browse-file', sender)
    sender.emit('destroyed')
    await expect(invoke('domain-routing:import', sender, file)).rejects.toThrow('native-dialog')
  })
  it('rejects oversized files before parsing', async () => {
    const file = join(directory, 'domains.txt'); writeFileSync(file, 'x'.repeat(4 * 1024 * 1024 + 1))
    state.selection = [file]
    await expect(invoke('domain-routing:browse-file', sender)).rejects.toThrow('4 MiB')
    expect(state.rules).toEqual([])
  })
})
