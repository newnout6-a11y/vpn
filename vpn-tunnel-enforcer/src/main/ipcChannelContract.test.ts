import { describe, it, expect } from 'vitest'
import { checkIpcContract, inspectIpcContract } from '../../scripts/check-ipc-contract.mjs'

describe('IPC parity (AT-00-001; F-138)', () => {
  it('compares handlers, actual bridge methods and shared declarations exactly', () => {
    const inventory = checkIpcContract()
    expect(inventory.problems, inventory.problems.join('\n')).toEqual([])
  })
  const fixture = {
    main: { 'main.ts': "function handleLogged(channel, listener) { ipcMain.handle(channel, listener) }; handleLogged('one', () => 1)" },
    preload: "contextBridge.exposeInMainWorld('electronAPI', { getOne: () => invoke('one') })",
    shared: "const IPC_REQUESTS = { 'one': request('getOne', []) } as const"
  }
  it('resolves real wrapper calls', () => { expect(inspectIpcContract(fixture).problems).toEqual([]) })
  it('compares the actual methods inside the failure-serialization bridge wrapper', () => {
    const preload = "contextBridge.exposeInMainWorld('electronAPI', withIpcFailures({ getOne: () => invoke('one') } satisfies ElectronAPI))"
    expect(inspectIpcContract({ ...fixture, preload }).problems).toEqual([])
    expect(inspectIpcContract({ ...fixture, preload: preload.replace("invoke('one')", "ipcRenderer.invoke('one')") }).problems)
      .toContain('Preload bypasses result decoder: getOne')
  })
  it('does not count comments or unrelated strings as handlers', () => {
    const result = inspectIpcContract({ ...fixture, main: { 'main.ts': "// ipcMain.handle('one', effect)\nconst unused = 'one'" } })
    expect(result.problems).toContain('main missing: one')
  })
  it('names extra, duplicate and mismatched declarations', () => {
    const result = inspectIpcContract({ ...fixture,
      main: { 'main.ts': "ipcMain.handle('one', fn); ipcMain.handle('one', fn); ipcMain.handle('extra', fn)" },
      shared: "const IPC_REQUESTS = { 'one': request('wrongMethod', []) } as const" })
    expect(result.problems).toEqual(expect.arrayContaining(['main duplicate: one', 'preload missing: extra', 'shared missing: extra', 'Method mismatch: one (getOne)']))
  })
  it('fails closed on an unresolved dynamic channel', () => {
    const result = inspectIpcContract({ ...fixture, main: { 'main.ts': "ipcMain.handle(settings.channel, listener)" } })
    expect(result.problems).toContain('main.ts: unresolved ipcMain.handle channel')
  })
  it('rejects a bridge method bypassing the shared decoder', () => {
    const result = inspectIpcContract({ ...fixture,
      preload: "contextBridge.exposeInMainWorld('electronAPI', { getOne: () => invoke('one'), raw: () => ipcRenderer.invoke('one') })" })
    expect(result.problems).toContain('Preload bypasses result decoder: raw')
  })
})
