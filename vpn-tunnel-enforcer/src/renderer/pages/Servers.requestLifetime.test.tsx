// AT-00-003/008: actual Servers handlers, real React unmount, held main responses.
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Servers } from './Servers'
import { useAppStore } from '../store'
import { emitServerChanged } from '../nav'
import { ipcError } from '../../shared/ipc-result'

vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key, i18n: { language: 'ru' } }) }))
vi.mock('../nav', () => ({ emitServerChanged: vi.fn() }))
vi.mock('../components/ForeignVpnBanner', () => ({ ForeignVpnBanner: () => null }))
vi.mock('../components/ServerDetailModal', () => ({ ServerDetailModal: () => null }))
vi.mock('../components/LiveServerBatchComparison', () => ({ LiveServerBatchComparison: () => null }))

const group = { id: 'subscription', name: 'Subscription', source: 'subscription', sourceUrl: 'https://sub.example.test/list', status: 'active', importedAt: 1 }
const profile = { id: 'saved', name: 'Saved', protocol: 'vless', server: 'vpn.example.test', port: 443, status: 'unknown', groupId: group.id }
let release: (value: unknown) => void
let reject: (value: unknown) => void
let api: Record<string, ReturnType<typeof vi.fn>>
beforeEach(() => {
  localStorage.clear()
  useAppStore.setState({ logs: [], globalToasts: [] })
  api = {
    serversList: vi.fn(async () => [profile]), serversGetActive: vi.fn(async () => ({ profile: null, activeId: null })),
    groupsList: vi.fn(async () => [group]), operationsCancelRequest: vi.fn(async () => true),
    ...Object.fromEntries(['serversCopyKey', 'serversExportKeyToFile', 'serversExportAllKeysToFile', 'serversExportAllProxiesToFile']
      .map(name => [name, vi.fn(() => new Promise((done, fail) => { release = done; reject = fail }))])),
    serversAdd: vi.fn(() => new Promise(done => { release = done })),
    groupsRefresh: vi.fn(() => new Promise(done => { release = done }))
  }
  Object.assign(window, { electronAPI: api })
  vi.mocked(emitServerChanged).mockClear()
})
afterEach(() => { cleanup(); vi.restoreAllMocks() })

const exports = [
    ['serversCopyKey', 'servers.exportKey', true], ['serversExportKeyToFile', 'servers.saveKey', true],
    ['serversExportAllKeysToFile', 'servers.exportAllKeys', false], ['serversExportAllProxiesToFile', 'servers.exportProxyList', false]
] as const
describe('Servers requester lifetime', () => {
  it.each(exports.flatMap(([method, label, row]) => ['success', 'error'].map(outcome => ({ method, label, row, outcome }))))
  ('cancels $method on unmount and suppresses late export $outcome effects', async ({ method, label, row, outcome }) => {
    const view = render(<Servers />)
    await screen.findByRole('button', { name: 'servers.groups.refresh' })
    if (row) fireEvent.click(await screen.findByRole('button', { name: 'servers.rowActions' }))
    fireEvent.click(screen.getByRole(row ? 'menuitem' : 'button', { name: label }))
    expect(api[method]).toHaveBeenCalledOnce()
    view.unmount()
    expect(api.operationsCancelRequest).toHaveBeenCalledExactlyOnceWith(expect.stringMatching(/^[0-9a-f-]{36}$/))
    expect(api[method].mock.calls[0].at(-1)).toBe(api.operationsCancelRequest.mock.calls[0][0])
    const timers = vi.spyOn(window, 'setTimeout')
    await act(async () => {
      if (outcome === 'error') reject({ name: 'IpcRemoteError', ...ipcError('internal') })
      else release({ ok: true, path: 'ignored.txt', exported: 1, skipped: 0, clearAfterMs: 60000 })
    })
    expect(useAppStore.getState().logs).toEqual([])
    expect(timers.mock.calls.some(call => [2200, 2500].includes(Number(call[1])))).toBe(false)
  })

  it.each(exports)('completes current %s and clears its flash timer on unmount', async (method, label, row) => {
    const view = render(<Servers />)
    await screen.findByRole('button', { name: 'servers.groups.refresh' })
    if (row) fireEvent.click(await screen.findByRole('button', { name: 'servers.rowActions' }))
    const timers = vi.spyOn(window, 'setTimeout'), clear = vi.spyOn(window, 'clearTimeout')
    fireEvent.click(screen.getByRole(row ? 'menuitem' : 'button', { name: label }))
    await act(async () => { release({ ok: true, path: 'current.txt', exported: 1, skipped: 0, clearAfterMs: 60000 }) })
    if (row) {
      fireEvent.click(screen.getByRole('button', { name: 'servers.rowActions' }))
      expect(screen.getByRole('menuitem', { name: method === 'serversCopyKey' ? 'servers.keyCopied' : 'servers.keySaved' })).toBeTruthy()
    } else expect(useAppStore.getState().logs).toHaveLength(1)
    view.unmount()
    expect(api.operationsCancelRequest).not.toHaveBeenCalled()
    if (row) {
      const index = timers.mock.calls.findIndex(call => [2200, 2500].includes(Number(call[1])))
      expect(index).toBeGreaterThanOrEqual(0)
      expect(clear).toHaveBeenCalledWith(timers.mock.results[index].value)
    }
  })

  it.each(exports)('keeps typed cancellation quiet for %s', async (method, label, row) => {
    api[method].mockRejectedValue({ name: 'IpcRemoteError', ...ipcError('cancelled') })
    const view = render(<Servers />)
    await screen.findByRole('button', { name: 'servers.groups.refresh' })
    if (row) fireEvent.click(await screen.findByRole('button', { name: 'servers.rowActions' }))
    const timers = vi.spyOn(window, 'setTimeout')
    await act(async () => { fireEvent.click(screen.getByRole(row ? 'menuitem' : 'button', { name: label })) })
    expect(useAppStore.getState().logs).toEqual([])
    expect(screen.queryByText(ipcError('cancelled').message)).toBeNull()
    expect(timers.mock.calls.some(call => [2200, 2500].includes(Number(call[1])))).toBe(false)
    view.unmount()
    expect(api.operationsCancelRequest).not.toHaveBeenCalled()
  })

  it('keeps typed cancellation silent and clears a successful refresh toast timer', async () => {
    api.serversAdd.mockRejectedValue({ name: 'IpcRemoteError', ...ipcError('cancelled') })
    const view = render(<Servers />)
    await screen.findByRole('button', { name: 'servers.groups.refresh' })
    fireEvent.change(screen.getByLabelText('servers.add.keyLabel'), { target: { value: 'https://sub.example.test/new' } })
    fireEvent.click(screen.getByRole('button', { name: 'servers.addServer' }))
    await waitFor(() => expect((screen.getByRole('button', { name: 'servers.addServer' }) as HTMLButtonElement).disabled).toBe(false))
    expect(screen.queryByText(ipcError('cancelled').message)).toBeNull()
    const timers = vi.spyOn(window, 'setTimeout'), clear = vi.spyOn(window, 'clearTimeout')
    fireEvent.click(screen.getByRole('button', { name: 'servers.groups.refresh' }))
    await act(async () => { release({ ok: true, group, addedCount: 1, updatedCount: 0, removedCount: 0 }) })
    const index = timers.mock.calls.findIndex(call => call[1] === 6000)
    expect(index).toBeGreaterThanOrEqual(0)
    const timer = timers.mock.results[index].value
    view.unmount()
    expect(clear).toHaveBeenCalledWith(timer)
    expect(api.operationsCancelRequest).not.toHaveBeenCalled()
  })
  it.each(['import', 'refresh'] as const)('cancels %s on unmount without late reads, logs, events or success timers', async kind => {
    const view = render(<Servers />)
    await screen.findByRole('button', { name: 'servers.groups.refresh' })
    if (kind === 'import') {
      fireEvent.change(screen.getByLabelText('servers.add.keyLabel'), { target: { value: 'https://sub.example.test/new' } })
      fireEvent.click(screen.getByRole('button', { name: 'servers.addServer' }))
    } else fireEvent.click(screen.getByRole('button', { name: 'servers.groups.refresh' }))
    const call = kind === 'import' ? api.serversAdd : api.groupsRefresh
    expect(call).toHaveBeenCalledOnce()
    view.unmount()
    expect(api.operationsCancelRequest).toHaveBeenCalledExactlyOnceWith(expect.stringMatching(/^[0-9a-f-]{36}$/))
    const token = api.operationsCancelRequest.mock.calls[0][0]
    expect(call.mock.calls[0].at(-1)).toBe(token)
    const reads = [api.serversList.mock.calls.length, api.groupsList.mock.calls.length]
    const timers = vi.spyOn(window, 'setTimeout')
    await act(async () => { release(kind === 'import' ? [profile] : { ok: true, group, addedCount: 1, updatedCount: 0, removedCount: 0 }) })
    expect([api.serversList.mock.calls.length, api.groupsList.mock.calls.length]).toEqual(reads)
    expect(emitServerChanged).not.toHaveBeenCalled()
    expect(useAppStore.getState().logs).toEqual([])
    expect(timers.mock.calls.some(call => call[1] === 6000)).toBe(false)
  })

  it('finishes a current import and forgets its completed token before unmount', async () => {
    const view = render(<Servers />)
    await screen.findByRole('button', { name: 'servers.groups.refresh' })
    fireEvent.change(screen.getByLabelText('servers.add.keyLabel'), { target: { value: 'https://sub.example.test/new' } })
    fireEvent.click(screen.getByRole('button', { name: 'servers.addServer' }))
    await act(async () => { release([profile]) })
    await waitFor(() => expect(emitServerChanged).toHaveBeenCalledOnce())
    view.unmount()
    expect(api.operationsCancelRequest).not.toHaveBeenCalled()
  })
})
