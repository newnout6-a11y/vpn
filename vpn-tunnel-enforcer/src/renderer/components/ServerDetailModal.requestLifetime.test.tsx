// AT-00-003/008: actual modal, held export replies and React scope cleanup.
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ServerDetailModal } from './ServerDetailModal'
import { useAppStore } from '../store'
import { ipcError } from '../../shared/ipc-result'

vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key }) }))
vi.mock('./LiveServerCheckSection', () => ({ LiveServerCheckSection: () => null }))
const profile = { id: 'one', name: 'First', protocol: 'vless', server: 'vpn.example.test', port: 443, status: 'unknown' as const }
const other = { ...profile, id: 'two', name: 'Second' }
const methods = [['serversCopyKey', 'serverDetail.copyKey', 'serverDetail.keyCopied', 2200],
  ['serversExportKeyToFile', 'serverDetail.saveKey', 'serverDetail.keySaved', 2500]] as const
let pending: Array<{ resolve: (value: unknown) => void; reject: (value: unknown) => void }>
let api: Record<string, ReturnType<typeof vi.fn>>
const props = { open: true, profile, onClose: vi.fn() }
beforeEach(() => {
  useAppStore.setState(state => ({ settings: { ...state.settings, disableGeoLookup: true } }))
  pending = []
  api = { serverProbe: vi.fn(async () => null), operationsCancelRequest: vi.fn(async () => true),
    ...Object.fromEntries(methods.map(([method]) => [method, vi.fn(() => new Promise((resolve, reject) => pending.push({ resolve, reject })))])) }
  Object.assign(window, { electronAPI: api })
})
afterEach(() => { cleanup(); vi.restoreAllMocks() })

describe('detail export scope', () => {
  it.each(methods.flatMap(([method, label]) => ['close', 'profile', 'empty', 'unmount'].map(boundary => ({ method, label, boundary }))))
  ('cancels $method on $boundary without late flash effects', async ({ method, label, boundary }) => {
    const view = render(<ServerDetailModal {...props} />)
    await act(async () => {})
    fireEvent.click(screen.getByRole('button', { name: label }))
    expect(api[method]).toHaveBeenCalledOnce()
    if (boundary === 'unmount') view.unmount()
    else view.rerender(<ServerDetailModal {...props} open={boundary !== 'close'} profile={boundary === 'empty' ? null : boundary === 'profile' ? other : profile} />)
    expect(api.operationsCancelRequest).toHaveBeenCalledExactlyOnceWith(expect.stringMatching(/^[0-9a-f-]{36}$/))
    expect(api[method].mock.calls[0]).toEqual([profile.id, api.operationsCancelRequest.mock.calls[0][0]])
    const timers = vi.spyOn(window, 'setTimeout')
    await act(async () => { pending[0].resolve({ ok: true }) })
    expect(timers.mock.calls.some(call => [2200, 2500].includes(Number(call[1])))).toBe(false)
    if (boundary === 'profile') expect(screen.getByRole('button', { name: label })).toBeTruthy()
  })

  it.each(methods)('finishes current %s, forgets the token and clears its flash timer', async (method, label, success, duration) => {
    const view = render(<ServerDetailModal {...props} />)
    await act(async () => {})
    const timers = vi.spyOn(window, 'setTimeout'), clear = vi.spyOn(window, 'clearTimeout')
    fireEvent.click(screen.getByRole('button', { name: label }))
    await act(async () => { pending[0].resolve({ ok: true }) })
    expect(screen.getByRole('button', { name: success })).toBeTruthy()
    const index = timers.mock.calls.findIndex(call => call[1] === duration)
    expect(index).toBeGreaterThanOrEqual(0)
    view.rerender(<ServerDetailModal {...props} open={false} />)
    expect(clear).toHaveBeenCalledWith(timers.mock.results[index].value)
    expect(api.operationsCancelRequest).not.toHaveBeenCalled()
  })

  it.each(methods)('keeps cancelled %s quiet and rejects a late old-profile error', async (method, label, success) => {
    const view = render(<ServerDetailModal {...props} />)
    await act(async () => {})
    fireEvent.click(screen.getByRole('button', { name: label }))
    await act(async () => { pending[0].reject({ name: 'IpcRemoteError', ...ipcError('cancelled') }) })
    expect(screen.queryByRole('button', { name: 'serverDetail.keyExportFailed' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: label }))
    view.rerender(<ServerDetailModal {...props} profile={other} />)
    fireEvent.click(screen.getByRole('button', { name: label }))
    await act(async () => { pending[2].resolve({ ok: true }); pending[1].reject(new Error('late old failure')) })
    expect(screen.getByRole('button', { name: success })).toBeTruthy()
    expect(api[method].mock.calls[2][0]).toBe(other.id)
    expect(api[method].mock.calls[2][1]).not.toBe(api[method].mock.calls[1][1])
    view.unmount()
    expect(api.operationsCancelRequest).toHaveBeenCalledTimes(1)
  })

  it.each(methods)('starts a fresh %s scope when reopening the same profile', async (method, label, success) => {
    const view = render(<ServerDetailModal {...props} />)
    await act(async () => {})
    fireEvent.click(screen.getByRole('button', { name: label }))
    view.rerender(<ServerDetailModal {...props} open={false} />)
    view.rerender(<ServerDetailModal {...props} />)
    fireEvent.click(screen.getByRole('button', { name: label }))
    await act(async () => { pending[1].resolve({ ok: true }); pending[0].reject(new Error('closed request')) })
    expect(screen.getByRole('button', { name: success })).toBeTruthy()
    expect(api[method].mock.calls[1][1]).not.toBe(api[method].mock.calls[0][1])
    view.unmount()
    expect(api.operationsCancelRequest).toHaveBeenCalledTimes(1)
  })

  it('keeps same-profile metadata refresh in its scope and cancels both pending destinations on unmount', async () => {
    const view = render(<ServerDetailModal {...props} />)
    await act(async () => {})
    fireEvent.click(screen.getByRole('button', { name: 'serverDetail.copyKey' }))
    view.rerender(<ServerDetailModal {...props} profile={{ ...profile, name: 'Renamed' }} />)
    expect(api.operationsCancelRequest).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'serverDetail.saveKey' }))
    view.unmount()
    expect(api.operationsCancelRequest).toHaveBeenCalledTimes(2)
    expect(api.operationsCancelRequest).toHaveBeenCalledWith(api.serversCopyKey.mock.calls[0][1])
    expect(api.operationsCancelRequest).toHaveBeenCalledWith(api.serversExportKeyToFile.mock.calls[0][1])
    const timers = vi.spyOn(window, 'setTimeout')
    await act(async () => { pending[0].resolve({ ok: true }); pending[1].resolve({ ok: true }) })
    expect(timers.mock.calls.some(call => [2200, 2500].includes(Number(call[1])))).toBe(false)
  })
})
