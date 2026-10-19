// AT-00-003/008: actual modal; controlled IPC/fetch responses after cleanup.
import { act, cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ServerDetailModal } from './ServerDetailModal'
import { useAppStore } from '../store'
import { ipcError } from '../../shared/ipc-result'
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key }) }))
vi.mock('./LiveServerCheckSection', () => ({ LiveServerCheckSection: () => null }))
const profile = { id: 'one', name: 'First', protocol: 'vless', server: 'vpn.example.test', port: 8443, status: 'unknown' as const }
const other = { ...profile, id: 'two', name: 'Second', server: 'other.example.test' }
const props = { open: true, profile, onClose: vi.fn() }
let api: Record<string, ReturnType<typeof vi.fn>>, fetchMock: ReturnType<typeof vi.fn>
function deferred() { let resolve!: (value: any) => void, reject!: (error: any) => void
  const promise = new Promise<any>((yes, no) => { resolve = yes; reject = no }); return { promise, resolve, reject } }
const result = (org: string) => ({ host: profile.server, resolvedIps: ['8.8.8.8'], reverseDns: null,
  asn: { asn: 'AS1', org, country: '', network: '' }, latency: null, openPorts: [], tlsCert: null, httpBanner: null })
beforeEach(() => {
  useAppStore.setState(state => ({ settings: { ...state.settings, disableGeoLookup: true } }))
  api = { serverProbe: vi.fn(async () => null), operationsCancelRequest: vi.fn(async () => true) }
  Object.assign(window, { electronAPI: api }); fetchMock = vi.fn(); vi.stubGlobal('fetch', fetchMock)
})
afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks() })
describe('server detail probe scope', () => {
  it.each(['close', 'profile', 'empty', 'unmount'])('cancels its pending main probe on %s and fences late replies', async boundary => {
    const first = deferred(), next = deferred()
    api.serverProbe.mockReturnValueOnce(first.promise).mockReturnValueOnce(next.promise)
    const view = render(<ServerDetailModal {...props} />)
    const token = api.serverProbe.mock.calls[0][2]
    expect(token).toMatch(/^[0-9a-f-]{36}$/)
    if (boundary === 'unmount') view.unmount()
    else view.rerender(<ServerDetailModal {...props} open={boundary !== 'close'} profile={boundary === 'empty' ? null : boundary === 'profile' ? other : profile} />)
    expect(api.operationsCancelRequest).toHaveBeenCalledExactlyOnceWith(token)
    if (boundary === 'profile') {
      expect(api.serverProbe.mock.calls[1][2]).not.toBe(token)
      await act(async () => { next.resolve(result('CURRENT-PROBE')) })
    }
    await act(async () => { first.resolve(result('OLD-PROBE')) })
    expect(screen.queryByText('OLD-PROBE')).toBeNull()
    if (boundary === 'profile') expect(screen.getByText('CURRENT-PROBE')).toBeTruthy()
  })
  it('cancels on the UI deadline and does not display a late result', async () => {
    vi.useFakeTimers(); const pending = deferred(); api.serverProbe.mockReturnValue(pending.promise)
    render(<ServerDetailModal {...props} />)
    await act(async () => { await vi.advanceTimersByTimeAsync(10_001) })
    expect(api.operationsCancelRequest).toHaveBeenCalledExactlyOnceWith(api.serverProbe.mock.calls[0][2])
    await act(async () => { pending.resolve(result('LATE-PROBE')) })
    expect(screen.queryByText('LATE-PROBE')).toBeNull()
  })
  it('does not cancel an already settled probe on cleanup', async () => {
    const view = render(<ServerDetailModal {...props} />); await act(async () => {})
    view.unmount(); expect(api.operationsCancelRequest).not.toHaveBeenCalled()
  })
  it('keeps typed cancellation quiet', async () => {
    const pending = deferred(); api.serverProbe.mockReturnValue(pending.promise)
    render(<ServerDetailModal {...props} />)
    await act(async () => { pending.reject({ name: 'IpcRemoteError', ...ipcError('cancelled') }) })
    expect(screen.queryByText('serverDetail.probeError')).toBeNull()
    expect(screen.queryByText('serverDetail.probing')).toBeNull()
  })
  it.each(['response', 'body'])('aborts geo on close before late %s can start fallback', async stage => {
    useAppStore.setState(state => ({ settings: { ...state.settings, disableGeoLookup: false } }))
    const held = deferred()
    fetchMock.mockImplementationOnce(() => stage === 'response' ? held.promise : Promise.resolve({ ok: true, json: () => held.promise }))
    const view = render(<ServerDetailModal {...props} />); await act(async () => {})
    const signal = fetchMock.mock.calls[0][1]?.signal
    expect(signal).toBeInstanceOf(AbortSignal)
    view.unmount(); expect(signal.aborted).toBe(true)
    await act(async () => { held.resolve(stage === 'response' ? { ok: false } : { error: true }) })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
  it('aborts an active geo fallback and stops geo after its deadline', async () => {
    vi.useFakeTimers(); useAppStore.setState(state => ({ settings: { ...state.settings, disableGeoLookup: false } }))
    const pending = deferred()
    fetchMock.mockResolvedValueOnce({ ok: false }).mockReturnValueOnce(pending.promise)
    const view = render(<ServerDetailModal {...props} />); await act(async () => {})
    expect(fetchMock).toHaveBeenCalledTimes(2)
    const signal = fetchMock.mock.calls[1][1]?.signal
    expect(signal).toBeInstanceOf(AbortSignal)
    await act(async () => { await vi.advanceTimersByTimeAsync(10_001) })
    expect(signal.aborted).toBe(true)
    view.unmount(); await act(async () => { pending.resolve({ ok: false }) })
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
  it('fences group replies after profile replacement, including profiles without a host', async () => {
    const oldGroup = deferred(), newGroup = deferred()
    api.groupsGet = vi.fn().mockReturnValueOnce(oldGroup.promise).mockReturnValueOnce(newGroup.promise)
    const first = { ...profile, server: '', groupId: 'old-group' }
    const second = { ...other, server: '', groupId: 'new-group' }
    const view = render(<ServerDetailModal {...props} profile={first} />)
    view.rerender(<ServerDetailModal {...props} profile={second} />)
    await act(async () => { newGroup.resolve({ id: 'new-group', name: 'CURRENT-GROUP', source: 'manual', status: 'active' }) })
    await act(async () => { oldGroup.resolve({ id: 'old-group', name: 'OLD-GROUP', source: 'manual', status: 'active' }) })
    expect(screen.queryByText('OLD-GROUP')).toBeNull()
    expect(screen.getByText('CURRENT-GROUP')).toBeTruthy()
    expect(api.serverProbe).not.toHaveBeenCalled()
  })
})
