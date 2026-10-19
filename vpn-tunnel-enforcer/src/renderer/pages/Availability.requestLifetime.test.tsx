// AT-00-003/008: actual page handlers and React unmount with held IPC replies.
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Availability } from './Availability'
import { useAppStore } from '../store'
import { ipcError } from '../../shared/ipc-result'

let release: (value: unknown) => void, reject: (error: unknown) => void
let api: Record<string, ReturnType<typeof vi.fn>>
const result = { id: 'result', url: 'https://example.test/', testedAt: 1, tunnelActive: false,
  tunnel: null, direct: null, verdict: 'works-both', recommendation: 'FAKE-current-result' }
beforeEach(() => {
  useAppStore.setState({ logs: [], tunRunning: false })
  api = { urlAvailabilityHistory: vi.fn(async () => []), operationsCancelRequest: vi.fn(async () => true),
    urlAvailabilityCheck: vi.fn(() => new Promise((done, fail) => { release = done; reject = fail })) }
  Object.assign(window, { electronAPI: api })
})
afterEach(() => { cleanup(); vi.restoreAllMocks() })
function start() {
  const view = render(<Availability />)
  fireEvent.change(screen.getByPlaceholderText('https://youtube.com или просто youtube.com'), { target: { value: 'https://example.test/' } })
  fireEvent.click(screen.getAllByRole('button', { name: 'Проверить' })[0])
  return view
}
describe('URL check requester lifetime', () => {
  it.each(['success', 'error'])('cancels on unmount and suppresses late %s effects', async outcome => {
    const view = start()
    expect(api.urlAvailabilityCheck).toHaveBeenCalledOnce()
    view.unmount()
    expect(api.operationsCancelRequest).toHaveBeenCalledExactlyOnceWith(expect.stringMatching(/^[0-9a-f-]{36}$/))
    expect(api.urlAvailabilityCheck.mock.calls[0][1]).toBe(api.operationsCancelRequest.mock.calls[0][0])
    const reads = api.urlAvailabilityHistory.mock.calls.length
    await act(async () => {
      if (outcome === 'success') release(result)
      else reject({ name: 'IpcRemoteError', ...ipcError('internal') })
    })
    expect(api.urlAvailabilityHistory).toHaveBeenCalledTimes(reads)
    expect(useAppStore.getState().logs).toEqual([])
  })

  it('keeps typed cancellation quiet and forgets its completed token', async () => {
    api.urlAvailabilityCheck.mockRejectedValue({ name: 'IpcRemoteError', ...ipcError('cancelled') })
    const view = start()
    await waitFor(() => expect(screen.queryByText('Проверяем…')).toBeNull())
    expect(screen.queryByText(ipcError('cancelled').message)).toBeNull()
    expect(useAppStore.getState().logs).toEqual([])
    view.unmount()
    expect(api.operationsCancelRequest).not.toHaveBeenCalled()
  })

  it('publishes current success and refreshes history once', async () => {
    const view = start()
    await act(async () => { release(result) })
    expect(screen.getByText('FAKE-current-result')).toBeTruthy()
    expect(api.urlAvailabilityHistory).toHaveBeenCalledTimes(2)
    expect(useAppStore.getState().logs).toHaveLength(1)
    view.unmount()
    expect(api.operationsCancelRequest).not.toHaveBeenCalled()
  })

  it('shows a current typed failure and allows a new request', async () => {
    start()
    await act(async () => { reject({ name: 'IpcRemoteError', ...ipcError('permission') }) })
    expect(screen.getByText(ipcError('permission').message)).toBeTruthy()
    fireEvent.click(screen.getAllByRole('button', { name: 'Проверить' })[0])
    expect(api.urlAvailabilityCheck).toHaveBeenCalledTimes(2)
    expect(api.urlAvailabilityCheck.mock.calls[0][1]).not.toBe(api.urlAvailabilityCheck.mock.calls[1][1])
    await act(async () => { release(result) })
  })

  it('explains the expected URL format for a typed validation failure', async () => {
    start()
    await act(async () => { reject({ name: 'IpcRemoteError', ...ipcError('validation') }) })
    expect(screen.getByText(/Введите URL вида example\.com или https:\/\/example\.com\/path/)).toBeTruthy()
  })
})

describe('routing check requester lifetime', () => {
  function startRouting() {
    useAppStore.setState({ tunRunning: true })
    api.runRoutingSelfTest = vi.fn(() => new Promise((done, fail) => { release = done; reject = fail }))
    const view = render(<Availability />)
    fireEvent.click(screen.getAllByRole('button', { name: 'Проверить' })[1])
    return view
  }
  it.each(['success', 'error'])('cancels and fences late %s on unmount', async outcome => {
    const view = startRouting()
    const token = api.runRoutingSelfTest.mock.calls[0][0]
    expect(token).toMatch(/^[0-9a-f-]{36}$/)
    view.unmount()
    expect(api.operationsCancelRequest).toHaveBeenCalledExactlyOnceWith(token)
    await act(async () => {
      if (outcome === 'success') release({ verdict: 'ok', smartRu: {}, message: 'FAKE-late' })
      else reject({ name: 'IpcRemoteError', ...ipcError('internal') })
    })
    expect(useAppStore.getState().logs).toEqual([])
  })
  it('keeps cancellation quiet and releases the finished token', async () => {
    const view = startRouting()
    await act(async () => { reject({ name: 'IpcRemoteError', ...ipcError('cancelled') }) })
    expect(useAppStore.getState().logs).toEqual([])
    view.unmount(); expect(api.operationsCancelRequest).not.toHaveBeenCalled()
  })
  it('publishes current routing results and does not cancel finished work', async () => {
    const view = startRouting()
    await act(async () => { release({ verdict: 'ok', smartRu: { enabled: false }, message: 'FAKE-current-route' }) })
    expect(screen.getByText('FAKE-current-route')).toBeTruthy()
    expect(useAppStore.getState().logs).toHaveLength(1)
    view.unmount(); expect(api.operationsCancelRequest).not.toHaveBeenCalled()
  })
  it('uses separate cancellation tokens for simultaneous URL and routing checks', async () => {
    const view = startRouting(), routeRelease = release
    fireEvent.change(screen.getByPlaceholderText('https://youtube.com или просто youtube.com'), { target: { value: 'https://example.test/' } })
    fireEvent.click(screen.getAllByRole('button', { name: 'Проверить' })[0])
    const urlRelease = release, routeToken = api.runRoutingSelfTest.mock.calls[0][0], urlToken = api.urlAvailabilityCheck.mock.calls[0][1]
    expect(routeToken).not.toBe(urlToken)
    view.unmount()
    expect(api.operationsCancelRequest).toHaveBeenCalledWith(routeToken)
    expect(api.operationsCancelRequest).toHaveBeenCalledWith(urlToken)
    expect(api.operationsCancelRequest).toHaveBeenCalledTimes(2)
    await act(async () => { routeRelease({ verdict: 'ok' }); urlRelease(result) })
    expect(useAppStore.getState().logs).toEqual([])
  })
})
