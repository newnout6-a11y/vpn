import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { LiveServerBatchComparison } from './LiveServerBatchComparison'
import { ipcError } from '../../shared/ipc-result'
import i18n from '../i18n'
import type { LiveServerBatchCheckProgress, LiveServerBatchCheckResult, ServerProfile } from '../../shared/ipc-types'

const profiles = [{ id: 'p1', name: 'Fixture server', server: 'fixture.invalid', port: 443 }] as ServerProfile[]
const deferred = () => {
  let resolve!: (result: LiveServerBatchCheckResult) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<LiveServerBatchCheckResult>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
const result = (requestId: string): LiveServerBatchCheckResult => ({
  requestId, mode: 'extended', startedAt: '', finishedAt: '', cancelled: false, results: [], errors: []
})
let listener: (progress: LiveServerBatchCheckProgress) => void
let api: { serverLiveCheckBatch: ReturnType<typeof vi.fn>; serverLiveCheckCancel: ReturnType<typeof vi.fn>; onLiveBatchCheckProgress: ReturnType<typeof vi.fn> }
let unsubscribe: ReturnType<typeof vi.fn>
const start = () => fireEvent.click(screen.getByRole('button', { name: 'Запустить сравнение' }))
const progress = (requestId: string, sequence: number, stage: 'dns' | 'tls' = 'dns'): LiveServerBatchCheckProgress => ({
  requestId, sequence, profileId: 'p1', index: 0, total: 1, status: 'running', stage
})

beforeEach(async () => {
  await i18n.changeLanguage('ru')
  unsubscribe = vi.fn()
  api = {
    serverLiveCheckBatch: vi.fn(), serverLiveCheckCancel: vi.fn().mockResolvedValue({ cancelled: true }),
    onLiveBatchCheckProgress: vi.fn(fn => { listener = fn; return unsubscribe })
  }
  window.electronAPI = api as unknown as typeof window.electronAPI
})
afterEach(cleanup)

describe('AT-00-003 / AT-00-004: batch request lifetime', () => {
  it.each([['en', 'Preparing check…'], ['ru', 'Подготовка проверки…']])('localizes preparation in %s', async (locale, label) => {
    await i18n.changeLanguage(locale)
    api.serverLiveCheckBatch.mockReturnValue(new Promise(() => {}))
    render(<LiveServerBatchComparison open profiles={profiles} onClose={vi.fn()} />)
    start()
    expect(screen.getByRole('status')).toHaveTextContent(label)
  })
  it('owns a UUID and offers cancel before the first progress event', async () => {
    api.serverLiveCheckBatch.mockReturnValue(new Promise(() => {}))
    render(<LiveServerBatchComparison open profiles={profiles} onClose={vi.fn()} />)
    start()
    const id = api.serverLiveCheckBatch.mock.calls[0][0].requestId
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i)
    fireEvent.click(screen.getByRole('button', { name: 'Отмена' }))
    expect(api.serverLiveCheckCancel).toHaveBeenCalledWith(id)
    expect(screen.getByRole('button', { name: 'Запустить сравнение' })).toBeEnabled()
  })

  it('accepts only matching, increasing progress while a request is active', async () => {
    const pending = deferred()
    api.serverLiveCheckBatch.mockReturnValue(pending.promise)
    render(<LiveServerBatchComparison open profiles={profiles} onClose={vi.fn()} />)
    start()
    const id = api.serverLiveCheckBatch.mock.calls[0][0].requestId
    await act(async () => listener(progress('another-request', 99, 'tls')))
    expect(screen.queryByText('tls')).not.toBeInTheDocument()
    await act(async () => listener(progress(id, 2, 'tls')))
    await act(async () => listener(progress(id, 1, 'dns')))
    expect(screen.getByText('tls')).toBeInTheDocument()
    expect(screen.queryByText('dns')).not.toBeInTheDocument()
    await act(async () => pending.resolve(result(id)))
    await act(async () => listener(progress(id, 3, 'dns')))
    expect(screen.getByText('Готово')).toBeInTheDocument()
    expect(screen.queryByText('dns')).not.toBeInTheDocument()
  })

  it.each(['resolve', 'reject'] as const)('ignores late %s and finally from a cancelled run during a new run', async outcome => {
    const old = deferred(), current = deferred()
    api.serverLiveCheckBatch.mockReturnValueOnce(old.promise).mockReturnValueOnce(current.promise)
    render(<LiveServerBatchComparison open profiles={profiles} onClose={vi.fn()} />)
    start()
    const oldId = api.serverLiveCheckBatch.mock.calls[0][0].requestId
    // Supply progress so this also reproduces the old early-release UI race.
    await act(async () => listener(progress(oldId, 1)))
    fireEvent.click(screen.getByRole('button', { name: 'Отмена' }))
    start()
    const id = api.serverLiveCheckBatch.mock.calls[1][0].requestId
    await act(async () => outcome === 'resolve' ? old.resolve(result(oldId)) : old.reject(new Error('late failure')))
    expect(screen.getByRole('button', { name: 'Отмена' })).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.queryByText('Готово')).not.toBeInTheDocument()
    await act(async () => current.resolve(result(id)))
    expect(screen.getByText('Готово')).toBeInTheDocument()
  })

  it.each(['hide', 'unmount'] as const)('cancels and unsubscribes on %s, ignoring a late error', async action => {
    const old = deferred()
    api.serverLiveCheckBatch.mockReturnValue(old.promise)
    const view = render(<LiveServerBatchComparison open profiles={profiles} onClose={vi.fn()} />)
    start()
    const id = api.serverLiveCheckBatch.mock.calls[0][0].requestId
    if (action === 'unmount') view.unmount()
    else view.rerender(<LiveServerBatchComparison open={false} profiles={profiles} onClose={vi.fn()} />)
    expect(api.serverLiveCheckCancel).toHaveBeenCalledWith(id)
    expect(unsubscribe).toHaveBeenCalled()
    await act(async () => old.reject(new Error('late failure')))
    if (action === 'hide') {
      view.rerender(<LiveServerBatchComparison open profiles={profiles} onClose={vi.fn()} />)
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
      expect(screen.getByRole('button', { name: 'Запустить сравнение' })).toBeEnabled()
    }
  })

  it.each(['cancelled', 'timeout'] as const)('treats typed %s distinctly', async category => {
    api.serverLiveCheckBatch.mockRejectedValue({ name: 'IpcRemoteError', ...ipcError(category) })
    render(<LiveServerBatchComparison open profiles={profiles} onClose={vi.fn()} />)
    await act(async () => start())
    if (category === 'cancelled') expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    else expect(screen.getByRole('alert')).toHaveTextContent(ipcError(category).message)
    expect(screen.getByRole('button', { name: 'Запустить сравнение' })).toBeEnabled()
  })

  it('isolates the reopened dialog from old responses and unsubscribed progress callbacks', async () => {
    const old = deferred(), current = deferred()
    api.serverLiveCheckBatch.mockReturnValueOnce(old.promise).mockReturnValueOnce(current.promise)
    const view = render(<LiveServerBatchComparison open profiles={profiles} onClose={vi.fn()} />)
    start()
    const staleListener = listener
    const oldId = api.serverLiveCheckBatch.mock.calls[0][0].requestId
    view.rerender(<LiveServerBatchComparison open={false} profiles={profiles} onClose={vi.fn()} />)
    view.rerender(<LiveServerBatchComparison open profiles={profiles} onClose={vi.fn()} />)
    start()
    const id = api.serverLiveCheckBatch.mock.calls[1][0].requestId
    await act(async () => staleListener(progress(id, 99, 'tls')))
    await act(async () => listener(progress(oldId, 99, 'tls')))
    expect(screen.queryByText('tls')).not.toBeInTheDocument()
    await act(async () => old.resolve(result(oldId)))
    expect(screen.getByRole('button', { name: 'Отмена' })).toBeInTheDocument()
    await act(async () => current.resolve(result(id)))
    expect(screen.getByText('Готово')).toBeInTheDocument()
  })
})
