// AT-00-003/008: production page, cancellation identity and stale UI callbacks.
import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ru from '../i18n/locales/ru.json'
import { SpeedTest } from './SpeedTest'
import { useAppStore } from '../store'
import type { SpeedTestResult } from '../../shared/ipc-types'

vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => {
  const [section, name] = key.split('.')
  const sections: Record<string, Record<string, string>> = { speedTest: ru.speedTest, common: ru.common }
  return sections[section]?.[name] ?? key
} }) }))
vi.mock('../components/PageTip', () => ({ PageTip: () => null }))

function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (error: unknown) => void
  const promise = new Promise<T>((ok, fail) => { resolve = ok; reject = fail })
  return { promise, resolve, reject }
}
const result: SpeedTestResult = { id: 'one', timestamp: 1, downloadMbps: 123, uploadMbps: 45,
  latencyMs: 6, serverName: 'Fixture CDN', profileUsed: 'Fixture profile' }
let run: ReturnType<typeof deferred<SpeedTestResult>>
let progress: (data: { percent: number; phase: string; requestId?: string }) => void
const dispose = vi.fn()
beforeEach(() => {
  vi.clearAllMocks()
  useAppStore.setState({ tunRunning: true })
  run = deferred<SpeedTestResult>()
  ;(window as any).electronAPI = {
    speedTestRun: vi.fn(() => run.promise), speedTestCancel: vi.fn(async () => true),
    speedTestHistory: vi.fn(async () => []),
    onSpeedTestProgress: vi.fn(callback => { progress = callback; return dispose })
  }
})
afterEach(cleanup)
const start = () => fireEvent.click(screen.getByRole('button', { name: ru.speedTest.runTest }))
const requestedId = () => vi.mocked(window.electronAPI.speedTestRun).mock.calls[0][0]

describe('speed test page lifetime', () => {
  it('owns a request before progress, ignores other requests, and cancels explicitly', async () => {
    render(<SpeedTest />)
    start()
    expect(requestedId()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    await act(async () => { progress({ percent: 77, phase: 'download', requestId: 'other' }) })
    expect(screen.queryByText('77%')).not.toBeInTheDocument()
    await act(async () => { progress({ percent: 45, phase: 'download', requestId: requestedId() }) })
    expect(screen.getByText('45%')).toBeVisible()
    fireEvent.click(screen.getByRole('button', { name: ru.common.cancel }))
    expect(window.electronAPI.speedTestCancel).toHaveBeenCalledWith(requestedId())
    await act(async () => { run.reject({ name: 'IpcRemoteError', code: 'IPC_CANCELLED', category: 'cancelled', message: 'Операция отменена' }) })
    expect(screen.getByRole('button', { name: ru.speedTest.runTest })).toBeEnabled()
    expect(screen.queryByText('Операция отменена')).not.toBeInTheDocument()
    expect(window.electronAPI.speedTestHistory).toHaveBeenCalledTimes(1)
  })

  it('cancels on unmount before first progress and ignores a late result after remount', async () => {
    const first = render(<SpeedTest />)
    start()
    const id = requestedId(), oldProgress = progress, oldRun = run
    first.unmount()
    expect(dispose).toHaveBeenCalledTimes(1)
    expect(window.electronAPI.speedTestCancel).toHaveBeenCalledWith(id)
    run = deferred<SpeedTestResult>()
    render(<SpeedTest />)
    start()
    await act(async () => { oldProgress({ percent: 99, phase: 'complete', requestId: id }); oldRun.resolve(result) })
    expect(screen.queryByText('Fixture CDN')).not.toBeInTheDocument()
    expect(screen.queryByText('99%')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: ru.speedTest.running })).toBeDisabled()
    expect(window.electronAPI.speedTestHistory).toHaveBeenCalledTimes(2)
  })

  it('does not replace post-run history with a slow initial history read', async () => {
    const oldHistory = deferred<SpeedTestResult[]>()
    vi.mocked(window.electronAPI.speedTestHistory).mockImplementationOnce(() => oldHistory.promise).mockResolvedValue([result])
    render(<SpeedTest />)
    start()
    await act(async () => { run.resolve(result) })
    await waitFor(() => expect(window.electronAPI.speedTestHistory).toHaveBeenCalledTimes(2))
    await act(async () => { oldHistory.resolve([]) })
    expect(screen.queryByText(ru.speedTest.noHistory)).not.toBeInTheDocument()
  })

  it('finishes the run without waiting for the history refresh, and permits retry after a cancel failure', async () => {
    const history = deferred<SpeedTestResult[]>()
    vi.mocked(window.electronAPI.speedTestHistory).mockResolvedValueOnce([]).mockImplementationOnce(() => history.promise)
    vi.mocked(window.electronAPI.speedTestCancel).mockRejectedValueOnce(new Error('bounded cancellation failure'))
    render(<SpeedTest />)
    start()
    fireEvent.click(screen.getByRole('button', { name: ru.common.cancel }))
    expect(await screen.findByText('bounded cancellation failure')).toBeVisible()
    expect(screen.getByRole('button', { name: ru.common.cancel })).toBeEnabled()
    await act(async () => { run.resolve(result) })
    expect(screen.getByRole('button', { name: ru.speedTest.runTest })).toBeEnabled()
    await act(async () => { history.resolve([result]) })
  })

  it('ignores late run and history failures after unmount (AT-00-003)', async () => {
    const history = deferred<SpeedTestResult[]>()
    vi.mocked(window.electronAPI.speedTestHistory).mockImplementationOnce(() => history.promise)
    const logged = vi.spyOn(console, 'error').mockImplementation(() => {})
    try {
      const page = render(<SpeedTest />)
      start()
      page.unmount()
      await act(async () => { run.reject(new Error('late run failure')); history.reject(new Error('late history failure')) })
      expect(logged).not.toHaveBeenCalled()
      expect(window.electronAPI.speedTestHistory).toHaveBeenCalledTimes(1)
      expect(window.electronAPI.speedTestCancel).toHaveBeenCalledWith(requestedId())
    } finally { logged.mockRestore() }
  })
})
