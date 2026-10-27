import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import type { ElectronAPI } from '../../shared/electron-api'
import { PageActivityProvider } from './usePageActive'
import { DiagnosticsCard } from '../components/DiagnosticsCard'
import { useForeignVpn } from '../components/useForeignVpn'
import { DashboardSide } from '../components/DashboardSide'
import { useAppStore } from '../store'

vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string, fallback?: string) => fallback ?? key }) }))
vi.mock('../components/CountryFlagIcon', () => ({ CountryFlagIcon: () => null }))

function visible(value: boolean) {
  Object.defineProperty(document, 'hidden', { configurable: true, value: !value })
  document.dispatchEvent(new Event('visibilitychange'))
}
beforeEach(() => {
  vi.useFakeTimers()
  visible(true)
  useAppStore.setState({ tunRunning: false, serverSwitchingName: null, connectionBusy: null, logs: [] })
  window.electronAPI = {
    getTrafficForensicsStatus: vi.fn().mockResolvedValue({ running: false, enabled: false }),
    detectForeignVpn: vi.fn().mockResolvedValue({ foreign: null }),
    serversList: vi.fn().mockResolvedValue([]), serversGetActive: vi.fn().mockResolvedValue({ activeId: null, profile: null }),
    groupsList: vi.fn().mockResolvedValue([]), trafficHistoryList: vi.fn().mockResolvedValue([]),
    logRenderer: vi.fn().mockResolvedValue(undefined)
  } as unknown as ElectronAPI
})
afterEach(() => { cleanup(); visible(true); vi.useRealTimers() })

// AT-07-010 / AT-09-010: pausing readers must preserve visited form drafts.
it('pauses hidden/inactive diagnostics and resumes with one catch-up wave, retaining drafts', async () => {
  const view = (active: boolean) => <PageActivityProvider value={active}>
    <input aria-label="draft" defaultValue="original" /><DiagnosticsCard />
  </PageActivityProvider>
  const mounted = render(view(true))
  await act(async () => {})
  fireEvent.change(screen.getByLabelText('draft'), { target: { value: 'unsaved edit' } })
  expect(window.electronAPI.getTrafficForensicsStatus).toHaveBeenCalledTimes(1)
  mounted.rerender(view(false))
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000) })
  expect(window.electronAPI.getTrafficForensicsStatus).toHaveBeenCalledTimes(1)
  mounted.rerender(view(true))
  await act(async () => {})
  expect(window.electronAPI.getTrafficForensicsStatus).toHaveBeenCalledTimes(2)
  act(() => visible(false))
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000) })
  expect(window.electronAPI.getTrafficForensicsStatus).toHaveBeenCalledTimes(2)
  await act(async () => visible(true))
  expect(window.electronAPI.getTrafficForensicsStatus).toHaveBeenCalledTimes(3)
  expect(screen.getByLabelText('draft')).toHaveValue('unsaved edit')
})

it('discards an old diagnostics response after the page has resumed', async () => {
  let old!: (status: Awaited<ReturnType<ElectronAPI['getTrafficForensicsStatus']>>) => void
  vi.mocked(window.electronAPI.getTrafficForensicsStatus).mockImplementationOnce(() => new Promise(resolve => { old = resolve }))
  const view = (active: boolean) => <PageActivityProvider value={active}><DiagnosticsCard /></PageActivityProvider>
  const mounted = render(view(true))
  mounted.rerender(view(false))
  mounted.rerender(view(true))
  await act(async () => {})
  await act(async () => old({ running: true, enabled: true, lastError: 'stale failure' } as Awaited<ReturnType<ElectronAPI['getTrafficForensicsStatus']>>))
  expect(screen.queryByText('stale failure')).not.toBeInTheDocument()
  expect(vi.getTimerCount()).toBe(1)
  mounted.unmount()
  expect(vi.getTimerCount()).toBe(0)
})

it('runs only the active server readers and fences foreign-VPN replies when TUN starts', async () => {
  let resolveForeign!: (result: { foreign: string }) => void
  vi.mocked(window.electronAPI.detectForeignVpn).mockImplementation(() => new Promise(resolve => { resolveForeign = resolve }))
  function Banner() { return <output>{useForeignVpn() ?? 'none'}</output> }
  const view = (active: boolean) => <PageActivityProvider value={active}><DashboardSide /><Banner /><Banner /></PageActivityProvider>
  const mounted = render(view(false))
  await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
  expect(window.electronAPI.serversList).not.toHaveBeenCalled()
  mounted.rerender(view(true))
  await act(async () => {})
  expect(window.electronAPI.serversList).toHaveBeenCalledTimes(1)
  expect(window.electronAPI.detectForeignVpn).toHaveBeenCalledTimes(1)
  await act(async () => { useAppStore.setState({ tunRunning: true }); resolveForeign({ foreign: 'stale tunnel' }) })
  expect(screen.queryByText('stale tunnel')).not.toBeInTheDocument()
  mounted.rerender(view(false))
  const before = vi.mocked(window.electronAPI.serversList).mock.calls.length
  await act(async () => { await vi.advanceTimersByTimeAsync(30_000) })
  expect(window.electronAPI.serversList).toHaveBeenCalledTimes(before)
})
