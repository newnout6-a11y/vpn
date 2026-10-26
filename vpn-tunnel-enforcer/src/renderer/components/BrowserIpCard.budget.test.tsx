import { act, cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import type { ElectronAPI } from '../../shared/electron-api'
import { BrowserIpCard, BROWSER_CHECK_DEADLINE_MS, fetchBrowserIpv4 } from './BrowserIpCard'
import { PageActivityProvider } from '../hooks/usePageActive'
import { useAppStore } from '../store'

beforeEach(() => {
  vi.useFakeTimers()
  vi.stubGlobal('RTCPeerConnection', undefined)
  useAppStore.setState({ browserIpCheck: null, publicIp: '198.51.100.1', vpnIp: '198.51.100.1', tunRunning: true, logs: [] })
  window.electronAPI = { getPublicIp: vi.fn().mockResolvedValue({ ip: '198.51.100.1' }), logRenderer: vi.fn() } as unknown as ElectronAPI
})
afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals() })

function blockedFetch(_url: unknown, init?: RequestInit): Promise<Response> {
  return new Promise((_, reject) => {
    const abort = () => reject(new DOMException('Aborted', 'AbortError'))
    if (init?.signal?.aborted) abort()
    else init?.signal?.addEventListener('abort', abort, { once: true })
  })
}

function metricValue(label: string): Element {
  const value = screen.getByText(label).nextElementSibling
  expect(value).not.toBeNull()
  return value!
}

// AT-07-003/010/012, AT-09-010: real browser probes, mocked network boundary.
it('races both browser providers and drains the losing fetch after a valid answer', async () => {
  let loserAborted = false
  vi.stubGlobal('fetch', vi.fn((url: string, init?: RequestInit) => {
    if (url.includes('myip.com')) return Promise.resolve({ ok: true, json: async () => ({ ip: '198.51.100.2' }) })
    init?.signal?.addEventListener('abort', () => { loserAborted = true }, { once: true })
    return blockedFetch(url, init)
  }))
  expect(await fetchBrowserIpv4()).toBe('198.51.100.2')
  expect(fetch).toHaveBeenCalledTimes(2)
  expect(loserAborted).toBe(true)
  expect(vi.getTimerCount()).toBe(0)
})

it('uses one total deadline and reports missing browser/main proof without cached success', async () => {
  let lateMain!: (value: Awaited<ReturnType<ElectronAPI['getPublicIp']>>) => void
  vi.mocked(window.electronAPI.getPublicIp).mockImplementation(() => new Promise(resolve => { lateMain = resolve }))
  const signals: AbortSignal[] = []
  vi.stubGlobal('fetch', vi.fn((url: string, init?: RequestInit) => {
    signals.push(init!.signal!)
    return blockedFetch(url, init)
  }))
  render(<BrowserIpCard />)
  expect(screen.queryByText('198.51.100.1')).toBeNull()
  expect(metricValue('WebRTC').className).not.toContain('--color-success')
  expect(metricValue('Browser IPv6').className).not.toContain('--color-success')
  fireEvent.click(screen.getByText('Проверить браузер'))
  expect(fetch).toHaveBeenCalledTimes(3)
  await act(async () => { await vi.advanceTimersByTimeAsync(BROWSER_CHECK_DEADLINE_MS) })
  const result = useAppStore.getState().browserIpCheck
  expect(result).toMatchObject({ browserIpv4: null, nodeIp: null, browserMatchesNode: null, summary: 'info' })
  expect(result?.details.some(text => text.includes('видят один'))).toBe(false)
  expect(screen.getByText('Проверка браузера не завершена')).toBeTruthy()
  expect(metricValue('Main/Node IPv4').textContent).toBe('—')
  expect(metricValue('Browser IPv6').textContent).toBe('IPv6 не проверен')
  expect(metricValue('Browser IPv6').className).not.toContain('--color-success')
  expect(signals.every(signal => signal.aborted)).toBe(true)
  await act(async () => lateMain({ ip: '203.0.113.2', isLeak: false }))
  expect(useAppStore.getState().browserIpCheck).toBe(result)
})

it('shows a fresh browser IP neutrally when main or IPv6 verification fails', async () => {
  vi.mocked(window.electronAPI.getPublicIp).mockRejectedValue(new Error('main read failed'))
  vi.stubGlobal('fetch', vi.fn(async (url: string) => ({
    ok: true, json: async () => ({ ip: url.includes('api6.') ? 'invalid:ipv6' : '198.51.100.2' })
  })))
  render(<BrowserIpCard />)
  fireEvent.click(screen.getByText('Проверить браузер'))
  await act(async () => {})
  expect(useAppStore.getState().browserIpCheck).toMatchObject({
    browserIpv4: '198.51.100.2', browserIpv6: null, nodeIp: null, browserMatchesNode: null, summary: 'info'
  })
  expect(metricValue('Browser IPv4').className).not.toContain('--color-success')
  expect(metricValue('Main/Node IPv4').textContent).toBe('—')
  expect(metricValue('Browser IPv6').className).not.toContain('--color-success')
})

it('does not substitute cached main IP when the browser probe throws', async () => {
  vi.stubGlobal('RTCPeerConnection', class { constructor() { throw new Error('WebRTC initialization failed') } })
  vi.stubGlobal('fetch', vi.fn((url: string, init?: RequestInit) => blockedFetch(url, init)))
  render(<BrowserIpCard />)
  fireEvent.click(screen.getByText('Проверить браузер'))
  await act(async () => {})
  expect(useAppStore.getState().browserIpCheck).toMatchObject({ nodeIp: null, browserIpv4: null, browserMatchesNode: null })
  expect(metricValue('Main/Node IPv4').textContent).toBe('—')
  expect(screen.queryByText('198.51.100.1')).toBeNull()
})

it('aborts a browser check on page deactivation and ignores its late main reply', async () => {
  let lateMain!: (value: Awaited<ReturnType<ElectronAPI['getPublicIp']>>) => void
  vi.mocked(window.electronAPI.getPublicIp).mockImplementation(() => new Promise(resolve => { lateMain = resolve }))
  const signals: AbortSignal[] = []
  vi.stubGlobal('fetch', vi.fn((url: string, init?: RequestInit) => {
    signals.push(init!.signal!)
    return blockedFetch(url, init)
  }))
  const view = (active: boolean) => <PageActivityProvider value={active}><BrowserIpCard /></PageActivityProvider>
  const mounted = render(view(true))
  fireEvent.click(screen.getByText('Проверить браузер'))
  mounted.rerender(view(false))
  await act(async () => lateMain({ ip: '203.0.113.2', isLeak: false }))
  expect(signals.every(signal => signal.aborted)).toBe(true)
  expect(useAppStore.getState().browserIpCheck).toBeNull()
})
