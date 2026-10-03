// AT-00-003 / AT-00-007 / AT-00-008 / F-019 / F-021: cancelled selection owns cleanup.
import '@testing-library/jest-dom/vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string, fallback?: string) => fallback ?? key }) }))
vi.mock('./CountryFlagIcon', () => ({ CountryFlagIcon: () => null }))

import { ProfileSelectorInline } from './ProfileSelectorInline'
import { applyTerminalTunStatus, useAppStore } from '../store'

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: Error) => void
  const promise = new Promise<T>((ok, fail) => { resolve = ok; reject = fail })
  return { promise, resolve, reject }
}

const profiles = ['Sweden', 'Norway', 'Netherlands'].map(name => ({
  id: name, name, protocol: 'vless', server: 'fixture.example', port: 443
}))
let activeId: string

beforeEach(() => {
  vi.spyOn(window, 'scrollTo').mockImplementation(() => undefined)
  activeId = 'Sweden'
  useAppStore.setState({ mode: 'hard', tunRunning: true, serverSwitchingName: null,
    connectionBusy: null, connectionCancelling: false, restartingProgress: null, logs: [],
    settings: { ...useAppStore.getState().settings, connectionMode: 'directVpn' } })
  Object.assign(window, { electronAPI: {
    serversList: vi.fn().mockResolvedValue(profiles),
    serversGetActive: vi.fn(async () => ({ activeId })),
    serversSelect: vi.fn().mockResolvedValue(undefined),
    logRenderer: vi.fn().mockResolvedValue({ success: true })
  } })
})
afterEach(() => { cleanup(); vi.restoreAllMocks() })

async function select(name: string) {
  const picker = await screen.findByRole('button', { name: /Текущий профиль/ })
  fireEvent.click(picker)
  fireEvent.click(await screen.findByRole('button', { name: new RegExp(`^${name}`) }))
}

describe('inline picker cancellation', () => {
  it('holds ownership across terminal stop/remount, releases it after backend cleanup and then selects offline (AT-00-008)', async () => {
    const pending = deferred<void | { cancelled: true }>()
    vi.mocked(window.electronAPI.serversSelect).mockReturnValueOnce(pending.promise)
    const view = render(<ProfileSelectorInline />)
    await select('Norway')
    expect(window.electronAPI.serversSelect).toHaveBeenCalledExactlyOnceWith('Norway')
    expect(useAppStore.getState().serverSwitchingName).toBe('Norway')
    act(() => {
      useAppStore.getState().setConnectionCancelling(true)
      applyTerminalTunStatus('stopped')
    })
    view.unmount()
    render(<ProfileSelectorInline />)
    await select('Netherlands')
    expect(window.electronAPI.serversSelect).toHaveBeenCalledTimes(1)
    expect(useAppStore.getState().connectionCancelling).toBe(true)
    activeId = 'Norway'
    act(() => useAppStore.getState().acknowledgeServerSwitchCancellation())
    await act(async () => pending.resolve({ cancelled: true }))
    expect(useAppStore.getState().serverSwitchingName).toBeNull()
    expect(useAppStore.getState().connectionCancelling).toBe(false)
    expect(useAppStore.getState().connectionBusy).toBeNull()
    expect(useAppStore.getState().tunRunning).toBe(false)
    expect(useAppStore.getState().logs.some(log => log.level === 'error')).toBe(false)
    expect(useAppStore.getState().logs.some(log => log.message === 'Сервер выбран: Norway')).toBe(false)
    await waitFor(() => expect(screen.getByRole('button', { name: /Текущий профиль/ })).toHaveTextContent('Norway'))
    await select('Netherlands')
    expect(window.electronAPI.serversSelect).toHaveBeenCalledTimes(2)
    expect(useAppStore.getState().serverSwitchingName).toBeNull()
  })

  it.each(['connecting', 'disconnecting'] as const)('rejects selection during %s (AT-00-007)', async busy => {
    useAppStore.setState({ connectionBusy: busy })
    render(<ProfileSelectorInline />)
    await select('Norway')
    expect(window.electronAPI.serversSelect).not.toHaveBeenCalled()
  })

  it('logs real failures and releases selection ownership (AT-00-004)', async () => {
    vi.mocked(window.electronAPI.serversSelect).mockRejectedValue(new Error('Remote unavailable'))
    render(<ProfileSelectorInline />)
    await select('Norway')
    await waitFor(() => expect(useAppStore.getState().serverSwitchingName).toBeNull())
    expect(useAppStore.getState().logs.some(log => log.level === 'error' && log.message.includes('Remote unavailable'))).toBe(true)
  })
})
