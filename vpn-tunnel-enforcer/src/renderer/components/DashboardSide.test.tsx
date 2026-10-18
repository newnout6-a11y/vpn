import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { ipcError, IpcRemoteError, serializeIpcError } from '../../shared/ipc-result'
import type { ElectronAPI } from '../../shared/electron-api'

vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string, fallback?: string) => fallback ?? key }) }))
vi.mock('./CountryFlagIcon', () => ({ CountryFlagIcon: () => null }))
import { DashboardSide } from './DashboardSide'
import { useAppStore } from '../store'

beforeEach(() => {
  useAppStore.setState({ logs: [], connectionBusy: null, serverSwitchingName: null, tunRunning: false })
  window.electronAPI = {
    serversList: vi.fn().mockResolvedValue([{ id: 'one', name: 'Fixture profile', protocol: 'vless', server: 'example.test', port: 443, ping: null }]),
    serversGetActive: vi.fn().mockResolvedValue({ profile: null, activeId: null }),
    serversSelect: vi.fn(), trafficHistoryList: vi.fn().mockResolvedValue([]), logRenderer: vi.fn().mockResolvedValue(undefined)
  } as unknown as ElectronAPI
})
afterEach(() => cleanup())

// AT-00-004: the real server picker must not display a rejection record as [object Object].
it.each([serializeIpcError(new IpcRemoteError(ipcError('permission')), 'en'), new Error('Permission denied')])('keeps server-selection errors readable', async error => {
  vi.mocked(window.electronAPI.serversSelect).mockRejectedValue(error)
  render(<DashboardSide />)
  fireEvent.click(await screen.findByText('Fixture profile'))
  await waitFor(() => expect(useAppStore.getState().logs.some(log => log.message.includes('Permission denied'))).toBe(true))
  expect(useAppStore.getState().logs.some(log => log.message.includes('[object Object]'))).toBe(false)
})
