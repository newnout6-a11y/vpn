import '@testing-library/jest-dom/vitest'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { RotationSettings } from './RotationSettings'
import type { RotationConfig, ServerProfile } from '../../shared/ipc-types'

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (k: string) => k,
    i18n: { language: 'ru', changeLanguage: vi.fn() }
  })
}))

describe('<RotationSettings />', () => {
  const mockConfig: RotationConfig = {
    enabled: true,
    intervalMinutes: 15,
    order: 'sequential',
    profileIds: ['prof-1', 'prof-2'],
    currentIndex: 0,
    nextRotationAt: Date.now() + 600000
  }

  const mockProfiles: ServerProfile[] = [
    { id: 'prof-1', name: 'Server A', protocol: 'vless', status: 'online', server: '1.1.1.1', port: 443 },
    { id: 'prof-2', name: 'Server B', protocol: 'shadowsocks', status: 'offline', server: '2.2.2.2', port: 8443 }
  ]

  beforeEach(() => {
    ;(globalThis as any).window = (globalThis as any).window || {}
    ;(globalThis as any).window.electronAPI = {
      rotationGetConfig: vi.fn().mockResolvedValue(mockConfig),
      rotationSetConfig: vi.fn().mockImplementation(async (partial) => ({ ...mockConfig, ...partial })),
      rotationRotateNow: vi.fn().mockResolvedValue({ success: true, profileId: 'prof-2' }),
      serversList: vi.fn().mockResolvedValue(mockProfiles)
    }
  })

  afterEach(() => {
    cleanup()
    vi.clearAllMocks()
  })

  it('renders config and profiles correctly when IPC succeeds', async () => {
    render(<RotationSettings />)

    await waitFor(() => {
      expect(screen.getAllByText('Server A').length).toBeGreaterThan(0)
      expect(screen.getByText('Server B')).toBeInTheDocument()
    })

    expect(screen.getByDisplayValue('15')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('displays error banner and reverts interval input when rotationSetConfig fails', async () => {
    const api = (globalThis as any).window.electronAPI
    api.rotationSetConfig.mockRejectedValueOnce(new Error('IPC permission denied'))

    render(<RotationSettings />)

    await waitFor(() => {
      expect(screen.getByDisplayValue('15')).toBeInTheDocument()
    })

    const intervalInput = screen.getByDisplayValue('15')
    fireEvent.change(intervalInput, { target: { value: '45' } })
    fireEvent.blur(intervalInput)

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })

    expect(screen.getByText('IPC permission denied')).toBeInTheDocument()
    // Reverts back to config.intervalMinutes (15) on IPC failure
    expect(screen.getByDisplayValue('15')).toBeInTheDocument()
  })

  it('displays error alert when rotationRotateNow fails', async () => {
    const api = (globalThis as any).window.electronAPI
    api.rotationRotateNow.mockRejectedValueOnce(new Error('Rotator daemon unreachable'))

    render(<RotationSettings />)

    await waitFor(() => {
      expect(screen.getByText('settings.rotationRotateNow')).toBeInTheDocument()
    })

    const rotateBtn = screen.getByText('settings.rotationRotateNow')
    fireEvent.click(rotateBtn)

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })

    expect(screen.getByText('Rotator daemon unreachable')).toBeInTheDocument()

    // Can dismiss error
    const dismissBtn = screen.getByRole('button', { name: 'Dismiss error' })
    fireEvent.click(dismissBtn)

    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('displays error and retry button when initial fetch fails', async () => {
    const api = (globalThis as any).window.electronAPI
    api.rotationGetConfig.mockRejectedValueOnce(new Error('Config file corrupted'))

    render(<RotationSettings />)

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })

    expect(screen.getByText('Config file corrupted')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Повторить' })).toBeInTheDocument()

    // When clicking retry after IPC recovery
    api.rotationGetConfig.mockResolvedValueOnce(mockConfig)
    fireEvent.click(screen.getByRole('button', { name: 'Повторить' }))

    await waitFor(() => {
      expect(screen.getAllByText('Server A').length).toBeGreaterThan(0)
    })
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })
})

it('Audit: displays structured rotation failure returned by backend', async () => {
  const cfg = { enabled: true, intervalMinutes: 15, order: 'sequential', profileIds: ['p1','p2'], currentIndex: 0, nextRotationAt: null }
  ;(window as any).electronAPI = {
    rotationGetConfig: vi.fn().mockResolvedValue(cfg),
    rotationSetConfig: vi.fn().mockResolvedValue(cfg),
    rotationRotateNow: vi.fn().mockResolvedValue({ success: false, newProfile: 'p2' }),
    serversList: vi.fn().mockResolvedValue([{ id: 'p1', name: 'Server A', protocol: 'vless' }, { id: 'p2', name: 'Server B', protocol: 'vless' }])
  }
  render(<RotationSettings />)
  fireEvent.click(await screen.findByText('settings.rotationRotateNow'))
  expect(await screen.findByRole('alert')).toHaveTextContent('Не удалось переключить сервер')
  expect(window.electronAPI.rotationGetConfig).toHaveBeenCalledTimes(1)
  cleanup()
})
