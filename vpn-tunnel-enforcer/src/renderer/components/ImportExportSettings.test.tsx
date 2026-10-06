// AT-01-008, F-144, AC-SET-CFG-001: accessible separate export actions.
import { fireEvent, render, screen, waitFor, cleanup } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ImportExportSettings } from './ImportExportSettings'
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key }) }))
afterEach(cleanup)
describe('configuration export actions', () => {
  it('selects masking by default and secrets only via the separate action', async () => {
    const configExport = vi.fn(async () => ({ success: false, error: 'Export cancelled' }))
    Object.assign(window, { electronAPI: { configExport } })
    render(<ImportExportSettings />)
    fireEvent.click(screen.getByRole('button', { name: 'settings.exportSettings' }))
    await waitFor(() => expect(configExport).toHaveBeenCalledWith('redacted'))
    await waitFor(() => expect((screen.getByRole('button', { name: 'settings.exportSettingsWithSecrets' }) as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(screen.getByRole('button', { name: 'settings.exportSettingsWithSecrets' }))
    await waitFor(() => expect(configExport).toHaveBeenCalledWith('secrets'))
  })
  it('disables both export actions while the native operation is pending', async () => {
    let finish!: (value: { success: boolean }) => void
    Object.assign(window, { electronAPI: { configExport: () => new Promise(resolve => { finish = resolve }) } })
    render(<ImportExportSettings />)
    fireEvent.click(screen.getByRole('button', { name: 'settings.exportSettingsWithSecrets' }))
    expect((screen.getByRole('button', { name: 'settings.exportSettings' }) as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByRole('button', { name: 'settings.exportSettingsWithSecrets' }) as HTMLButtonElement).disabled).toBe(true)
    finish({ success: false })
    await waitFor(() => expect((screen.getByRole('button', { name: 'settings.exportSettings' }) as HTMLButtonElement).disabled).toBe(false))
  })
})
