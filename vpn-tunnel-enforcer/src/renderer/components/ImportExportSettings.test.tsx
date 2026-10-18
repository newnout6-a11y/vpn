// AT-01-008, F-144, AC-SET-CFG-001: accessible separate export actions.
import { fireEvent, render, screen, waitFor, cleanup } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ipcError, type IpcErrorCategory } from '../../shared/ipc-result'
import { ImportExportSettings } from './ImportExportSettings'
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key, i18n: { language: 'ru' } }) }))
afterEach(cleanup)

const remote = (category: IpcErrorCategory) => ({ name: 'IpcRemoteError', ...ipcError(category) })
describe('configuration export actions', () => {
  it('selects masking by default and secrets only via the separate action', async () => {
    const configExport = vi.fn(async () => { throw remote('cancelled') })
    Object.assign(window, { electronAPI: { configExport } })
    render(<ImportExportSettings />)
    fireEvent.click(screen.getByRole('button', { name: 'settings.exportSettings' }))
    await waitFor(() => expect(configExport).toHaveBeenCalledWith('redacted'))
    await waitFor(() => expect((screen.getByRole('button', { name: 'settings.exportSettingsWithSecrets' }) as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(screen.getByRole('button', { name: 'settings.exportSettingsWithSecrets' }))
    await waitFor(() => expect(configExport).toHaveBeenCalledWith('secrets'))
  })
  it('disables both export actions while the native operation is pending', async () => {
    let finish!: (value: { success: true; path: string }) => void
    Object.assign(window, { electronAPI: { configExport: () => new Promise(resolve => { finish = resolve }) } })
    render(<ImportExportSettings />)
    fireEvent.click(screen.getByRole('button', { name: 'settings.exportSettingsWithSecrets' }))
    expect((screen.getByRole('button', { name: 'settings.exportSettings' }) as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByRole('button', { name: 'settings.exportSettingsWithSecrets' }) as HTMLButtonElement).disabled).toBe(true)
    finish({ success: true, path: 'selected.json' })
    expect(await screen.findByText('settings.exportSuccess')).toBeTruthy()
    expect((screen.getByRole('button', { name: 'settings.exportSettingsWithSecrets' }) as HTMLButtonElement).disabled).toBe(false)
  })
})


// AT-00-004, F-074: canonical rejections and successful config flows in the real component.
describe('configuration error and success UI', () => {
  const clickImport = () => fireEvent.click(screen.getByRole('button', { name: 'settings.importSettings' }))
  const validation = { success: true, sections: ['notifications'], conflicts: [] }
  it.each(['export', 'browse', 'import', 'apply'] as const)('shows canonical permission errors from %s', async stage => {
    const fail = async () => { throw remote('permission') }
    Object.assign(window, { electronAPI: {
      configExport: fail,
      configBrowseImport: stage === 'browse' ? fail : async () => 'selected.json',
      configImport: stage === 'import' ? fail : async () => validation,
      configImportApply: fail
    } })
    render(<ImportExportSettings />)
    if (stage === 'export') fireEvent.click(screen.getByRole('button', { name: 'settings.exportSettings' }))
    else {
      clickImport()
      if (stage === 'apply') fireEvent.click(await screen.findByRole('button', { name: 'settings.applyImport' }))
    }
    expect(await screen.findByText(ipcError('permission').message)).toBeTruthy()
    expect(screen.queryByText('settings.exportSuccess')).toBeNull()
    expect(screen.queryByText('settings.importSuccess')).toBeNull()
  })
  it.each([
    new Error('FAKE-SECRET at C:\\private\\config.json'),
    { ...remote('permission'), message: 'FAKE-SECRET at C:\\private\\config.json' }
  ])('replaces raw or forged errors with a generic localized message', async error => {
    Object.assign(window, { electronAPI: { configExport: async () => { throw error } } })
    render(<ImportExportSettings />)
    fireEvent.click(screen.getByRole('button', { name: 'settings.exportSettings' }))
    expect(await screen.findByText(ipcError('internal').message)).toBeTruthy()
    expect(document.body.textContent).not.toContain('FAKE-SECRET')
  })
  it('keeps native save and browse cancellation silent without success', async () => {
    const configExport = vi.fn(async () => { throw remote('cancelled') })
    const configImport = vi.fn()
    Object.assign(window, { electronAPI: { configExport, configBrowseImport: async () => null, configImport } })
    render(<ImportExportSettings />)
    fireEvent.click(screen.getByRole('button', { name: 'settings.exportSettings' }))
    await waitFor(() => expect((screen.getByRole('button', { name: 'settings.exportSettings' }) as HTMLButtonElement).disabled).toBe(false))
    clickImport()
    await waitFor(() => expect((screen.getByRole('button', { name: 'settings.importSettings' }) as HTMLButtonElement).disabled).toBe(false))
    expect(configImport).not.toHaveBeenCalled()
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.queryByText('settings.exportSuccess')).toBeNull()
    expect(screen.queryByText('settings.importSuccess')).toBeNull()
  })
  it('applies the validated selection and renders success only after resolution', async () => {
    const configImportApply = vi.fn(async () => ({ success: true }))
    Object.assign(window, { electronAPI: {
      configBrowseImport: async () => 'selected.json', configImport: async () => validation, configImportApply
    } })
    render(<ImportExportSettings />)
    clickImport()
    fireEvent.click(await screen.findByRole('button', { name: 'settings.applyImport' }))
    expect(await screen.findByText('settings.importSuccess')).toBeTruthy()
    expect(configImportApply).toHaveBeenCalledWith('selected.json', ['notifications'], 'replace')
    expect(screen.queryByText('settings.importSections')).toBeNull()
  })
})
