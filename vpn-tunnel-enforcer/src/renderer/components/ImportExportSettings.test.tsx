// AT-01-008, F-144, AC-SET-CFG-001: accessible separate export actions.
import { fireEvent, render, screen, waitFor, cleanup, act } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ipcError, type IpcErrorCategory } from '../../shared/ipc-result'
import { ImportExportSettings } from './ImportExportSettings'
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key, i18n: { language: 'ru' } }) }))
afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks() })

const remote = (category: IpcErrorCategory) => ({ name: 'IpcRemoteError', ...ipcError(category) })
const setApi = (api: Record<string, unknown>) => Object.assign(window, {
  electronAPI: { configCancel: vi.fn(async () => false), ...api }
})
describe('configuration export actions', () => {
  it('cancels its held browse on unmount and never starts late validation', async () => {
    let release!: (path: string) => void
    const configBrowseImport = vi.fn(() => new Promise<string>(done => { release = done }))
    const configCancel = vi.fn(async () => true), configImport = vi.fn()
    setApi({ configBrowseImport, configCancel, configImport })
    const view = render(<ImportExportSettings />)
    fireEvent.click(screen.getByRole('button', { name: 'settings.importSettings' }))
    view.unmount()
    expect(configCancel).toHaveBeenCalledWith(expect.stringMatching(/^[0-9a-f-]{36}$/))
    await act(async () => { release('selected.json') })
    expect(configImport).not.toHaveBeenCalled()
  })

  it('cancels a held export on unmount without scheduling a late success timer', async () => {
    let release!: () => void
    const configExport = vi.fn(() => new Promise<void>(done => { release = done }))
    const configCancel = vi.fn(async () => true)
    setApi({ configExport, configCancel })
    const view = render(<ImportExportSettings />)
    fireEvent.click(screen.getByRole('button', { name: 'settings.exportSettings' }))
    view.unmount()
    expect(configCancel).toHaveBeenCalledWith(expect.any(String))
    const timers = vi.spyOn(globalThis, 'setTimeout')
    await act(async () => { release() })
    expect(timers.mock.calls.some(call => call[1] === 3000)).toBe(false)
  })

  it('selects masking by default and secrets only via the separate action', async () => {
    const configExport = vi.fn(async () => { throw remote('cancelled') })
    setApi({ configExport })
    render(<ImportExportSettings />)
    fireEvent.click(screen.getByRole('button', { name: 'settings.exportSettings' }))
    await waitFor(() => expect(configExport).toHaveBeenCalledWith('redacted', expect.any(String)))
    await waitFor(() => expect((screen.getByRole('button', { name: 'settings.exportSettingsWithSecrets' }) as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(screen.getByRole('button', { name: 'settings.exportSettingsWithSecrets' }))
    await waitFor(() => expect(configExport).toHaveBeenCalledWith('secrets', expect.any(String)))
  })
  it('disables both export actions while the native operation is pending', async () => {
    let finish!: (value: { success: true; path: string }) => void
    setApi({ configExport: () => new Promise(resolve => { finish = resolve }) })
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
  it('keeps failed import choices visible but requires a fresh native selection before retry', async () => {
    const configBrowseImport = vi.fn(async (_requestId: string) => 'selected.json')
    const configImportApply = vi.fn().mockRejectedValueOnce(remote('permission')).mockResolvedValue({ success: true })
    setApi({ configBrowseImport, configImport: async () => validation, configImportApply })
    render(<ImportExportSettings />)
    clickImport()
    fireEvent.click(await screen.findByRole('button', { name: 'settings.applyImport' }))
    expect(await screen.findByText(ipcError('permission').message)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'common.ok' }))
    expect(screen.getByText('settings.importSections')).toBeTruthy()
    const consumed = screen.getByRole('button', { name: 'settings.applyImport' }) as HTMLButtonElement
    expect(consumed.disabled).toBe(true)
    fireEvent.click(consumed)
    expect(configImportApply).toHaveBeenCalledTimes(1)
    clickImport()
    await waitFor(() => expect(configBrowseImport).toHaveBeenCalledTimes(2))
    await waitFor(() => expect((screen.getByRole('button', { name: 'settings.applyImport' }) as HTMLButtonElement).disabled).toBe(false))
    expect(configBrowseImport.mock.calls[1][0]).not.toBe(configBrowseImport.mock.calls[0][0])
    fireEvent.click(screen.getByRole('button', { name: 'settings.applyImport' }))
    expect(await screen.findByText('settings.importSuccess')).toBeTruthy()
  })
  // AT-00-003/008: route unmount across every import workflow boundary.
  it.each(['validate', 'idle', 'apply'] as const)('revokes its %s workflow on unmount without late UI', async stage => {
    let release!: (value: unknown) => void
    const held = () => new Promise(done => { release = done })
    const configCancel = vi.fn(async () => true)
    const configBrowseImport = vi.fn(async (_requestId: string) => 'selected.json')
    const configImport = vi.fn(stage === 'validate' ? held : async () => validation)
    const configImportApply = vi.fn(held)
    setApi({ configCancel, configBrowseImport, configImport, configImportApply })
    const view = render(<ImportExportSettings />)
    clickImport()
    if (stage === 'validate') await waitFor(() => expect(configImport).toHaveBeenCalled())
    else {
      const apply = await screen.findByRole('button', { name: 'settings.applyImport' })
      if (stage === 'apply') fireEvent.click(apply)
    }
    const requestId = configBrowseImport.mock.calls[0][0]
    expect(configImport).toHaveBeenCalledWith('selected.json', requestId)
    view.unmount()
    expect(configCancel).toHaveBeenCalledExactlyOnceWith(requestId)
    const timers = vi.spyOn(globalThis, 'setTimeout')
    if (stage !== 'idle') await act(async () => { release(stage === 'validate' ? validation : { success: true }) })
    expect(timers.mock.calls.some(call => call[1] === 3000)).toBe(false)
    if (stage !== 'apply') expect(configImportApply).not.toHaveBeenCalled()
  })

  it('revokes a dismissed idle selection and removes success timers on unmount', async () => {
    const configCancel = vi.fn(async () => true)
    const configBrowseImport = vi.fn(async (_requestId: string) => 'selected.json')
    setApi({ configCancel, configBrowseImport, configImport: async () => validation, configExport: async () => ({ success: true }) })
    const view = render(<ImportExportSettings />)
    clickImport()
    fireEvent.click(await screen.findByRole('button', { name: 'common.cancel' }))
    expect(configCancel).toHaveBeenCalledExactlyOnceWith(configBrowseImport.mock.calls[0][0])
    vi.useFakeTimers()
    await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'settings.exportSettings' })) })
    expect(screen.getByText('settings.exportSuccess')).toBeTruthy()
    expect(vi.getTimerCount()).toBeGreaterThan(0)
    view.unmount()
    expect(vi.getTimerCount()).toBe(0)
    expect(configCancel).toHaveBeenCalledTimes(1)
  })
  it.each(['export', 'browse', 'import', 'apply'] as const)('shows canonical permission errors from %s', async stage => {
    const fail = async () => { throw remote('permission') }
    setApi({
      configExport: fail,
      configBrowseImport: stage === 'browse' ? fail : async () => 'selected.json',
      configImport: stage === 'import' ? fail : async () => validation,
      configImportApply: fail
    })
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
    setApi({ configExport: async () => { throw error } })
    render(<ImportExportSettings />)
    fireEvent.click(screen.getByRole('button', { name: 'settings.exportSettings' }))
    expect(await screen.findByText(ipcError('internal').message)).toBeTruthy()
    expect(document.body.textContent).not.toContain('FAKE-SECRET')
  })
  it('keeps native save and browse cancellation silent without success', async () => {
    const configExport = vi.fn(async () => { throw remote('cancelled') })
    const configImport = vi.fn()
    setApi({ configExport, configBrowseImport: async () => null, configImport })
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
    setApi({
      configBrowseImport: async () => 'selected.json', configImport: async () => validation, configImportApply
    })
    render(<ImportExportSettings />)
    clickImport()
    fireEvent.click(await screen.findByRole('button', { name: 'settings.applyImport' }))
    expect(await screen.findByText('settings.importSuccess')).toBeTruthy()
    expect(configImportApply).toHaveBeenCalledWith('selected.json', ['notifications'], 'replace', expect.any(String))
    expect(screen.queryByText('settings.importSections')).toBeNull()
  })
})
