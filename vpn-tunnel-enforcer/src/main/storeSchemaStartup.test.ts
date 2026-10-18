// AT-00-006 / F-074: refusal must be visible even during static main imports.
import { afterEach, describe, expect, it, vi } from 'vitest'
const native = vi.hoisted(() => ({ isReady: vi.fn(() => false), exit: vi.fn(), showErrorBox: vi.fn() }))
vi.mock('electron', () => ({ app: native, dialog: native }))
import { refuseIncompatibleStoreStartup } from './storeSchemaStartup'
import { StoreSchemaError } from './storeSchema'

afterEach(() => { vi.restoreAllMocks(); vi.clearAllMocks(); native.isReady.mockReturnValue(false) })
describe('early storage refusal', () => {
  it.each(['STORE_SCHEMA_FUTURE', 'STORE_SCHEMA_INVALID', 'STORE_SCHEMA_UNREGISTERED'] as const)('reports %s and exits before ready', code => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {})
    const error = new StoreSchemaError(code)
    error.message = 'must-not-log C:\\private\\config.json token=secret'
    refuseIncompatibleStoreStartup(error)
    expect(native.showErrorBox).toHaveBeenCalledExactlyOnceWith('VPNTE: запуск отменён', expect.stringContaining('Несовместимый файл не изменён'))
    expect(log).toHaveBeenCalledExactlyOnceWith('VPNTE storage startup refused', { code })
    expect(JSON.stringify([log.mock.calls, native.showErrorBox.mock.calls])).not.toContain('must-not-log')
    expect(native.exit).toHaveBeenCalledExactlyOnceWith(1)
    expect(native.showErrorBox.mock.invocationCallOrder[0]).toBeLessThan(native.exit.mock.invocationCallOrder[0])
  })
  it('still exits if the native refusal box fails', () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    native.showErrorBox.mockImplementationOnce(() => { throw new Error('dialog unavailable') })
    expect(() => refuseIncompatibleStoreStartup(new StoreSchemaError('STORE_SCHEMA_FUTURE'))).toThrow('dialog unavailable')
    expect(native.exit).toHaveBeenCalledExactlyOnceWith(1)
  })
  it('leaves runtime errors to the existing IPC/startup boundary', () => {
    const log = vi.spyOn(console, 'error').mockImplementation(() => {})
    native.isReady.mockReturnValue(true)
    refuseIncompatibleStoreStartup(new StoreSchemaError('STORE_SCHEMA_FUTURE'))
    native.isReady.mockReturnValue(false)
    refuseIncompatibleStoreStartup(new Error('unrelated error'))
    expect(log).not.toHaveBeenCalled()
    expect(native.showErrorBox).not.toHaveBeenCalled()
    expect(native.exit).not.toHaveBeenCalled()
  })
})
