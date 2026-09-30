import { afterEach, describe, expect, it, vi } from 'vitest'
import { confirmSecretExport } from './secretClipboard'

describe('secret export warning (AT-01-008)', () => {
  afterEach(() => vi.restoreAllMocks())
  it('warns about timeout and clipboard history, propagating cancellation', () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    expect(confirmSecretExport('clipboard')).toBe(false)
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining('60 секунд'))
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining('облачные копии не удаляются'))
  })
  it('warns that file export is plaintext and propagates approval', () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    expect(confirmSecretExport('file')).toBe(true)
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining('обычный текстовый файл'))
  })
})
