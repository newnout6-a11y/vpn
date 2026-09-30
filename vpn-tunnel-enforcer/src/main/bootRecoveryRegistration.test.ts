import { join } from 'path'
import { describe, expect, it, vi } from 'vitest'

vi.mock('electron', () => ({
  app: {
    isPackaged: true,
    getPath: vi.fn(() => '/tmp'),
    setLoginItemSettings: vi.fn()
  },
  safeStorage: {
    isEncryptionAvailable: vi.fn(() => true),
    encryptString: vi.fn((value: string) => Buffer.from(value)),
    decryptString: vi.fn((value: Buffer) => value.toString())
  }
}))
vi.mock('./admin', () => ({ execElevated: vi.fn() }))
vi.mock('./domainEnrichment', () => ({ domainEnrichmentService: { setEnabled: vi.fn() } }))

import { buildBootRecoveryTaskCommand, getBootRecoveryScriptPath } from './settings'

describe('boot recovery registration (AT-03-002)', () => {
  it('uses the actual packaged extraResources path', () => {
    const previous = process.resourcesPath
    Object.defineProperty(process, 'resourcesPath', { configurable: true, value: 'C:\\Program Files\\VPNTE\\resources' })
    expect(getBootRecoveryScriptPath(true)).toBe(join('C:\\Program Files\\VPNTE\\resources', 'vpnte-recover.ps1'))
    Object.defineProperty(process, 'resourcesPath', { configurable: true, value: previous })
  })

  it('encodes the script path so schtasks /TR has no nested path quotes', () => {
    const command = buildBootRecoveryTaskCommand("C:\\Program Files\\VPNTE\\resources\\vpnte-recover.ps1")
    expect(command).toContain('-EncodedCommand')
    expect(command).not.toContain('-File "C:\\Program Files')
    const decoded = Buffer.from(command.split(' ').at(-1)!, 'base64').toString('utf16le')
    expect(decoded).toContain('-RegisterTask')
    expect(decoded).toContain("C:\\Program Files\\VPNTE\\resources\\vpnte-recover.ps1")
  })
})