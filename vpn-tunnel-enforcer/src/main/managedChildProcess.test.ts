import { describe, it, expect, vi, beforeEach } from 'vitest'
import { cleanupManagedChildPidFile } from './managedChildProcess'
import * as fsPromises from 'fs/promises'

vi.mock('fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof fsPromises>()
  const readFile = vi.fn()
  const rm = vi.fn()
  return {
    ...actual,
    default: { ...actual, readFile, rm },
    readFile,
    rm
  }
})

describe('cleanupManagedChildPidFile', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('leaves PID file untouched and returns false when entry belongs to another owner', async () => {
    const mockReadFile = vi.mocked(fsPromises.readFile)
    const mockRm = vi.mocked(fsPromises.rm)
    const logSpy = vi.fn()

    mockReadFile.mockResolvedValue(JSON.stringify({
      pid: 1234,
      owner: 'other-app-instance',
      role: 'sidecar',
      startedAt: Date.now()
    }))

    const result = await cleanupManagedChildPidFile('/path/to/child.pid', 'my-owner', logSpy)

    expect(result).toBe(false)
    // Must NOT delete the other owner's pid file!
    expect(mockRm).not.toHaveBeenCalled()
    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining('belongs to different owner'),
      expect.objectContaining({ expectedOwner: 'my-owner', actualOwner: 'other-app-instance' })
    )
  })

  it('removes corrupted/unparseable PID file and returns true', async () => {
    const mockReadFile = vi.mocked(fsPromises.readFile)
    const mockRm = vi.mocked(fsPromises.rm)

    mockReadFile.mockResolvedValue('not-valid-json{{{')
    mockRm.mockResolvedValue(undefined as any)

    const result = await cleanupManagedChildPidFile('/path/to/child.pid', 'my-owner')

    expect(result).toBe(true)
    expect(mockRm).toHaveBeenCalledWith('/path/to/child.pid', { force: true })
  })

  it('returns true when PID file does not exist', async () => {
    const mockReadFile = vi.mocked(fsPromises.readFile)
    const mockRm = vi.mocked(fsPromises.rm)

    mockReadFile.mockRejectedValue(new Error('ENOENT'))

    const result = await cleanupManagedChildPidFile('/path/to/child.pid', 'my-owner')

    expect(result).toBe(true)
    expect(mockRm).not.toHaveBeenCalled()
  })
})
