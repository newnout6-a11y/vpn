// AT-03-003/007/012: real persistent worker, fixed registry reads only; no OS writes.
import { describe, expect, it, vi } from 'vitest'
vi.mock('./admin', () => ({ isProcessElevated: vi.fn() }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
import { RecoveryPsWorker } from './recoveryPsWorker'

describe('persistent DNS policy reader native proof', () => {
  it.skipIf(process.platform !== 'win32')('returns fresh routing DNS frames without full adapter baselines (AT-03-006)', async () => {
    const worker = new RecoveryPsWorker(process.env.ProgramData || 'C:\\ProgramData')
    try {
      await worker.execute({ op: 'warmup' })
      for (let read = 0; read < 2; read++) {
        const value = await worker.execute({ op: 'inspect-physical-dns' }, 20000)
        const parsed = value.trim() ? JSON.parse(value) : []
        const rows = Array.isArray(parsed) ? parsed : [parsed]
        for (const row of rows) {
          expect(Number.isInteger(row.ifIndex)).toBe(true)
          expect(typeof row.alias).toBe('string')
          expect(Array.isArray(row.ipv4Dns)).toBe(true)
          expect(Object.keys(row).sort()).toEqual(['alias', 'ifIndex', 'ipv4Dns'])
        }
        expect(JSON.parse(await worker.execute({ op: 'inspect-dns-policy' }))).toHaveLength(2)
      }
    } finally { await worker.stop() }
    expect(worker.hasExited).toBe(true)
  }, 30000)
  it.skipIf(process.platform !== 'win32')('keeps frames synchronized after a fresh ACL refusal (AT-01-009/AT-03-012)', async () => {
    const worker = new RecoveryPsWorker('C:\\VPNTE-invalid-programdata')
    try {
      for (let read = 0; read < 2; read++) {
        const value = await worker.execute({ op: 'inspect-runtime-acl', runtimeDir: 'C:\\VPNTE-never-created-fixture' })
        expect(value).toMatch(/^VPNTE_RUNTIME_FAILURE:/)
        expect(JSON.parse(value.slice('VPNTE_RUNTIME_FAILURE:'.length))).toMatchObject({ operation: 'known-folder', reason: 'RuntimeProgramDataMismatch' })
        expect(JSON.parse(await worker.execute({ op: 'inspect-dns-policy' }))).toHaveLength(2)
      }
    } finally { await worker.stop() }
    expect(worker.hasExited).toBe(true)
  }, 25000)
  it.skipIf(process.platform !== 'win32')('returns complete fresh frames and confirms worker exit', async () => {
    const worker = new RecoveryPsWorker(process.env.ProgramData || 'C:\\ProgramData')
    try {
      for (let read = 0; read < 3; read++) {
        const rows = JSON.parse(await worker.execute({ op: 'inspect-dns-policy' }))
        expect(rows).toHaveLength(2)
        expect(rows.map((row: { tag: string }) => row.tag)).toEqual(['smartNameResolution', 'parallelAandAAAA'])
        for (const row of rows) {
          expect(Object.keys(row).sort()).toEqual(['data', 'exists', 'tag', 'type'])
          expect(typeof row.exists).toBe('boolean')
          if (row.exists) {
            expect(row.type).toBe('REG_DWORD')
            expect(row.data).toMatch(/^0x[0-9a-f]{1,8}$/i)
          } else expect(row).toMatchObject({ type: null, data: null })
        }
      }
      expect(worker.hasExited).toBe(false)
    } finally { await worker.stop() }
    expect(worker.hasExited).toBe(true)
    await expect(worker.execute({ op: 'inspect-dns-policy' })).rejects.toMatchObject({ code: 'exited' })
  }, 25000)
})
