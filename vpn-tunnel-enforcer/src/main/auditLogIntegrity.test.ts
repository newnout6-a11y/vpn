// AT-00-010, F-143: bounded scan and exact JSONL record accounting.
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { mkdtemp, open, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { inspectAuditLog } from './auditLogIntegrity'

let directory: string
beforeEach(async () => { directory = await mkdtemp(join(process.cwd(), '.tmp', 'audit-scan-')) })
afterEach(async () => { await rm(directory, { recursive: true, force: true }) })
describe('bounded audit log inspection', () => {
  it('distinguishes a missing file from retained corruption', async () => {
    expect(await inspectAuditLog(join(directory, 'missing'))).toEqual({ invalidRows: 0, needsSeparator: false, complete: true })
  })
  it('counts one oversized row once and continues checking subsequent rows', async () => {
    const path = join(directory, 'history')
    await writeFile(path, Buffer.concat([Buffer.alloc(600_000, 120), Buffer.from('\n{}\n')]))
    expect(await inspectAuditLog(path)).toEqual({ invalidRows: 2, needsSeparator: false, complete: true })
  })
  it('reports an incomplete scan at the byte limit and checks the actual final byte', async () => {
    const path = join(directory, 'history'), handle = await open(path, 'w')
    try {
      await handle.truncate(34 * 1024 * 1024)
      await handle.write(Buffer.from('\n'), 0, 1, 34 * 1024 * 1024 - 1)
    } finally { await handle.close() }
    expect(await inspectAuditLog(path)).toEqual({ invalidRows: 0, needsSeparator: false, complete: false })
  })
})
