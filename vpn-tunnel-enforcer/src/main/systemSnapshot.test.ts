import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const source = readFileSync(join(process.cwd(), 'src', 'main', 'systemSnapshot.ts'), 'utf-8')

describe('system snapshot scheduling', () => {
  it('rate-limits periodic collection and serializes it with explicit captures', () => {
    expect(source).toContain('export const PERIODIC_SNAPSHOT_INTERVAL_MS = 5 * 60_000')
    expect(source).toContain('Math.max(PERIODIC_SNAPSHOT_INTERVAL_MS, Math.floor(intervalMs))')
    expect(source).toContain("if (reason === 'periodic' && pendingSnapshotCaptures > 0)")
    expect(source).toContain('const capture = snapshotCaptureQueue.then(() => captureSnapshotNow(reason))')
    expect(source).toContain("'skipped periodic snapshot while capture is in progress'")
  })
})
