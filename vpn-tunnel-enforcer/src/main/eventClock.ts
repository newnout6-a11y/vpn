import { randomBytes } from 'node:crypto'

// Ordering and elapsed duration only. Keep calendar dates on Date.now() so
// history filters and human-readable timestamps follow Windows/NTP corrections.
// Scope is this main process, not different processes or app restarts.
const originNs = process.hrtime.bigint()
export const eventClockId = 'clock_' + randomBytes(12).toString('hex')

export function monotonicTimeMs(): number {
  return Number((process.hrtime.bigint() - originNs) / 1_000_000n)
}
