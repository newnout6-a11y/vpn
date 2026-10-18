// Calendar time anchored to a monotonic process clock. NTP/manual wall-clock
// changes must not reorder audit events or make a live session end before start.
// Scope is this main process; this is not a cross-process synchronization clock.
const epochMs = Date.now()
const originNs = process.hrtime.bigint()

export function eventTimestamp(): number {
  return epochMs + Number((process.hrtime.bigint() - originNs) / 1_000_000n)
}
