// AT-00-005: diagnostic timings remain separate, anonymous and honest about ambiguity.
// Tool-level assertions cover timing analysis, not the full operation-ID acceptance test.
import { execFileSync, spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const script = join(process.cwd(), 'scripts/analyze-lifecycle-log.mjs')
const at = (ms: number) => new Date(Date.UTC(2026, 9, 1) + ms).toISOString()
const event = (ms: number, scope: string, message: string, details: unknown = {}) => ({ ts: at(ms), scope, message, details })
function run(events: unknown[], prefix = '') {
  return JSON.parse(execFileSync(process.execPath, [script], { input: prefix + events.map(item => typeof item === 'string' ? item : JSON.stringify(item)).join('\r\n'), encoding: 'utf8', windowsHide: true }))
}

describe('read-only lifecycle timing analysis (AT-00-005)', () => {
  it('reports IPC and parallel/background stages separately without counting double', () => {
    const r = run([
      event(0, 'ipc', 'start-direct-vpn started'),
      event(200, 'tun', 'start timing', { totalMs: 180, phaseDurations: {
        'adapter-lockdown': { durationMs: 80, startMs: 0, endMs: 80, parallel: true },
        'physical-dns-sources': { durationMs: 70, parallel: true },
        'physical-dns-sources-await': { durationMs: 15 },
        'tun-interface-metric-readback': { durationMs: 90, background: true },
        'firewall-kill-switch-await': { durationMs: 100, startMs: 80, endMs: 180 }
      } }),
      event(210, 'ipc', 'start-direct-vpn finished', { ms: 209, result: { success: true } })
    ])
    expect(r.ipc[0]).toMatchObject({ elapsedMs: 210, loggedMs: 209, pairing: 'unique-window' })
    expect(r.timings[0]).toMatchObject({ totalMs: 180, phases: { 'adapter-lockdown': { durationMs: 80, parallel: true }, 'tun-interface-metric-readback': { durationMs: 90, background: true } } })
    expect(r.summary[0]).toMatchObject({ samples: 1, medianMs: 209 })
    expect(r.timings[0].phases['physical-dns-sources']).toEqual({ durationMs: 70, parallel: true })
    expect(r.timings[0].phases['physical-dns-sources-await']).toEqual({ durationMs: 15 })
  })
  it('does not assign overlapping same-channel completions to specific starts', () => {
    const r = run([event(0, 'ipc', 'start-tun started'), event(10, 'ipc', 'start-tun started'), event(20, 'ipc', 'start-tun finished', { ms: 10 }), event(100, 'ipc', 'start-tun failed', { ms: 100 })])
    expect(r.ipc).toHaveLength(2)
    expect(r.ipc.every((item: any) => item.pairing === 'ambiguous' && item.elapsedMs === null && item.startedAt === null)).toBe(true)
    expect(r.summary[0]).toMatchObject({ samples: 2, medianMs: 55, p95Ms: 100 })
  })
  it('keeps cancellation independent from connection and marks truncated logs', () => {
    const r = run([event(0, 'ipc', 'start-tun started'), event(1, 'ipc', 'cancel-tun started'), event(5, 'ipc', 'cancel-tun finished'), event(6, 'ipc', 'stop-tun finished', { ms: 2 })])
    expect(r.ipc[0]).toMatchObject({ channel: 'cancel-tun', elapsedMs: 4 })
    expect(r.ipc[1]).toMatchObject({ pairing: 'missing-start', loggedMs: 2 })
    expect(r.unfinished).toEqual([{ channel: 'start-tun', startedAt: at(0), pairing: 'missing-terminal' }])
  })
  it('rejects malformed lines, negative durations and reversed timestamps', () => {
    const r = run(['broken-json', null, event(1, 'ipc', 'stop-tun started'), event(0, 'ipc', 'stop-tun finished', { ms: -1 }), event(2, 'tun', 'stop timing', { totalMs: -10, phaseDurations: { 'stop-xray': -5, 'repair-dns': 0 } })], '\uFEFF')
    expect(r.invalidLines).toBe(2)
    expect(r.outOfOrderRecords).toBe(1)
    expect(r.ipc[0]).toMatchObject({ elapsedMs: null, loggedMs: null, pairing: 'out-of-order' })
    expect(r.timings[0]).toMatchObject({ totalMs: null, phases: { 'repair-dns': { durationMs: 0 } } })
    expect(r.summary).toEqual([])
  })
  it('omits configuration, topology, raw errors and unknown phase names', () => {
    const secret = 'credential-198.51.100.1-user-path'
    const r = run([event(0, 'ipc', 'stop-tun finished', { ms: 1, args: secret, result: secret, error: secret }), event(0, 'xray', 'start timing', { totalMs: 1, secret, phaseDurations: { [secret]: { durationMs: 1 }, 'resolve-server': { durationMs: 1, server: secret, error: secret } } }), event(0, 'other', secret, { secret })])
    expect(JSON.stringify(r)).not.toContain(secret)
    expect(r.timings[0].phases).toEqual({ 'resolve-server': { durationMs: 1 } })
  })
  it('reports file errors without disclosing the path', () => {
    const r = spawnSync(process.execPath, [script, join(process.cwd(), '.tmp', 'nonexistent-private-input.log')], { encoding: 'utf8', windowsHide: true })
    expect(r.status).toBe(1)
    expect(r.stdout).toBe('')
    expect(r.stderr.trim()).toBe('ENOENT')
  })
})
