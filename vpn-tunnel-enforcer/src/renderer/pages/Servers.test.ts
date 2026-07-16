import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { displayedServerPing, hasSuccessfulRowPing } from './Servers'

const source = readFileSync(join(process.cwd(), 'src/renderer/pages/Servers.tsx'), 'utf8')

describe('displayedServerPing', () => {
  it('uses per-row server ping when present', () => {
    expect(displayedServerPing({ ping: 120 }, { ping: 80 })).toBe(80)
  })

  it('falls back to persisted profile ping', () => {
    expect(displayedServerPing({ ping: 120 })).toBe(120)
  })

  it('never receives or displays health-check latency', () => {
    const healthLatencyThatMustNotBeShown = 3
    expect(displayedServerPing({ ping: 120 }, { ping: null })).not.toBe(healthLatencyThatMustNotBeShown)
    expect(displayedServerPing({ ping: 120 }, { ping: null })).toBe(120)
  })
})

describe('hasSuccessfulRowPing', () => {
  it('treats a completed numeric ping as fresher than a cached health failure', () => {
    expect(hasSuccessfulRowPing({ ping: 105, loading: false })).toBe(true)
  })

  it('does not hide an error while the direct ping is still running or failed', () => {
    expect(hasSuccessfulRowPing({ ping: 105, loading: true })).toBe(false)
    expect(hasSuccessfulRowPing({ ping: null, loading: false })).toBe(false)
  })
})

describe('server page ping wiring', () => {
  it('uses the same ping IPC as the dashboard for per-row pings', () => {
    expect(source).toContain('const ping = await window.electronAPI.serversPingOne(host, port)')
    expect(source).not.toContain('const probe = await window.electronAPI.serverProbe(host, port)')
  })

  it('pings rows directly while the tunnel is running instead of relying on persisted pingAll', () => {
    expect(source).toContain('if (tunRunning) {')
    expect(source).toContain('await pingRow(profile.id, profile.server, profile.port)')
  })

  it('clears an obsolete health result when a direct ping succeeds', () => {
    expect(source).toContain('const { [rowKey]: _staleHealth, ...next } = prev')
    expect(source).toContain('const hasFreshPingSuccess = hasSuccessfulRowPing(perRowPing)')
  })
})
