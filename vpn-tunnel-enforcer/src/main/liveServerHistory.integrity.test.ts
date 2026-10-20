import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createHash } from 'node:crypto'
import { join, resolve } from 'node:path'
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'fs'
import type { LiveServerCheck } from '../shared/ipc-types'

const state = vi.hoisted(() => ({ fail: '', failAt: 1, attempts: 0, log: vi.fn() }))
vi.mock('electron', () => ({ app: { getPath: () => { throw new Error('No userData') } } }))
vi.mock('./appLogger', () => ({ logEvent: state.log }))
vi.mock('fs', async importOriginal => {
  const actual = await importOriginal<typeof import('fs')>()
  const methods = ['readFileSync', 'writeFileSync', 'renameSync', 'copyFileSync', 'fsyncSync'] as const
  return { ...actual, ...Object.fromEntries(methods.map(method => [method, (...args: unknown[]) => {
    if (state.fail === method && ++state.attempts === state.failAt) throw Object.assign(new Error('C:\\private\\password-secret at unsafe-stack'), { code: 'EACCES' })
    return Reflect.apply(actual[method], actual, args)
  }])) }
})
import { liveServerHistory } from './liveServerHistory'

const check = (id = 'legacy-1', profileId = 'p1'): LiveServerCheck => ({
  id, profileId, host: 'probe.example', port: 443, mode: 'basic',
  startedAt: '2026-10-20T01:00:00.000Z', finishedAt: '2026-10-20T01:00:01.000Z', durationMs: 1000,
  dns: { status: 'ok', durationMs: 1, a: ['192.0.2.1'], aaaa: [], cnameChain: [] },
  reachability: { status: 'ok', durationMs: 1, port: 443, tcpReachable: true }, findings: []
})
let directory: string, file: string
const disk = () => readFileSync(file, 'utf8')
const hash = () => createHash('sha256').update(disk()).digest('hex')
beforeEach(() => {
  state.fail = ''; state.failAt = 1; state.attempts = 0; state.log.mockClear()
  mkdirSync(resolve('.tmp'), { recursive: true })
  directory = mkdtempSync(resolve('.tmp/live-history-')); file = join(directory, 'live-server-checks.json')
  liveServerHistory.init(file)
})
afterEach(() => { state.fail = ''; rmSync(directory, { recursive: true, force: true }) })

// AT-00-006/010, F-074/F-143: real JSON files, injected filesystem boundaries.
describe('live history integrity', () => {
  it('loads 100 legacy records across five targets and survives a restart', () => {
    const raw = Object.fromEntries(Array.from({ length: 5 }, (_, i) => [`profile:p${i}`, Array.from({ length: 20 }, (_, n) => check(`${i}-${n}`, `p${i}`))]))
    writeFileSync(file, JSON.stringify(raw)); const before = hash(); liveServerHistory.init(file)
    for (let i = 0; i < 5; i++) expect(liveServerHistory.getHistory({ profileId: `p${i}` })).toHaveLength(20)
    expect(hash()).toBe(before) // Read must not repair or rewrite implicitly.
    liveServerHistory.addCheck(check('new', 'p0')); liveServerHistory.init(file)
    expect(liveServerHistory.getHistory({ profileId: 'p0' })[0].id).toBe('new')
    expect(JSON.parse(readFileSync(file + '.bak', 'utf8'))).toEqual(raw)
  })
  it.each(['{"profile:p1":[', 'null', '[]', '{"profile:p1":17}'])('reports corrupt input %s without logging raw content', raw => {
    writeFileSync(file, raw); liveServerHistory.init(file)
    expect(liveServerHistory.getHistory()).toEqual([])
    expect(state.log).toHaveBeenCalledWith('error', 'live-server-history', 'history.corrupted', expect.objectContaining({ reason: expect.stringMatching(/^invalid-(json|schema)$/) }))
    expect(JSON.stringify(state.log.mock.calls)).not.toContain(raw)
    expect(disk()).toBe(raw)
    liveServerHistory.addCheck(check()); liveServerHistory.init(file)
    expect(liveServerHistory.getHistory()[0].id).toBe('legacy-1')
  })
  it('keeps valid records when other rows or target buckets are malformed', () => {
    writeFileSync(file, JSON.stringify({ 'profile:p1': [null, check(), { ...check(), findings: [null] }], 'profile:bad': false }))
    liveServerHistory.init(file)
    expect(liveServerHistory.getHistory().map(row => row.id)).toEqual(['legacy-1'])
    expect(state.log).toHaveBeenCalledWith('error', 'live-server-history', 'history.corrupted', expect.objectContaining({ reason: 'invalid-schema', rejectedEntries: 3 }))
  })
  it.each([
    { dns: { status: 'ok', a: false } }, { findings: [null] }, { finishedAt: 'yesterday' },
    { port: 70000 }, { host: {} }, { dns: { ...check().dns, a: [null] } },
    { latency: { samples: false } }, { handshake: { status: 'ok', durationMs: 0, evidence: { detail: {} } } },
    { openPorts: [{ port: 443, open: true, state: {} }] },
    { egress: { status: 'ok', durationMs: 0, reflectors: [null] } },
    { throughput: { status: 'ok', durationMs: 0, samples: [null] } },
    { infrastructure: { status: 'ok', changesFromPrevious: { ipChanged: 'yes' } } }
  ])('rejects malformed diagnostic rows: %j', patch => {
    writeFileSync(file, JSON.stringify({ 'profile:p1': [{ ...check(), ...patch }, check('valid')] }))
    liveServerHistory.init(file)
    expect(liveServerHistory.getHistory().map(row => row.id)).toEqual(['valid'])
    expect(state.log).toHaveBeenCalledWith('error', 'live-server-history', 'history.corrupted', expect.objectContaining({ rejectedEntries: 1 }))
  })
  it('recovers from a valid backup without destroying it on the next write', () => {
    const backup = JSON.stringify({ 'profile:p1': [check('backup')] })
    writeFileSync(file + '.bak', backup); writeFileSync(file, '{broken')
    liveServerHistory.init(file)
    expect(liveServerHistory.getHistory()[0].id).toBe('backup')
    expect(state.log).toHaveBeenCalledWith('warn', 'live-server-history', 'history.recovered', expect.any(Object))
    liveServerHistory.addCheck(check('new')); liveServerHistory.init(file)
    expect(liveServerHistory.getHistory().map(row => row.id)).toEqual(['new', 'backup'])
    expect(readFileSync(file + '.bak', 'utf8')).toBe(backup)
  })
  it('loads the backup when the main file disappeared, then retains those rows after save and restart', () => {
    const backup = JSON.stringify({ 'profile:p1': [check('backup')] })
    writeFileSync(file + '.bak', backup)
    liveServerHistory.init(file)
    expect(liveServerHistory.getHistory().map(row => row.id)).toEqual(['backup'])
    expect(state.log).toHaveBeenCalledWith('warn', 'live-server-history', 'history.recovered', { source: 'backup' })
    liveServerHistory.addCheck(check('new')); liveServerHistory.init(file)
    expect(liveServerHistory.getHistory().map(row => row.id)).toEqual(['new', 'backup'])
    expect(readFileSync(file + '.bak', 'utf8')).toBe(backup)
  })
  it('refuses a future backup even when the main file is missing', () => {
    const backup = '{"schemaVersion":1}'
    writeFileSync(file + '.bak', backup)
    expect(() => liveServerHistory.init(file)).toThrow()
    expect(() => liveServerHistory.addCheck(check())).toThrow()
    expect(readFileSync(file + '.bak', 'utf8')).toBe(backup)
    expect(readdirSync(directory)).toEqual(['live-server-checks.json.bak'])
  })
  it.each([1, -1, 'future'])('refuses unsupported schema %j at read and write without changing bytes', schemaVersion => {
    liveServerHistory.addCheck(check('old'))
    writeFileSync(file, JSON.stringify({ schemaVersion, 'profile:p1': [check()] })); const before = hash()
    expect(() => liveServerHistory.addCheck(check('new'))).toThrow()
    expect(() => liveServerHistory.clearHistory()).toThrow()
    expect(() => liveServerHistory.init(file)).toThrow()
    expect(() => liveServerHistory.getHistory()).toThrow()
    expect(hash()).toBe(before)
  })
  it('surfaces unreadable storage and permits a fresh retry', () => {
    writeFileSync(file, JSON.stringify({ 'profile:p1': [check()] })); state.fail = 'readFileSync'
    expect(() => liveServerHistory.init(file)).toThrow()
    state.attempts = 0
    expect(() => liveServerHistory.getHistory()).toThrow()
    expect(state.log).toHaveBeenCalledWith('error', 'live-server-history', 'history.unavailable', { reason: 'permission', ioCode: 'EACCES' })
    expect(JSON.stringify(state.log.mock.calls)).not.toMatch(/private|password-secret|unsafe-stack/)
    state.fail = ''; expect(liveServerHistory.getHistory()[0].id).toBe('legacy-1')
  })
  it.each(['writeFileSync', 'renameSync', 'copyFileSync', 'fsyncSync'])('failed %s leaves both file and memory unchanged, then retries', stage => {
    liveServerHistory.addCheck(check('old')); const before = hash(); state.fail = stage
    expect(() => liveServerHistory.addCheck(check('new'))).toThrow(expect.objectContaining({ category: 'permission' }))
    expect(liveServerHistory.getHistory().map(row => row.id)).toEqual(['old'])
    state.attempts = 0
    if (stage === 'copyFileSync') state.fail = 'writeFileSync' // clear writes an empty backup.
    expect(() => liveServerHistory.clearHistory()).toThrow()
    expect(liveServerHistory.getHistory().map(row => row.id)).toEqual(['old'])
    expect(state.log).toHaveBeenCalledWith('error', 'live-server-history', 'history.write-failed', { reason: 'permission', ioCode: 'EACCES' })
    expect(JSON.stringify(state.log.mock.calls)).not.toMatch(/private|password-secret|unsafe-stack/)
    state.fail = ''; expect(hash()).toBe(before)
    expect(readdirSync(directory).filter(name => name.endsWith('.tmp'))).toEqual([])
    liveServerHistory.addCheck(check('new')); liveServerHistory.init(file)
    expect(liveServerHistory.getHistory().map(row => row.id)).toEqual(['new', 'old'])
    liveServerHistory.clearHistory(); liveServerHistory.init(file); expect(liveServerHistory.getHistory()).toEqual([])
  })
  it.each(['renameSync', 'fsyncSync'])('failure in final %s after backup still preserves the previous commit', stage => {
    liveServerHistory.addCheck(check('old')); const before = disk()
    state.fail = stage; state.failAt = 2
    expect(() => liveServerHistory.addCheck(check('new'))).toThrow(expect.objectContaining({ category: 'permission' }))
    state.fail = ''
    expect(disk()).toBe(before); expect(readFileSync(file + '.bak', 'utf8')).toBe(before)
    expect(liveServerHistory.getHistory()[0].id).toBe('old')
    expect(readdirSync(directory).some(name => name.endsWith('.tmp'))).toBe(false)
  })
  it('does not overwrite a future-format backup', () => {
    liveServerHistory.addCheck(check('old')); const before = disk(), backup = '{"schemaVersion":1}'
    writeFileSync(file + '.bak', backup)
    expect(() => liveServerHistory.clearHistory()).toThrow()
    expect(disk()).toBe(before); expect(readFileSync(file + '.bak', 'utf8')).toBe(backup)
  })
  it('does not resurrect explicitly cleared rows after corrupting the cleared file', () => {
    liveServerHistory.addCheck(check('old')); liveServerHistory.clearHistory()
    writeFileSync(file, '{broken'); liveServerHistory.init(file)
    expect(liveServerHistory.getHistory()).toEqual([])
  })
  it('rejects invalid incoming records without writing or changing memory', () => {
    liveServerHistory.addCheck(check('old')); const before = hash()
    expect(() => liveServerHistory.addCheck({ ...check('new'), dns: null } as unknown as LiveServerCheck)).toThrow(expect.objectContaining({ category: 'validation' }))
    expect(hash()).toBe(before); expect(liveServerHistory.getHistory()[0].id).toBe('old')
  })
  it('returns detached records so a caller cannot mutate persisted state', () => {
    liveServerHistory.addCheck(check()); const before = disk()
    const rows = liveServerHistory.getHistory({ profileId: 'p1' }); rows[0].dns.a.push('203.0.113.1'); rows.length = 0
    expect(liveServerHistory.getHistory({ profileId: 'p1' })[0].dns.a).toEqual(['192.0.2.1'])
    expect(disk()).toBe(before)
  })
  it('refuses an add without a persistent userData path', async () => {
    vi.resetModules()
    const { liveServerHistory: fresh } = await import('./liveServerHistory')
    expect(() => fresh.addCheck(check())).toThrow()
    expect(fresh.getHistory()).toEqual([])
  })
})
