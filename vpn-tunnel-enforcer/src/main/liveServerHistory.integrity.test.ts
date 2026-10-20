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
import { liveServerHistory, LIVE_HISTORY_SCHEMA_VERSION } from './liveServerHistory'

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
    const backup = JSON.stringify({ schemaVersion: LIVE_HISTORY_SCHEMA_VERSION + 1 })
    writeFileSync(file + '.bak', backup)
    expect(() => liveServerHistory.init(file)).toThrow()
    expect(() => liveServerHistory.addCheck(check())).toThrow()
    expect(readFileSync(file + '.bak', 'utf8')).toBe(backup)
    expect(readdirSync(directory)).toEqual(['live-server-checks.json.bak'])
  })
  it.each([LIVE_HISTORY_SCHEMA_VERSION + 1, -1, 'future'])('refuses unsupported schema %j at read and write without changing bytes', schemaVersion => {
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
    liveServerHistory.addCheck(check('old')); const before = disk(), backup = JSON.stringify({ schemaVersion: LIVE_HISTORY_SCHEMA_VERSION + 1 })
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
  it('preserves provenance and receipt identities across sanitization, disk and restart', () => {
    const record = { ...check('op_11111111111141118111111111111111'),
      operationKey: 'op_11111111111141118111111111111111', correlationId: 'ipc_22222222222242228222222222222222',
      provenance: { source: 'ipc', owner: 'manual', route: 'unconfirmed', confidence: 'indeterminate' }
    } as LiveServerCheck
    liveServerHistory.addCheck(record); liveServerHistory.init(file)
    expect(liveServerHistory.getHistory()[0]).toEqual(record)
  })
  it('does not fabricate provenance for historical rows and rejects forged metadata', () => {
    writeFileSync(file, JSON.stringify({ 'profile:p1': [check('legacy'),
      { ...check('forged'), provenance: { source: 'ipc', owner: 'administrator', route: 'tun', confidence: 'observed' } }] }))
    liveServerHistory.init(file)
    expect(liveServerHistory.getHistory().map(row => row.id)).toEqual(['legacy'])
    expect(liveServerHistory.getHistory()[0]).not.toHaveProperty('provenance')
  })
  it('records the ordered v0 to v1 migration with the exact backup checksum only after a successful write', () => {
    const legacy = JSON.stringify({ 'profile:p1': [check('legacy')] })
    writeFileSync(file, legacy); liveServerHistory.init(file)
    expect(disk()).toBe(legacy)
    state.fail = 'renameSync'; state.failAt = 2
    expect(() => liveServerHistory.addCheck(check('failed'))).toThrow()
    expect(disk()).toBe(legacy)
    expect(state.log.mock.calls.some(call => call[2] === 'history.migrated')).toBe(false)
    state.fail = ''; state.log.mockClear()
    liveServerHistory.addCheck(check('new'))
    const migration = { id: 'live-history-provenance-v1', from: 0, to: 1, checksum: createHash('sha256').update(legacy).digest('hex') }
    expect(JSON.parse(disk())).toMatchObject({ schemaVersion: 1, migration })
    expect(readFileSync(file + '.bak', 'utf8')).toBe(legacy)
    expect(state.log).toHaveBeenCalledWith('info', 'live-server-history', 'history.migrated', migration)
    liveServerHistory.init(file); state.log.mockClear(); liveServerHistory.addCheck(check('next'))
    expect(JSON.parse(disk()).migration).toEqual(migration)
    expect(state.log.mock.calls.some(call => call[2] === 'history.migrated')).toBe(false)
  })
  it('preserves legacy receipt and profile UUIDs while redacting credential UUIDs in diagnostics', () => {
    const id = '11111111-1111-4111-8111-111111111111', profileId = '22222222-2222-4222-8222-222222222222'
    const credential = '33333333-3333-4333-8333-333333333333'
    liveServerHistory.addCheck({ ...check(id, profileId), error: credential }); liveServerHistory.init(file)
    expect(liveServerHistory.getHistory({ profileId })[0]).toMatchObject({ id, profileId })
    expect(JSON.stringify(liveServerHistory.getHistory())).not.toContain(credential)
  })
  it('redacts credentials in nested diagnostics before returning, saving and backing up records', () => {
    const privateText = 'password=PASSWORD_SECRET Bearer TOKEN_SECRET vless://UUID_SECRET@vpn.example:443 C:\\Users\\private-user\\config.json'
    const record = { ...check('op_11111111111141118111111111111111'),
      error: privateText,
      dns: { ...check().dns, error: privateText },
      tls: { status: 'error', durationMs: 0, authorized: false, authorizationError: privateText },
      findings: [{ code: 'TEST', severity: 'warning', title: privateText, detail: privateText,
        evidence: { normalText: privateText, auth: 'AUTH_SECRET', cookie: 'COOKIE_SECRET', apiKey: 'API_SECRET', port: 443 } }]
    } as LiveServerCheck
    const original = JSON.stringify(record)
    liveServerHistory.addCheck(record); liveServerHistory.addCheck(check('second')); liveServerHistory.init(file)
    const serialized = JSON.stringify(liveServerHistory.getHistory()) + disk() + readFileSync(file + '.bak', 'utf8')
    expect(serialized).not.toMatch(/PASSWORD_SECRET|TOKEN_SECRET|UUID_SECRET|private-user|AUTH_SECRET|COOKIE_SECRET|API_SECRET/)
    expect(JSON.stringify(record)).toBe(original)
    expect(liveServerHistory.getHistory()[1]).toMatchObject({ id: record.id, tls: { authorized: false }, findings: [{ evidence: { port: 443 } }] })
  })
  it('refuses an add without a persistent userData path', async () => {
    vi.resetModules()
    const { liveServerHistory: fresh } = await import('./liveServerHistory')
    expect(() => fresh.addCheck(check())).toThrow()
    expect(fresh.getHistory()).toEqual([])
  })
})
