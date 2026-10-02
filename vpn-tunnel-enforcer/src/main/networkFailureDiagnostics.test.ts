// AT-02-006 / AT-07-002 / AT-08-001: bounded, private, stage-specific diagnostics.
import { EventEmitter } from 'node:events'
import { mkdir, mkdtemp, writeFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const mocks = vi.hoisted(() => ({ connect: vi.fn(), tls: vi.fn() }))
vi.mock('socks', () => ({ SocksClient: { createConnection: mocks.connect } }))
vi.mock('node:tls', () => ({ connect: mocks.tls, default: { connect: mocks.tls } }))
import { CORE_TAIL_BYTES, collectTunnelFailureDiagnostics, failureAssessment, networkFailureCode, probeSocksPath, readCoreLogTail, summarizeCoreNetwork } from './networkFailureDiagnostics'

beforeEach(() => { vi.clearAllMocks() })
afterEach(() => { vi.useRealTimers() })

describe('bounded diagnostic evidence', () => {
  it('classifies only measured path differences, never a carrier/DPI cause', () => {
    expect(failureAssessment({ ok: true }, { ok: true })).toBe('TUN_PATH_FAILED_ENGINE_HTTPS_OK')
    expect(failureAssessment({ ok: true }, { ok: false })).toBe('UPSTREAM_TCP_OK_ENGINE_EGRESS_UNCONFIRMED')
    expect(failureAssessment({ ok: false }, { ok: false })).toBe('UPSTREAM_TCP_UNCONFIRMED')
    expect(failureAssessment({}, {})).toBe('INSUFFICIENT_EVIDENCE')
  })
  it('retains only complete records from the bounded file tail and reports truncation', async () => {
    const root = join(process.cwd(), '.tmp')
    await mkdir(root, { recursive: true })
    const dir = await mkdtemp(join(root, 'network-diagnostics-'))
    const path = join(dir, 'core.log')
    try {
      await writeFile(path, 'secret-head\n' + 'x'.repeat(CORE_TAIL_BYTES) + '\nlast record\n')
      expect(await readCoreLogTail(path)).toEqual({ truncated: true, text: 'last record\n' })
      await writeFile(path, 'x'.repeat(CORE_TAIL_BYTES + 10))
      expect((await readCoreLogTail(path)).text).toBe('')
      await writeFile(path, '')
      expect(await readCoreLogTail(path)).toEqual({ text: '', truncated: false })
    } finally { await rm(dir, { recursive: true, force: true }) }
  })
  it('filters old Xray records and distinguishes dial attempts from protocol progress/errors', () => {
    const result = summarizeCoreNetwork([
      '2026/10/02 16:59:30.001 [Info] connection refused',
      '2026/10/02 17:00:00.001 [Info] dialing TCP to tcp:192.0.2.1:443',
      '2026/10/02 17:00:01.001 [Info] tunneling request to tcp:secret.example:443',
      '2026/10/02 17:00:02.001 [Info] i/o timeout',
      '2026/10/02 17:00:03.001 [Info] REALITY verification failed',
      '2026/10/02 17:00:04.001 [Info] dial tcp: permission denied'
    ].join('\n'), new Date(2026, 9, 2, 17, 0, 0).getTime())
    expect(result).toMatchObject({ records: 5, dialing: 1, protocolRequests: 1, refused: 0, timeouts: 1, realityFailures: 1, denied: 1 })
    expect(JSON.stringify(result)).not.toMatch(/192\.0\.2|secret/)
  })
  it('parses sing-box zone offsets and separates local SOCKS failure', () => {
    expect(summarizeCoreNetwork('+0300 2026-10-02 17:00:02 ERROR outbound/socks[proxy-out]: dial tcp 127.0.0.1:50001: connection refused', Date.parse('2026-10-02T14:00:01Z')))
      .toMatchObject({ records: 1, localSocksFailures: 1, refused: 1 })
  })
  it('reports unreadable/missing core evidence and skipped paths honestly', async () => {
    const result = await collectTunnelFailureDiagnostics({ runtimeDir: join(process.cwd(), '.tmp', 'absent-core-fixture'), startedAt: Date.now() })
    expect(result).toMatchObject({ xray: { readable: false }, tun: { readable: false }, physicalTcp: { checked: false }, engineHttps: { checked: false } })
    expect(mocks.connect).not.toHaveBeenCalled()
  })
  it('only emits known error codes and inspects wrapped causes', () => {
    expect(networkFailureCode({ cause: { code: 'ENETUNREACH' } })).toBe('ENETUNREACH')
    expect(networkFailureCode({ code: 'password=SECRET', message: 'private.example' })).toBe('UNKNOWN')
    expect(networkFailureCode(new Error('SocksClient connection timed out'))).toBe('ETIMEDOUT')
  })
})

describe('controlled network path diagnostics', () => {
  it('probes the supplied endpoint through the local direct SOCKS and closes its socket', async () => {
    const socket = { destroy: vi.fn() }
    mocks.connect.mockResolvedValue({ socket })
    expect(await probeSocksPath(50001, { host: '192.0.2.1', port: 443 })).toMatchObject({ ok: true, stage: 'local-socks-and-remote-connect' })
    expect(mocks.connect).toHaveBeenCalledWith(expect.objectContaining({ proxy: { host: '127.0.0.1', port: 50001, type: 5 }, destination: { host: '192.0.2.1', port: 443 } }))
    expect(socket.destroy).toHaveBeenCalledOnce()
    expect(mocks.tls).not.toHaveBeenCalled()
  })
  it('cleans up a late SOCKS socket after the overall deadline', async () => {
    vi.useFakeTimers()
    let complete!: (result: any) => void
    mocks.connect.mockReturnValue(new Promise(resolve => { complete = resolve }))
    const pending = probeSocksPath(50001, { host: '192.0.2.1', port: 443 })
    await vi.advanceTimersByTimeAsync(3000)
    expect(await pending).toMatchObject({ ok: false, code: 'ETIMEDOUT' })
    const socket = { destroy: vi.fn() }
    complete({ socket }); await Promise.resolve()
    expect(socket.destroy).toHaveBeenCalledOnce()
  })
  it.each(['timeout', 'certificate', 'valid', 'invalid', 'close'])('identifies TLS/HTTPS stage and cleans sockets: %s', async outcome => {
    vi.useFakeTimers()
    const socket = { destroy: vi.fn() }
    const secure = Object.assign(new EventEmitter(), { write: vi.fn(), destroy: vi.fn() })
    mocks.connect.mockResolvedValue({ socket }); mocks.tls.mockReturnValue(secure)
    const pending = probeSocksPath(50001, { host: '1.1.1.1', port: 443 }, true)
    await Promise.resolve()
    expect(mocks.tls).toHaveBeenCalledWith(expect.objectContaining({ rejectUnauthorized: true, host: '1.1.1.1', servername: '' }))
    if (outcome === 'timeout') await vi.advanceTimersByTimeAsync(3000)
    else if (outcome === 'certificate') secure.emit('error', { code: 'ERR_TLS_CERT_ALTNAME_INVALID' })
    else if (outcome === 'close') secure.emit('close')
    else {
      secure.emit('secureConnect')
      secure.emit('data', Buffer.from('HTTP/1.1 200 OK\r\n\r\nip=' + (outcome === 'valid' ? '203.0.113.7' : 'bad-ip') + '\n'))
      secure.emit('end')
    }
    const result = await pending
    expect(result.ok).toBe(outcome === 'valid')
    expect(result.stage).toBe(['valid', 'invalid'].includes(outcome) ? 'https-response' : 'tls')
    expect(socket.destroy).toHaveBeenCalledOnce()
    expect(secure.destroy).toHaveBeenCalledOnce()
    expect(JSON.stringify(result)).not.toMatch(/203\.0\.113/)
  })
})
