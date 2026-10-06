import { afterAll, afterEach, describe, expect, it, vi } from 'vitest'

const fixturePaths = vi.hoisted(() => {
  const fs = require('fs') as typeof import('fs')
  const path = require('path') as typeof import('path')
  const root = fs.mkdtempSync(path.join(require('os').tmpdir(), 'vpnte-traffic-forensics-'))
  return {
    root,
    data: path.join(root, 'user-data'),
    stage: path.join(root, 'stage'),
    sidecar: path.join(root, 'sidecar', 'vpnte-etw-sidecar.cmd')
  }
})
const STOP_ACK = 'VPNTE_CAPTURE_STOPPED:pktmon\nVPNTE_CAPTURE_STOPPED:netsh\n'
afterAll(() => rmSync(fixturePaths.root, { recursive: true, force: true }))
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { dirname, join } from 'path'
import { EventEmitter } from 'events'

const execElevatedMock = vi.hoisted(() => vi.fn())
const spawnMock = vi.hoisted(() => vi.fn())
const trafficSettingsMock = vi.hoisted(() => ({ enabled: true }))
process.env.VPNTE_TRAFFIC_FORENSICS_SIDECAR = '0'

vi.mock('electron', () => ({
  app: {
    getPath: () => fixturePaths.data,
    getVersion: () => '1.1.0-test',
    isPackaged: false
  }
}))

// Filesystem fixtures must never write to the production ProgramData runtime.
vi.mock('./runtimePaths', () => ({
  getPrivilegedRuntimeDir: (name: string) => join(fixturePaths.data, 'privileged', name)
}))

vi.mock('./admin', () => ({
  execElevated: execElevatedMock
}))

vi.mock('child_process', () => ({
  default: { spawn: spawnMock },
  spawn: spawnMock
}))

vi.mock('./appLogger', () => ({
  logEvent: vi.fn()
}))

// ACL hardening is covered by runtimeDirSecurity.test.ts. Stub it here so these
// tests neither shell out to PowerShell nor need child_process.execFile, which
// the child_process mock above deliberately does not provide.
vi.mock('./runtimeDirSecurity', () => ({
  ensureElevatedRuntimeDirHardened: vi.fn(async () => ({
    hardened: true,
    message: 'stubbed'
  })),
  verifyDirectoryHardened: vi.fn(async () => ({ hardened: true, message: 'stubbed' })),
  resetRuntimeDirHardeningCache: vi.fn(),
  directoryExists: vi.fn(async () => true)
}))

vi.mock('./settings', () => ({
  settingsStore: {
    get: () => ({
      deepTrafficInspectionEnabled: trafficSettingsMock.enabled,
      deepTrafficInspectionMaxSizeMb: 512,
      deepTrafficInspectionRetainSessions: 3
    })
  }
}))

vi.mock('./trafficForensicsSummary', async importOriginal => {
  const actual = await importOriginal<typeof import('./trafficForensicsSummary')>()
  return { ...actual, generateTrafficForensicsSummary: vi.fn(actual.generateTrafficForensicsSummary) }
})
import { generateTrafficForensicsSummary } from './trafficForensicsSummary'
import { ensureElevatedRuntimeDirHardened, verifyDirectoryHardened } from './runtimeDirSecurity'

import {
  getTrafficForensicsStatus,
  recordTrafficForensicsAppEvent,
  restartTrafficForensicsSession,
  stageTrafficForensicsArtifacts,
  startTrafficForensicsSession,
  stopTrafficForensicsSession
} from './trafficForensics'

function decodeEncodedCommand(command: string): string {
  const marker = 'EncodedCommand '
  const index = command.indexOf(marker)
  if (index === -1) return command
  const encoded = command.slice(index + marker.length).trim()
  return Buffer.from(encoded, 'base64').toString('utf16le')
}

function mockChildProcess(pid = 4242): any {
  const child = new EventEmitter() as any
  child.pid = pid
  child.kill = vi.fn()
  child.exitCode = null
  child.killed = false
  child.stdout = new EventEmitter()
  child.stderr = new EventEmitter()
  return child
}

async function resetForensicsState(): Promise<void> {
  await stopTrafficForensicsSession('test-reset').catch(() => undefined)
}

describe('trafficForensics', () => {
  afterEach(async () => {
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    vi.mocked(ensureElevatedRuntimeDirHardened).mockResolvedValue({ hardened: true, message: 'stubbed' })
    vi.mocked(verifyDirectoryHardened).mockResolvedValue({ hardened: true, message: 'stubbed' })
    rmSync(join(fixturePaths.data, 'traffic-forensics', 'latest-session.json'), { force: true })
    await resetForensicsState()
    execElevatedMock.mockReset()
    spawnMock.mockReset()
    trafficSettingsMock.enabled = true
    vi.mocked(ensureElevatedRuntimeDirHardened).mockResolvedValue({ hardened: true, message: 'stubbed' })
    vi.mocked(verifyDirectoryHardened).mockResolvedValue({ hardened: true, message: 'stubbed' })
    process.env.VPNTE_TRAFFIC_FORENSICS_SIDECAR = '0'
    if (existsSync(fixturePaths.data)) {
      rmSync(fixturePaths.data, { recursive: true, force: true })
    }
    if (existsSync(fixturePaths.stage)) {
      rmSync(fixturePaths.stage, { recursive: true, force: true })
    }
  })

  it('fails closed before script/network effects when the forensics namespace is untrusted (AT-01-009)', async () => {
    await resetForensicsState()
    execElevatedMock.mockClear()
    vi.mocked(ensureElevatedRuntimeDirHardened).mockResolvedValue({ hardened: false, message: 'unsafe parent' })
    await expect(startTrafficForensicsSession({ mode: 'directVpn', target: 'fixture' })).rejects.toThrow('RuntimeSecurityAclError')
    expect(execElevatedMock).not.toHaveBeenCalled()
    expect(spawnMock).not.toHaveBeenCalled()
  })

  it('stops its owned provider without runtime scripts after ACL refusal (AT-01-009/AT-08-005)', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    await startTrafficForensicsSession({ mode: 'directVpn', target: 'fixture' })
    execElevatedMock.mockClear()
    vi.mocked(verifyDirectoryHardened).mockResolvedValueOnce({ hardened: false, message: 'unsafe parent' })
    const status = await stopTrafficForensicsSession('security-test')
    expect(execElevatedMock).toHaveBeenCalledTimes(1)
    const command = execElevatedMock.mock.calls[0][0] as string
    expect(command).not.toContain('-File')
    expect(decodeEncodedCommand(command)).toContain("[Environment]::SystemDirectory, 'pktmon.exe'")
    expect(decodeEncodedCommand(command)).not.toContain(fixturePaths.data)
    expect(existsSync(join(status.sessionDir!, 'pktmon-stop.ps1'))).toBe(false)
    expect(status.running).toBe(false)
    expect(status.lastError).toContain('CaptureStoppedArtifactsUnavailable')
  })

  it.each(['pktmon', 'netsh'] as const)('preserves %s cleanup ownership and retries after stop failure (AT-08-005)', async engine => {
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    if (engine === 'netsh') execElevatedMock.mockRejectedValueOnce(new Error('pktmon unavailable'))
    const started = await startTrafficForensicsSession({ mode: 'directVpn', target: 'fixture' })
    expect(started.engine).toBe(engine)
    execElevatedMock.mockClear().mockRejectedValueOnce(new Error('stop failed'))
    await expect(stopTrafficForensicsSession('failure-test')).rejects.toThrow('CaptureStopUnconfirmed')
    const pending = await getTrafficForensicsStatus()
    expect(pending.running).toBe(true)
    expect(pending.cleanupPending).toBe(true)
    expect(pending.stoppedAt).toBeNull()
    expect(JSON.parse(readFileSync(join(started.sessionDir!, 'session-manifest.json'), 'utf8')).running).toBe(true)
    const retried = await stopTrafficForensicsSession('retry')
    expect(retried.running).toBe(false)
    expect(retried.cleanupPending).toBe(false)
    expect(execElevatedMock).toHaveBeenCalledTimes(2)
  })

  it('does not overwrite an active provider when manifest persistence fails (AT-01-009/AT-08-005)', async () => {
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    await startTrafficForensicsSession({ mode: 'directVpn', target: 'fixture' })
    execElevatedMock.mockClear().mockRejectedValueOnce(new Error('stop failed'))
    vi.mocked(ensureElevatedRuntimeDirHardened).mockResolvedValue({ hardened: false, message: 'unsafe parent' })
    await expect(stopTrafficForensicsSession('failure-test')).rejects.toThrow('CaptureStopUnconfirmed')
    expect((await getTrafficForensicsStatus()).running).toBe(true)
    expect((await getTrafficForensicsStatus()).stoppedAt).toBeNull()
    execElevatedMock.mockClear().mockRejectedValueOnce(new Error('still running'))
    await expect(restartTrafficForensicsSession()).rejects.toThrow('CaptureStopUnconfirmed')
    expect(execElevatedMock).toHaveBeenCalledTimes(1)
  })

  it('refuses a successful process exit without a provider stop acknowledgement (AT-08-005)', async () => {
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    await startTrafficForensicsSession({ mode: 'directVpn', target: 'fixture' })
    execElevatedMock.mockResolvedValueOnce({ stdout: '', stderr: '' })
    await expect(stopTrafficForensicsSession('empty-result')).rejects.toThrow('acknowledgement missing')
    expect((await getTrafficForensicsStatus()).running).toBe(true)
  })

  it.each([false, true])('orders stop/start and a subsequent stop=%s across finalization (AT-08-005, F-198)', async stopAgain => {
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    await startTrafficForensicsSession({ mode: 'directVpn', target: 'old' })
    execElevatedMock.mockClear()
    let release!: () => void
    let entered!: () => void
    const gate = new Promise<void>(resolve => { release = resolve })
    const finalizing = new Promise<void>(resolve => { entered = resolve })
    vi.mocked(generateTrafficForensicsSummary).mockImplementationOnce(async manifest => {
      entered()
      await gate
      return manifest
    })
    const stopping = stopTrafficForensicsSession('first')
    await finalizing
    const starting = startTrafficForensicsSession({ mode: 'directVpn', target: 'new' })
    const lastStop = stopAgain ? stopTrafficForensicsSession('last') : Promise.resolve()
    try {
      await new Promise(resolve => setTimeout(resolve, 20))
      expect(execElevatedMock).toHaveBeenCalledTimes(1)
    } finally {
      release()
      await Promise.all([stopping, starting, lastStop])
    }
    const started = await starting
    const status = await getTrafficForensicsStatus()
    const saved = JSON.parse(readFileSync(join(fixturePaths.data, 'privileged', 'traffic-forensics', 'latest-session.json'), 'utf8'))
    expect(started.running).toBe(true)
    expect(started.cleanupPending).toBe(false)
    expect(status.target).toBe('new')
    expect(status.running).toBe(!stopAgain)
    expect(saved.sessionId).toBe(started.sessionId)
    expect(saved.running).toBe(!stopAgain)
    expect(execElevatedMock).toHaveBeenCalledTimes(stopAgain ? 3 : 2)
  })

  it('orders restart before a subsequent stop without nested queue waits (AT-08-005)', async () => {
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    await startTrafficForensicsSession({ mode: 'directVpn', target: 'fixture' })
    execElevatedMock.mockClear()
    const [restarted, stopped] = await Promise.all([restartTrafficForensicsSession(), stopTrafficForensicsSession('last')])
    expect(restarted.running).toBe(true)
    expect(stopped.running).toBe(false)
    expect((await getTrafficForensicsStatus()).running).toBe(false)
    expect(execElevatedMock).toHaveBeenCalledTimes(3)
  })

  it('serializes concurrent provider stops without executing a stopped provider twice (AT-08-005)', async () => {
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    await startTrafficForensicsSession({ mode: 'directVpn', target: 'fixture' })
    execElevatedMock.mockClear()
    await Promise.all([stopTrafficForensicsSession('first'), stopTrafficForensicsSession('second')])
    expect(execElevatedMock).toHaveBeenCalledTimes(1)
    expect((await getTrafficForensicsStatus()).running).toBe(false)
  })

  it.each(['running', 'corrupt', 'oversized'] as const)('warns about %s legacy state even with capture disabled, without executing it (AT-08-004)', async kind => {
    const legacyDir = join(fixturePaths.data, 'traffic-forensics')
    mkdirSync(legacyDir, { recursive: true })
    const body = kind === 'corrupt' ? '{' : kind === 'oversized' ? 'x'.repeat(65537) : JSON.stringify({
      running: true, engine: 'pktmon', sessionDir: 'C:/hostile', etlPath: 'C:/hostile/script.ps1', sidecar: { pid: 4 }
    })
    writeFileSync(join(legacyDir, 'latest-session.json'), body)
    trafficSettingsMock.enabled = false
    execElevatedMock.mockClear()
    const status = await getTrafficForensicsStatus()
    expect(status.cleanupPending).toBe(true)
    expect(status.lastError).toContain('LegacyCaptureCleanupRequired')
    await expect(startTrafficForensicsSession({ mode: 'directVpn', target: 'fixture' })).rejects.toThrow('LegacyCaptureCleanupRequired')
    await expect(stopTrafficForensicsSession('legacy')).rejects.toThrow('LegacyCaptureCleanupRequired')
    expect(execElevatedMock).not.toHaveBeenCalled()
    expect(spawnMock).not.toHaveBeenCalled()
    expect(readFileSync(join(legacyDir, 'latest-session.json'), 'utf8')).toBe(body)
  })

  it.each([
    { lastError: 'native stop failed', stoppedAt: 1 },
    { lastError: null },
    { lastError: null, stoppedAt: 1, stopReason: 'status-reconciled-stop' },
    { lastError: null, stoppedAt: 1, stopReason: 'zombie-recovery' },
    { lastError: null, stoppedAt: 1, sidecar: { running: true } }
  ])('rejects a legacy false-stopped hint %j without modifying it (AT-08-004, F-198)', async metadata => {
    const legacyDir = join(fixturePaths.data, 'traffic-forensics')
    mkdirSync(legacyDir, { recursive: true })
    const body = JSON.stringify({ running: false, sessionDir: 'C:/hostile', ...metadata })
    const path = join(legacyDir, 'latest-session.json')
    writeFileSync(path, body)
    expect((await getTrafficForensicsStatus()).cleanupPending).toBe(true)
    await expect(startTrafficForensicsSession({ mode: 'directVpn', target: 'fixture' })).rejects.toThrow('LegacyCaptureCleanupRequired')
    expect(execElevatedMock).not.toHaveBeenCalled()
    expect(spawnMock).not.toHaveBeenCalled()
    expect(readFileSync(path, 'utf8')).toBe(body)
  })

  it('allows a stopped legacy hint without migrating its paths (AT-01-009/AT-08-004)', async () => {
    const legacyDir = join(fixturePaths.data, 'traffic-forensics')
    mkdirSync(legacyDir, { recursive: true })
    writeFileSync(join(legacyDir, 'latest-session.json'), JSON.stringify({ running: false, stoppedAt: 1, lastError: null, sessionDir: 'C:/hostile' }))
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    const status = await startTrafficForensicsSession({ mode: 'directVpn', target: 'fixture' })
    expect(status.running).toBe(true)
    expect(status.sessionDir).toContain(join('privileged', 'traffic-forensics'))
    expect(status.cleanupPending).toBe(false)
  })

  it('starts pktmon capture with full packets, ETW providers, and bounded circular logs', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })

    const status = await startTrafficForensicsSession({
      mode: 'localProxy',
      target: '127.0.0.1:10808'
    })

    expect(status.running).toBe(true)
    expect(status.engine).toBe('pktmon')
    expect(status.sidecar?.running).toBe(false)
    expect(status.sidecar?.lastError).toContain('sidecar executable not found')
    expect(execElevatedMock).toHaveBeenCalledTimes(1)
    const commandLine = execElevatedMock.mock.calls[0][0] as string
    const match = commandLine.match(/-File "([^"]+)"/) || commandLine.match(/-File ([^\s]+)/)
    expect(match).toBeTruthy()
    const command = readFileSync(match![1], 'utf-8')
    expect(command).toContain('pktmon start --capture --trace')
    expect(command).toContain('--comp nics')
    expect(command).toContain('--provider Microsoft-Windows-TCPIP --keywords 0x7FFFFFFFFFFFFFFF --level 17')
    expect(command).toContain('--provider Microsoft-Windows-WFP --keywords 0x7FFFFFFFFFFFFFFF --level 255')
    expect(command).toContain('--provider Microsoft-Windows-Winsock-AFD --keywords 0x3FFFFFFFFFFF --level 255')
    expect(command).toContain('--provider Microsoft-Windows-WebIO --keywords 0xFFFFFFFFFFFFFFFF --level 255')
    expect(command).toContain('--pkt-size 0')
    expect(command).toContain('--log-mode circular')
    expect(command).toContain('--file-size 512')
  })

  it('launches cmd sidecar through cmd.exe so packaged Windows builds do not hit spawn EINVAL', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    const sidecarPath = fixturePaths.sidecar
    rmSync(dirname(sidecarPath), { recursive: true, force: true })
    mkdirSync(dirname(sidecarPath), { recursive: true })
    writeFileSync(sidecarPath, '@echo off\r\n')
    process.env.VPNTE_TRAFFIC_FORENSICS_SIDECAR = sidecarPath
    spawnMock.mockReturnValue(mockChildProcess())

    const status = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'poland1'
    })

    expect(status.sidecar?.running).toBe(true)
    expect(spawnMock).toHaveBeenCalledTimes(1)
    expect(spawnMock.mock.calls[0][0]).toBe('cmd.exe')
    expect(spawnMock.mock.calls[0][1][0]).toBe('/d')
    expect(spawnMock.mock.calls[0][1][1]).toBe('/s')
    expect(spawnMock.mock.calls[0][1][2]).toBe('/c')
    expect(spawnMock.mock.calls[0][1][3]).toBe('call')
    expect(spawnMock.mock.calls[0][1][4]).toBe(sidecarPath)
    expect(spawnMock.mock.calls[0][1]).toContain('-Events')
    expect(spawnMock.mock.calls[0][1]).toContain('-Session')
    expect(spawnMock.mock.calls[0][1].join(' ')).not.toContain('""')
  })

  it('persists immediate sidecar exits instead of leaving a zombie running state', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    const sidecarPath = fixturePaths.sidecar
    rmSync(dirname(sidecarPath), { recursive: true, force: true })
    mkdirSync(dirname(sidecarPath), { recursive: true })
    writeFileSync(sidecarPath, '@echo off\r\nexit /b 9009\r\n')
    process.env.VPNTE_TRAFFIC_FORENSICS_SIDECAR = sidecarPath
    const child = mockChildProcess()
    spawnMock.mockReturnValue(child)

    const status = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'poland1'
    })
    child.exitCode = 9009
    child.emit('exit', 9009, null)
    await new Promise(resolve => setTimeout(resolve, 0))

    const refreshed = await getTrafficForensicsStatus()
    const manifest = JSON.parse(readFileSync(join(status.sessionDir!, 'session-manifest.json'), 'utf-8'))
    expect(refreshed.sidecar?.running).toBe(false)
    expect(refreshed.sidecar?.lastError).toContain('sidecar exited code=9009')
    expect(manifest.sidecar.running).toBe(false)
    expect(manifest.sidecar.lastError).toContain('sidecar exited code=9009')
  })

  it('preserves a sidecar exit observed during manifest I/O (AT-08-004, F-198)', async () => {
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    mkdirSync(dirname(fixturePaths.sidecar), { recursive: true })
    writeFileSync(fixturePaths.sidecar, '@echo off\r\n')
    process.env.VPNTE_TRAFFIC_FORENSICS_SIDECAR = fixturePaths.sidecar
    const child = mockChildProcess()
    spawnMock.mockReturnValue(child)
    const started = await startTrafficForensicsSession({ mode: 'directVpn', target: 'fixture' })
    let release!: () => void
    let entered!: () => void
    const gate = new Promise<void>(resolve => { release = resolve })
    const writing = new Promise<void>(resolve => { entered = resolve })
    vi.mocked(generateTrafficForensicsSummary).mockImplementationOnce(async manifest => {
      vi.mocked(ensureElevatedRuntimeDirHardened).mockImplementationOnce(async () => {
        entered()
        await gate
        return { hardened: true, message: 'stubbed' }
      })
      return manifest
    })
    const staging = stageTrafficForensicsArtifacts(fixturePaths.stage)
    await writing
    try { child.emit('exit', 9009, null) } finally { release(); await staging }
    await vi.waitFor(() => {
      const saved = JSON.parse(readFileSync(join(started.sessionDir!, 'session-manifest.json'), 'utf8'))
      expect(saved.sidecar.running).toBe(false)
      expect(saved.sidecar.lastError).toContain('sidecar exited code=9009')
      expect(saved.running).toBe(true)
    })
    expect((await getTrafficForensicsStatus()).sidecar?.running).toBe(false)
  })

  it.each(['exit', 'error'])('ignores a late old-sidecar %s after restart (AT-08-005, F-198)', async event => {
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    mkdirSync(dirname(fixturePaths.sidecar), { recursive: true })
    writeFileSync(fixturePaths.sidecar, '@echo off\r\n')
    process.env.VPNTE_TRAFFIC_FORENSICS_SIDECAR = fixturePaths.sidecar
    const oldChild = mockChildProcess(4242)
    const newChild = mockChildProcess(4243)
    spawnMock.mockReturnValueOnce(oldChild).mockReturnValueOnce(newChild)
    await startTrafficForensicsSession({ mode: 'directVpn', target: 'fixture' })
    const restarted = await restartTrafficForensicsSession()
    if (event === 'exit') oldChild.emit('exit', 9009, null)
    else oldChild.emit('error', new Error('late old-child error'))
    await new Promise(resolve => setTimeout(resolve, 20))
    const status = await getTrafficForensicsStatus()
    const saved = JSON.parse(readFileSync(join(restarted.sessionDir!, 'session-manifest.json'), 'utf8'))
    expect(status.sessionId).toBe(restarted.sessionId)
    expect(status.running).toBe(true)
    expect(status.sidecar?.pid).toBe(4243)
    expect(status.sidecar?.running).toBe(true)
    expect(saved.sidecar.pid).toBe(4243)
  })

  it('keeps provider cleanup pending when the managed sidecar is already gone (AT-08-004, F-198)', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    const sidecarPath = fixturePaths.sidecar
    rmSync(dirname(sidecarPath), { recursive: true, force: true })
    mkdirSync(dirname(sidecarPath), { recursive: true })
    writeFileSync(sidecarPath, '@echo off\r\n')
    process.env.VPNTE_TRAFFIC_FORENSICS_SIDECAR = sidecarPath
    const child = mockChildProcess()
    spawnMock.mockReturnValue(child)

    const status = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'poland1'
    })
    child.exitCode = 0

    const refreshed = await getTrafficForensicsStatus()
    const manifest = JSON.parse(readFileSync(join(status.sessionDir!, 'session-manifest.json'), 'utf-8'))
    expect(refreshed.running).toBe(true)
    expect(refreshed.cleanupPending).toBe(true)
    expect(refreshed.stoppedAt).toBeNull()
    expect(refreshed.sidecar?.running).toBe(false)
    expect(manifest.running).toBe(true)
    expect(manifest.stoppedAt).toBeNull()
  })

  it('does not surface old stopped sessions when deep capture is disabled', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })

    const started = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'poland1'
    })
    await stopTrafficForensicsSession('manual-stop')
    trafficSettingsMock.enabled = false

    const status = await getTrafficForensicsStatus()

    expect(existsSync(started.sessionDir!)).toBe(true)
    expect(status.enabled).toBe(false)
    expect(status.running).toBe(false)
    expect(status.sessionId).toBeNull()
    expect(status.summary).toBeNull()
    expect(status.artifactFiles).toEqual([])
    expect(status.health.artifactCount).toBe(0)
  })

  it('reports packet capture health and sidecar silence in status', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    const sidecarPath = fixturePaths.sidecar
    rmSync(dirname(sidecarPath), { recursive: true, force: true })
    mkdirSync(dirname(sidecarPath), { recursive: true })
    writeFileSync(sidecarPath, '@echo off\r\n')
    process.env.VPNTE_TRAFFIC_FORENSICS_SIDECAR = sidecarPath
    spawnMock.mockReturnValue(mockChildProcess())

    const status = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'poland1'
    })
    writeFileSync(join(status.sessionDir!, 'pktmon.etl'), Buffer.alloc(4096))
    writeFileSync(join(status.sessionDir!, 'events.ndjson'), JSON.stringify({
      provider: 'sidecar',
      category: 'lifecycle',
      event: 'started'
    }) + '\n')

    const refreshed = await getTrafficForensicsStatus()
    expect(refreshed.health.etlBytes).toBe(4096)
    expect(refreshed.health.eventsBytes).toBeGreaterThan(0)
    expect(refreshed.health.sidecarEvents).toBe(1)
    expect(refreshed.health.sidecarWarmingUp).toBe(true)
    expect(refreshed.health.sidecarOnlyLifecycle).toBe(false)
    expect(refreshed.health.warnings).toEqual([])
  })

  it('warns when sidecar stays lifecycle-only after the warmup window', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    const startTime = new Date('2026-06-19T00:00:00.000Z')
    vi.useFakeTimers()
    const sidecarPath = fixturePaths.sidecar
    try {
      vi.setSystemTime(startTime)
      rmSync(dirname(sidecarPath), { recursive: true, force: true })
      mkdirSync(dirname(sidecarPath), { recursive: true })
      writeFileSync(sidecarPath, '@echo off\r\n')
      process.env.VPNTE_TRAFFIC_FORENSICS_SIDECAR = sidecarPath
      spawnMock.mockReturnValue(mockChildProcess())

      const status = await startTrafficForensicsSession({
        mode: 'directVpn',
        target: 'poland1'
      })
      writeFileSync(join(status.sessionDir!, 'pktmon.etl'), Buffer.alloc(4096))
      writeFileSync(join(status.sessionDir!, 'events.ndjson'), JSON.stringify({
        provider: 'sidecar',
        category: 'lifecycle',
        event: 'started'
      }) + '\n')

      vi.setSystemTime(new Date(startTime.getTime() + 31000))
      const refreshed = await getTrafficForensicsStatus()
      expect(refreshed.health.sidecarWarmingUp).toBe(false)
      expect(refreshed.health.sidecarOnlyLifecycle).toBe(true)
      expect(refreshed.health.warnings[0]).toContain('sidecar is running')
    } finally {
      vi.useRealTimers()
    }
  })

  it('counts native ETW data events and clears the lifecycle-only warning', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    const sidecarPath = fixturePaths.sidecar
    rmSync(dirname(sidecarPath), { recursive: true, force: true })
    mkdirSync(dirname(sidecarPath), { recursive: true })
    writeFileSync(sidecarPath, '@echo off\r\n')
    process.env.VPNTE_TRAFFIC_FORENSICS_SIDECAR = sidecarPath
    spawnMock.mockReturnValue(mockChildProcess())

    const status = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'poland1'
    })
    writeFileSync(join(status.sessionDir!, 'pktmon.etl'), Buffer.alloc(4096))
    // A realistic NDJSON stream from the native ferrisetw sidecar: lifecycle +
    // health (non-data) plus tcp/dns/wfp rows (data events).
    const rows = [
      { provider: 'sidecar', category: 'lifecycle', event: 'started', engine: 'ferrisetw-realtime' },
      {
        provider: 'Microsoft-Windows-TCPIP',
        category: 'tcp',
        event: 'observed',
        protocol: 'tcp',
        localAddress: '10.8.0.2',
        localPort: 50123,
        remoteAddress: '142.250.1.2',
        remotePort: 443
      },
      {
        provider: 'Microsoft-Windows-DNS-Client',
        category: 'dns',
        event: 'query',
        queryName: 'youtube.com',
        remoteAddress: '142.250.1.2'
      },
      { provider: 'Microsoft-Windows-WFP', category: 'wfp', event: 'block', reason: 'wfp-block-observed' },
      { provider: 'sidecar', category: 'health', event: 'heartbeat', observedEvents: 3 }
    ]
    writeFileSync(
      join(status.sessionDir!, 'events.ndjson'),
      rows.map(row => JSON.stringify({ ...row, session: status.sessionId, sidecar: 'vpnte-etw-sidecar.exe', ts: '2026-06-19T00:00:00.000Z' })).join('\n') + '\n'
    )

    const refreshed = await getTrafficForensicsStatus()
    expect(refreshed.health.sidecarEvents).toBe(5)
    expect(refreshed.health.sidecarDataEvents).toBe(3)
    expect(refreshed.health.sidecarWarmingUp).toBe(false)
    expect(refreshed.health.sidecarOnlyLifecycle).toBe(false)
    expect(refreshed.health.warnings).toEqual([])
    // Rich diagnostics derived from the native ETW stream for the UI.
    expect(refreshed.health.sidecarEngine).toBe('ferrisetw-realtime')
    expect(refreshed.health.sidecarCategoryCounts).toEqual({ tcp: 1, dns: 1, wfp: 1 })
    expect(refreshed.health.sidecarWfpBlocks).toBe(1)
    expect(refreshed.health.sidecarTopDomains).toEqual([{ name: 'youtube.com', count: 1 }])
    expect(refreshed.health.sidecarTopRemotes).toContainEqual({ address: '142.250.1.2:443', count: 1 })
    expect(refreshed.health.sidecarLastEventAt).toBe(Date.parse('2026-06-19T00:00:00.000Z'))
  })

  it('does not surface a stopped previous-run session\'s stale ETW data as live', async () => {
    await resetForensicsState()
    vi.useFakeTimers()
    const sidecarPath = fixturePaths.sidecar
    try {
      // A session that started long before this process did — i.e. a leftover
      // from a previous launch or an app reinstall (userData survives uninstall).
      vi.setSystemTime(new Date('2020-01-01T00:00:00.000Z'))
      execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
      rmSync(dirname(sidecarPath), { recursive: true, force: true })
      mkdirSync(dirname(sidecarPath), { recursive: true })
      writeFileSync(sidecarPath, '@echo off\r\n')
      process.env.VPNTE_TRAFFIC_FORENSICS_SIDECAR = sidecarPath
      spawnMock.mockReturnValue(mockChildProcess())

      const status = await startTrafficForensicsSession({ mode: 'directVpn', target: 'poland1' })
      writeFileSync(
        join(status.sessionDir!, 'events.ndjson'),
        [
          { provider: 'sidecar', category: 'lifecycle', event: 'started', engine: 'ferrisetw-realtime' },
          { provider: 'Microsoft-Windows-DNS-Client', category: 'dns', event: 'query', queryName: 'youtube.com' },
          { provider: 'Microsoft-Windows-TCPIP', category: 'tcp', event: 'observed', remoteAddress: '142.250.1.2', remotePort: 443 }
        ].map(row => JSON.stringify({ ...row, session: status.sessionId })).join('\n') + '\n'
      )
      await stopTrafficForensicsSession('test-stop')

      const stopped = await getTrafficForensicsStatus()
      expect(stopped.running).toBe(false)
      // The events.ndjson still exists on disk, but because the session predates
      // this process it must NOT be re-read into the live diagnostics digest.
      expect(stopped.health.sidecarDataEvents).toBe(0)
      expect(stopped.health.sidecarCategoryCounts).toEqual({})
      expect(stopped.health.sidecarTopDomains).toEqual([])
      expect(stopped.health.sidecarTopRemotes).toEqual([])
      expect(stopped.health.sidecarEngine).toBeNull()
    } finally {
      vi.useRealTimers()
    }
  })

  it('does not mistake stop artifacts or sidecar exit for provider termination (AT-08-005, F-198)', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    const sidecarPath = fixturePaths.sidecar
    rmSync(dirname(sidecarPath), { recursive: true, force: true })
    mkdirSync(dirname(sidecarPath), { recursive: true })
    writeFileSync(sidecarPath, '@echo off\r\n')
    process.env.VPNTE_TRAFFIC_FORENSICS_SIDECAR = sidecarPath
    const child = mockChildProcess()
    spawnMock.mockReturnValue(child)

    const status = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'poland1'
    })
    child.exitCode = null
    child.killed = true
    child.emit('exit', null, 'SIGTERM')
    writeFileSync(join(status.sessionDir!, 'pktmon-stop.txt'), 'packet monitor is not running')

    const refreshed = await getTrafficForensicsStatus()
    const manifest = JSON.parse(readFileSync(join(status.sessionDir!, 'session-manifest.json'), 'utf-8'))
    expect(refreshed.running).toBe(true)
    expect(refreshed.stoppedAt).toBeNull()
    expect(refreshed.sidecar?.running).toBe(false)
    expect(manifest.running).toBe(true)
    expect(manifest.stoppedAt).toBeNull()
  })

  it('keeps the bundled cmd sidecar as a PowerShell wrapper', () => {
    const wrapper = readFileSync(join(process.cwd(), 'resources', 'vpnte-etw-sidecar.cmd'), 'utf-8')
    expect(wrapper).toContain('vpnte-etw-sidecar.ps1')
    expect(wrapper).toContain('powershell.exe')
    expect(wrapper).toContain('%*')
  })

  it('falls back to netsh trace when pktmon start fails', async () => {
    await resetForensicsState()
    execElevatedMock
      .mockRejectedValueOnce(new Error('pktmon driver unavailable'))
      .mockResolvedValueOnce({ stdout: STOP_ACK, stderr: '' })

    const status = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'profile-1'
    })

    expect(status.running).toBe(true)
    expect(status.engine).toBe('netsh')
    expect(execElevatedMock).toHaveBeenCalledTimes(2)
    expect(execElevatedMock.mock.calls[1][0]).toContain('netsh trace start')
    expect(execElevatedMock.mock.calls[1][0]).toContain('scenario=InternetClient')
    expect(execElevatedMock.mock.calls[1][0]).toContain('capture=yes')
  })

  it('stops capture and stages artifacts for diagnostics export', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })

    const started = await startTrafficForensicsSession({
      mode: 'localProxy',
      target: '127.0.0.1:10808'
    })
    expect(started.sessionDir).toBeTruthy()

    const statusBeforeStop = await getTrafficForensicsStatus()
    expect(statusBeforeStop.running).toBe(true)

    const stopped = await stopTrafficForensicsSession('user-stop')
    expect(stopped.running).toBe(false)
    expect(stopped.schemaVersion).toBe(2)
    expect(stopped.summaryPath).toBeTruthy()
    const stopCommandLine = execElevatedMock.mock.calls[1][0] as string
    const match = stopCommandLine.match(/-File "([^"]+)"/) || stopCommandLine.match(/-File ([^\s]+)/)
    expect(match).toBeTruthy()
    const stopCommand = readFileSync(match![1], 'utf-8')
    expect(stopCommand).toContain('VPNTE_CAPTURE_STOPPED:pktmon')
    expect(stopCommand).toContain('if ($LASTEXITCODE -ne 0)')
    expect(stopCommand.indexOf('VPNTE_CAPTURE_STOPPED:pktmon')).toBeLessThan(stopCommand.indexOf('Invoke-VpnteBestEffort'))
    expect(stopCommand).toContain('pktmon counters --json')
    expect(stopCommand).toContain('pktmon etl2pcap')
    expect(stopCommand).toContain('netsh wfp show netevents')
    expect(stopCommand).toContain('traffic-forensics-stop-errors.txt')
    expect(stopCommand).toContain('exit 0')
    expect(stopCommand).toContain('Get-NetTCPConnection')
    expect(stopCommand).toContain('Get-DnsClientCache')
    expect(stopCommand).toContain('Get-NetRoute')
    expect(stopCommand).toContain('Get-NetFirewallRule')
    expect(stopCommand).not.toContain('--brief')

    const staged = await stageTrafficForensicsArtifacts(fixturePaths.stage)
    expect(staged).toBe(true)
    expect(existsSync(join(fixturePaths.stage, 'traffic-forensics', 'latest-session.json'))).toBe(true)
    expect(existsSync(`${fixturePaths.stage}/traffic-forensics/sessions/${started.sessionId}/session-manifest.json`)).toBe(true)
    expect(existsSync(join(started.sessionDir!, 'summary.json'))).toBe(true)
    expect(existsSync(join(started.sessionDir!, 'timeline.ndjson'))).toBe(true)
    expect(existsSync(join(started.sessionDir!, 'drops.ndjson'))).toBe(true)
    expect(existsSync(join(started.sessionDir!, 'route-snapshots.json'))).toBe(true)

    const manifest = JSON.parse(readFileSync(join(started.sessionDir!, 'session-manifest.json'), 'utf-8'))
    expect(manifest.schemaVersion).toBe(2)
    expect(manifest.appVersion).toBe('1.1.0-test')
    expect(manifest.sidecar.eventsPath).toContain('events.ndjson')
    expect(manifest.sidecar.running).toBe(false)
    expect(manifest.normalizedArtifacts).toContain('summary.json')

    const summary = JSON.parse(readFileSync(join(started.sessionDir!, 'summary.json'), 'utf-8'))
    expect(summary.schemaVersion).toBe(1)
    expect(summary.sessionId).toBe(started.sessionId)
    expect(summary.verdicts.insufficientEvidence).toBe(true)
  })

  it('stages a live pktmon snapshot even while capture is still running', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })

    const started = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'poland2'
    })
    expect(started.running).toBe(true)

    const staged = await stageTrafficForensicsArtifacts(fixturePaths.stage)
    expect(staged).toBe(true)
    expect(execElevatedMock).toHaveBeenCalledTimes(2)
    expect(existsSync(`${fixturePaths.stage}/traffic-forensics/sessions/${started.sessionId}/session-manifest.json`)).toBe(true)

    const execCommand = execElevatedMock.mock.calls[1][0]
    expect(execCommand).toContain('-File')
    expect(execCommand).toContain('live-snapshot.ps1')

    const ps1Path = join(started.sessionDir!, 'live-snapshot.ps1')
    expect(existsSync(ps1Path)).toBe(true)
    const snapshotCommand = readFileSync(ps1Path, 'utf-8')

    expect(snapshotCommand).toContain('Copy-Item -LiteralPath')
    expect(snapshotCommand).toContain('pktmon-live.etl')
    expect(snapshotCommand).toContain('pktmon-live-counters.json')
    expect(snapshotCommand).toContain('pktmon-live-status.txt')
    expect(snapshotCommand).not.toContain('pktmon-live-trace.txt')
    expect(snapshotCommand).not.toContain('pktmon etl2pcap')
    expect(snapshotCommand).toContain('Get-NetUDPEndpoint')
    expect(snapshotCommand).toContain('Get-WinEvent -LogName \'Microsoft-Windows-DNS-Client/Operational\'')
    expect(snapshotCommand).not.toContain('--brief')
    expect(snapshotCommand).toContain('exit 0')
    expect(existsSync(join(started.sessionDir!, 'summary.json'))).toBe(true)
  })

  it('normalizes WFP, DNS, and TCP health signals into evidence-linked artifacts', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })

    const started = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'profile-1'
    })
    expect(started.sessionDir).toBeTruthy()

    writeFileSync(join(started.sessionDir!, 'wfp-netevents.xml'), '<Event><System><EventID>5152</EventID></System><Message>blocked outbound packet to 93.184.216.34:443</Message></Event>')
    writeFileSync(join(started.sessionDir!, 'dnsclient-events-live.txt'), JSON.stringify([
      { TimeCreated: '2026-06-19T00:00:00Z', Message: 'Query example.com resolved to 93.184.216.34 via DNS Client' }
    ]))
    writeFileSync(join(started.sessionDir!, 'tcpip-events-live.txt'), JSON.stringify([
      { TimeCreated: '2026-06-19T00:00:01Z', Message: 'Retransmit timeout observed for 93.184.216.34:443' }
    ]))
    writeFileSync(join(started.sessionDir!, 'nettcp-live.txt'), JSON.stringify([
      {
        LocalAddress: '10.8.0.2',
        LocalPort: 50123,
        RemoteAddress: '93.184.216.34',
        RemotePort: 443,
        State: 'Established',
        OwningProcess: 4242
      }
    ]))
    writeFileSync(join(started.sessionDir!, 'netudp-live.txt'), JSON.stringify([
      {
        LocalAddress: '10.8.0.2',
        LocalPort: 5353,
        OwningProcess: 4243
      }
    ]))

    await stopTrafficForensicsSession('user-stop')

    const summary = JSON.parse(readFileSync(join(started.sessionDir!, 'summary.json'), 'utf-8'))
    const expectedFlowId = 'tcp|10.8.0.2|50123|93.184.216.34|443|4242'
    expect(summary.verdicts.windowsFirewallBlockedTraffic).toBe(true)
    expect(summary.verdicts.timeoutOrPacketLossLikely).toBe(true)
    expect(summary.verdicts.dnsLeakDetected).toBe(false)
    expect(summary.evidence.windowsFirewallBlockedTraffic[0].flowId).toBe(expectedFlowId)
    expect(summary.evidence.timeoutOrPacketLossLikely[0].flowId).toBe(expectedFlowId)
    expect(summary.counts.dnsRecords).toBeGreaterThan(0)
    expect(summary.counts.flows).toBe(2)
    expect(summary.counts.appEvents).toBeGreaterThan(1)
    expect(readFileSync(join(started.sessionDir!, 'drops.ndjson'), 'utf-8')).toContain('wfp-block-observed')
    expect(readFileSync(join(started.sessionDir!, 'dns.ndjson'), 'utf-8')).toContain('example.com')
    expect(readFileSync(join(started.sessionDir!, 'dns.ndjson'), 'utf-8')).toContain(expectedFlowId)
    expect(readFileSync(join(started.sessionDir!, 'tcp-health.ndjson'), 'utf-8')).toContain('timeout-or-retransmit-observed')
    expect(readFileSync(join(started.sessionDir!, 'tcp-health.ndjson'), 'utf-8')).toContain(expectedFlowId)
    expect(readFileSync(join(started.sessionDir!, 'drops.ndjson'), 'utf-8')).toContain(expectedFlowId)
    expect(readFileSync(join(started.sessionDir!, 'flows.ndjson'), 'utf-8')).toContain('93.184.216.34')
    expect(readFileSync(join(started.sessionDir!, 'flows.ndjson'), 'utf-8')).toContain('example.com')
    expect(readFileSync(join(started.sessionDir!, 'flows.ndjson'), 'utf-8')).toContain('wfp-block-observed')
    expect(readFileSync(join(started.sessionDir!, 'flows.ndjson'), 'utf-8')).toContain('timeout-or-retransmit-observed')
    expect(readFileSync(join(started.sessionDir!, 'app-events.ndjson'), 'utf-8')).toContain('tcp-loss-signal')
  })

  it('normalizes pktmon packet and drop counters into packet metrics', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })

    const started = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'profile-1'
    })
    expect(started.sessionDir).toBeTruthy()

    writeFileSync(join(started.sessionDir!, 'pktmon-counters.json'), JSON.stringify({
      adapters: [
        {
          name: 'Wintun Userspace Tunnel',
          packets: 120,
          bytes: 65536,
          errors: 0
        },
        {
          name: 'Intel Wi-Fi',
          packets: 5,
          bytes: 500
        }
      ]
    }))
    writeFileSync(join(started.sessionDir!, 'pktmon-drop-counters.json'), JSON.stringify({
      dropCounters: {
        wfpBlocked: 2,
        checksumDiscarded: 1
      }
    }))

    await stopTrafficForensicsSession('user-stop')

    const summary = JSON.parse(readFileSync(join(started.sessionDir!, 'summary.json'), 'utf-8'))
    const packetMetrics = readFileSync(join(started.sessionDir!, 'packet-metrics.ndjson'), 'utf-8')
    const timeline = readFileSync(join(started.sessionDir!, 'timeline.ndjson'), 'utf-8')
    expect(summary.counts.packetMetrics).toBe(7)
    expect(summary.verdicts.timeoutOrPacketLossLikely).toBe(true)
    expect(summary.evidence.timeoutOrPacketLossLikely.some((ref: any) => ref.artifact === 'pktmon-drop-counters.json')).toBe(true)
    expect(packetMetrics).toContain('"category":"packet"')
    expect(packetMetrics).toContain('"category":"byte"')
    expect(packetMetrics).toContain('"category":"drop"')
    expect(packetMetrics).toContain('dropCounters.wfpBlocked')
    expect(timeline).toContain('"category":"packet-metric"')
  })

  it('ingests sidecar events.ndjson into timeline, records, and verdicts', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })

    const started = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'profile-1'
    })
    expect(started.sessionDir).toBeTruthy()

    writeFileSync(join(started.sessionDir!, 'events.ndjson'), [
      JSON.stringify({
        timestamp: 1780000000200,
        provider: 'Microsoft-Windows-DNS-Client',
        category: 'dns',
        event: 'query',
        queryName: 'leak.example',
        resolver: '8.8.8.8',
        verdict: 'leak-outside-tunnel',
        details: { interfaceAlias: 'Wi-Fi' }
      }),
      JSON.stringify({
        timestamp: 1780000000300,
        provider: 'Microsoft-Windows-WFP',
        category: 'wfp',
        event: 'block',
        reason: 'wfp-block-observed',
        remoteAddress: '203.0.113.55',
        remotePort: 443
      }),
      JSON.stringify({
        timestamp: 1780000000400,
        provider: 'Microsoft-Windows-TCPIP',
        category: 'tcp',
        event: 'reset',
        remoteAddress: '203.0.113.55',
        remotePort: 443
      }),
      JSON.stringify({
        timestamp: 1780000000500,
        provider: 'sidecar',
        category: 'health',
        event: 'buffer-pressure',
        droppedEvents: 7,
        bufferPressure: 0.91
      })
    ].join('\n') + '\n')
    writeFileSync(join(started.sessionDir!, 'nettcp-live.txt'), JSON.stringify([
      {
        LocalAddress: '10.8.0.2',
        LocalPort: 51111,
        RemoteAddress: '203.0.113.55',
        RemotePort: 443,
        State: 'Established',
        OwningProcess: 5252
      }
    ]))

    await stopTrafficForensicsSession('user-stop')

    const summary = JSON.parse(readFileSync(join(started.sessionDir!, 'summary.json'), 'utf-8'))
    const expectedFlowId = 'tcp|10.8.0.2|51111|203.0.113.55|443|5252'
    expect(summary.counts.sidecarEvents).toBe(4)
    expect(summary.verdicts.dnsLeakDetected).toBe(true)
    expect(summary.verdicts.windowsFirewallBlockedTraffic).toBe(true)
    expect(summary.verdicts.remoteResetLikely).toBe(true)
    expect(summary.verdicts.insufficientEvidence).toBe(true)
    expect(summary.evidence.windowsFirewallBlockedTraffic[0].flowId).toBe(expectedFlowId)
    expect(summary.evidence.remoteResetLikely[0].flowId).toBe(expectedFlowId)
    expect(readFileSync(join(started.sessionDir!, 'timeline.ndjson'), 'utf-8')).toContain('Microsoft-Windows-WFP')
    expect(readFileSync(join(started.sessionDir!, 'dns.ndjson'), 'utf-8')).toContain('leak.example')
    expect(readFileSync(join(started.sessionDir!, 'drops.ndjson'), 'utf-8')).toContain(expectedFlowId)
    expect(readFileSync(join(started.sessionDir!, 'tcp-health.ndjson'), 'utf-8')).toContain(expectedFlowId)
    expect(readFileSync(join(started.sessionDir!, 'app-events.ndjson'), 'utf-8')).toContain('sidecar:block')
  })

  it('marks DNS and traffic leaks only when physical-interface evidence exists', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })

    const started = await startTrafficForensicsSession({
      mode: 'localProxy',
      target: '127.0.0.1:10808'
    })
    expect(started.sessionDir).toBeTruthy()

    writeFileSync(join(started.sessionDir!, 'dns-client-servers-live.txt'), JSON.stringify([
      {
        InterfaceAlias: 'Wi-Fi',
        InterfaceIndex: 12,
        ServerAddresses: ['8.8.8.8', '1.1.1.1']
      }
    ]))
    writeFileSync(join(started.sessionDir!, 'routes-live.txt'), JSON.stringify([
      {
        DestinationPrefix: '0.0.0.0/0',
        InterfaceAlias: 'Intel(R) Wi-Fi 6',
        NextHop: '192.168.1.1',
        RouteMetric: 5
      }
    ]))

    await stopTrafficForensicsSession('user-stop')

    const summary = JSON.parse(readFileSync(join(started.sessionDir!, 'summary.json'), 'utf-8'))
    expect(summary.verdicts.dnsLeakDetected).toBe(true)
    expect(summary.verdicts.trafficLeakDetected).toBe(true)
    expect(summary.evidence.dnsLeakDetected[0].artifact).toBe('dns-client-servers-live.txt')
    expect(summary.evidence.trafficLeakDetected[0].artifact).toBe('routes-live.txt')
    expect(readFileSync(join(started.sessionDir!, 'app-events.ndjson'), 'utf-8')).toContain('dns-leak-signal')
    expect(readFileSync(join(started.sessionDir!, 'app-events.ndjson'), 'utf-8')).toContain('traffic-leak-signal')
  })

  it('does not mark the runtime TUN interface as a physical DNS leak', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })

    const userData = fixturePaths.data
    const runtimeDir = join(userData, 'privileged', 'tun-runtime')
    mkdirSync(runtimeDir, { recursive: true })
    writeFileSync(join(runtimeDir, 'sing-box.json'), JSON.stringify({
      inbounds: [
        {
          type: 'tun',
          tag: 'tun-in',
          interface_name: 'Ethernet 5'
        }
      ]
    }))

    const started = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'profile-1'
    })
    expect(started.sessionDir).toBeTruthy()

    writeFileSync(join(started.sessionDir!, 'dns-client-servers-live.txt'), JSON.stringify([
      {
        InterfaceAlias: 'Ethernet 5',
        InterfaceIndex: 51,
        ServerAddresses: ['192.168.250.254']
      }
    ]))

    await stopTrafficForensicsSession('user-stop')

    const summary = JSON.parse(readFileSync(join(started.sessionDir!, 'summary.json'), 'utf-8'))
    expect(summary.verdicts.dnsLeakDetected).toBe(false)
    expect(JSON.stringify(summary.evidence ?? {})).not.toContain('DNS resolver is bound to a physical/non-tunnel interface')
  })

  it('bridges app lifecycle events into summary verdict evidence', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })

    const started = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'profile-1'
    })
    expect(started.sessionDir).toBeTruthy()

    await recordTrafficForensicsAppEvent({
      source: 'tun',
      event: 'sing-box-start-failed',
      details: {
        message: 'sing-box did not start within timeout',
        stderr: 'FATAL dial failed'
      },
      timestamp: 1780000000000
    })
    await recordTrafficForensicsAppEvent({
      source: 'leak-self-test',
      event: 'leak-self-test-result',
      details: {
        physicalAdapterReached: true,
        publicIpMismatch: true,
        dnsLeakDetected: true,
        dnsLeakDetail: 'Cloudflare sees 198.51.100.10, default route is 203.0.113.20',
        defaultRoutePublicIp: '203.0.113.20',
        perAdapter: [
          {
            alias: 'Wi-Fi',
            ipv4: '192.168.1.10',
            publicIpViaThisAdapter: '198.51.100.10',
            curlExitCode: 0,
            curlStderrTail: null
          }
        ],
        summary: 'leak self-test detected physical adapter and DNS leak'
      },
      timestamp: 1780000000100
    })

    await stopTrafficForensicsSession('start-failed')

    const summary = JSON.parse(readFileSync(join(started.sessionDir!, 'summary.json'), 'utf-8'))
    expect(summary.verdicts.singBoxFailureLikely).toBe(true)
    expect(summary.verdicts.trafficLeakDetected).toBe(true)
    expect(summary.verdicts.dnsLeakDetected).toBe(true)
    expect(summary.evidence.singBoxFailureLikely[0].artifact).toBe('app-events-source.ndjson')
    expect(summary.evidence.trafficLeakDetected[0].artifact).toBe('app-events-source.ndjson')
    expect(summary.evidence.dnsLeakDetected[0].artifact).toBe('app-events-source.ndjson')
    expect(readFileSync(join(started.sessionDir!, 'app-events.ndjson'), 'utf-8')).toContain('sing-box-start-failed')
    expect(readFileSync(join(started.sessionDir!, 'app-events.ndjson'), 'utf-8')).toContain('leak-self-test-result')
    expect(readFileSync(join(started.sessionDir!, 'timeline.ndjson'), 'utf-8')).toContain('sing-box-start-failed')
    expect(readFileSync(join(started.sessionDir!, 'timeline.ndjson'), 'utf-8')).toContain('leak-self-test-result')
  })

  /**
   * Finding #5: the export used to copy the session directory verbatim while the
   * bundle manifest claimed redaction. These assert on the STAGED output — the
   * unit tests in forensicsRedaction.test.ts cover the scrubber itself, but only
   * this level catches "the redactor is fine, the export just doesn't call it".
   */
  it('pseudonymizes staged forensics artifacts instead of copying them verbatim', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    const stageDir = fixturePaths.stage

    const started = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'profile-1'
    })
    expect(started.sessionDir).toBeTruthy()

    // Real artifact shapes: a resolved domain, the remote IP it resolved to, the
    // established flow, a connection table and a resolver cache.
    writeFileSync(join(started.sessionDir!, 'dnsclient-events-live.txt'), JSON.stringify([
      { TimeCreated: '2026-06-19T00:00:00Z', Message: 'Query private-tracker.example.com resolved to 93.184.216.34 via DNS Client' }
    ]))
    writeFileSync(join(started.sessionDir!, 'nettcp-live.txt'), JSON.stringify([
      {
        LocalAddress: '10.8.0.2',
        LocalPort: 50123,
        RemoteAddress: '93.184.216.34',
        RemotePort: 443,
        State: 'Established',
        OwningProcess: 4242
      }
    ]))
    writeFileSync(
      join(started.sessionDir!, 'dns-cache-live.txt'),
      'Entry: private-tracker.example.com  Data: 93.184.216.34\nEntry: bank.ru  Data: 77.88.55.66\n'
    )

    await stopTrafficForensicsSession('user-stop')
    const staged = await stageTrafficForensicsArtifacts(stageDir)
    expect(staged).toBe(true)

    const stagedSession = join(stageDir, 'traffic-forensics', 'sessions', started.sessionId!)
    const stagedDns = readFileSync(join(stagedSession, 'dns.ndjson'), 'utf-8')
    const stagedFlows = readFileSync(join(stagedSession, 'flows.ndjson'), 'utf-8')
    const stagedCache = readFileSync(join(stagedSession, 'dns-cache-live.txt'), 'utf-8')

    // Nothing real survives.
    for (const body of [stagedDns, stagedFlows, stagedCache]) {
      expect(body).not.toContain('93.184.216.34')
      expect(body).not.toContain('private-tracker')
      expect(body).not.toContain('77.88.55.66')
    }
    expect(stagedCache).not.toContain('bank.ru')

    // The original session directory is untouched — redaction happens on the
    // copy, so local diagnosis still has the real data.
    expect(readFileSync(join(started.sessionDir!, 'flows.ndjson'), 'utf-8')).toContain('93.184.216.34')

    // ...but the bundle is still diagnosable: one address, one token, everywhere.
    const token = stagedDns.match(/<ip-public-\d+>/)?.[0]
    expect(token).toBeTruthy()
    expect(stagedFlows).toContain(token!)
    expect(stagedCache).toContain(token!)
    // Public suffixes survive so smart-RU analysis is still possible.
    expect(stagedCache).toContain('.ru')
    expect(stagedCache).toContain('.com')
    // The reader is told what happened.
    const notice = readFileSync(join(stageDir, 'traffic-forensics', 'REDACTION.txt'), 'utf-8')
    expect(notice).toContain('<ip-public-N>')
    expect(notice).toContain('*.etl')
  })

  it('never exports raw packet captures, redacted or otherwise', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    const stageDir = fixturePaths.stage

    const started = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'profile-1'
    })

    // Payload-bearing artifacts. There is no way to scrub these, so they must be
    // excluded outright rather than redacted.
    writeFileSync(join(started.sessionDir!, 'pktmon.etl'), 'BINARYPAYLOAD-SECRET')
    writeFileSync(join(started.sessionDir!, 'pktmon-trace.pcapng'), 'BINARYPAYLOAD-SECRET')
    writeFileSync(join(started.sessionDir!, 'pktmon-trace.txt'), 'GET /secret HTTP/1.1')

    await stopTrafficForensicsSession('user-stop')
    await stageTrafficForensicsArtifacts(stageDir)

    const stagedSession = join(stageDir, 'traffic-forensics', 'sessions', started.sessionId!)
    expect(existsSync(join(stagedSession, 'pktmon.etl'))).toBe(false)
    expect(existsSync(join(stagedSession, 'pktmon-trace.pcapng'))).toBe(false)
    expect(existsSync(join(stagedSession, 'pktmon-trace.txt'))).toBe(false)
    // And they are still on disk locally for deliberate manual submission.
    expect(existsSync(join(started.sessionDir!, 'pktmon.etl'))).toBe(true)
  })

  it('never copies bytes through verbatim, even for an unrecognized artifact type', async () => {
    // The failure mode that matters: an artifact type nobody anticipated must
    // default to being scrubbed, not to a raw byte copy. Everything goes through
    // readFile('utf-8') + redact + writeFile, so raw bytes cannot survive — which
    // is what the old `cp()` fallback allowed.
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: STOP_ACK, stderr: '' })
    const stageDir = fixturePaths.stage

    const started = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'profile-1'
    })
    // An extension the redactor has no special handling for, carrying both an
    // address and bytes that are not valid UTF-8.
    writeFileSync(
      join(started.sessionDir!, 'future-artifact.bin'),
      Buffer.concat([Buffer.from('peer 93.184.216.34 '), Buffer.from([0xff, 0xfe, 0x00, 0x81])])
    )

    await stopTrafficForensicsSession('user-stop')
    await stageTrafficForensicsArtifacts(stageDir)

    const stagedSession = join(stageDir, 'traffic-forensics', 'sessions', started.sessionId!)
    const stagedPath = join(stagedSession, 'future-artifact.bin')
    expect(existsSync(stagedPath)).toBe(true)

    const stagedBytes = readFileSync(stagedPath)
    expect(stagedBytes.toString('utf-8')).not.toContain('93.184.216.34')
    expect(stagedBytes.toString('utf-8')).toContain('<ip-public-')
    // Byte-for-byte identity would mean a raw copy slipped through.
    expect(stagedBytes.equals(readFileSync(join(started.sessionDir!, 'future-artifact.bin')))).toBe(false)
  })
})
