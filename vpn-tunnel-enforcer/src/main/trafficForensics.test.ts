import { afterEach, describe, expect, it, vi } from 'vitest'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'fs'
import { dirname, join } from 'path'
import { EventEmitter } from 'events'

const execElevatedMock = vi.hoisted(() => vi.fn())
const spawnMock = vi.hoisted(() => vi.fn())
process.env.VPNTE_TRAFFIC_FORENSICS_SIDECAR = '0'

vi.mock('electron', () => ({
  app: {
    getPath: () => 'C:/Users/Redmi/CascadeProjects/vpn/.tmp/vpnte-traffic-forensics',
    getVersion: () => '1.1.0-test',
    isPackaged: false
  }
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

vi.mock('./settings', () => ({
  settingsStore: {
    get: () => ({
      deepTrafficInspectionEnabled: true,
      deepTrafficInspectionMaxSizeMb: 512,
      deepTrafficInspectionRetainSessions: 3
    })
  }
}))

import {
  getTrafficForensicsStatus,
  recordTrafficForensicsAppEvent,
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
    await resetForensicsState()
    execElevatedMock.mockReset()
    spawnMock.mockReset()
    process.env.VPNTE_TRAFFIC_FORENSICS_SIDECAR = '0'
    if (existsSync('C:/Users/Redmi/CascadeProjects/vpn/.tmp/vpnte-traffic-forensics')) {
      rmSync('C:/Users/Redmi/CascadeProjects/vpn/.tmp/vpnte-traffic-forensics', { recursive: true, force: true })
    }
    if (existsSync('C:/Users/Redmi/CascadeProjects/vpn/.tmp/vpnte-traffic-stage')) {
      rmSync('C:/Users/Redmi/CascadeProjects/vpn/.tmp/vpnte-traffic-stage', { recursive: true, force: true })
    }
  })

  it('starts pktmon capture with full packets, ETW providers, and bounded circular logs', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: '', stderr: '' })

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
    execElevatedMock.mockResolvedValue({ stdout: '', stderr: '' })
    const sidecarPath = 'C:/Users/Redmi/CascadeProjects/vpn/.tmp/vpnte-test-sidecar/vpnte-etw-sidecar.cmd'
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
    execElevatedMock.mockResolvedValue({ stdout: '', stderr: '' })
    const sidecarPath = 'C:/Users/Redmi/CascadeProjects/vpn/.tmp/vpnte-test-sidecar/vpnte-etw-sidecar.cmd'
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

  it('clears stale running status when the managed sidecar is already gone', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: '', stderr: '' })
    const sidecarPath = 'C:/Users/Redmi/CascadeProjects/vpn/.tmp/vpnte-test-sidecar/vpnte-etw-sidecar.cmd'
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
    expect(refreshed.running).toBe(false)
    expect(refreshed.stopReason).toBe('zombie-recovery')
    expect(refreshed.sidecar?.running).toBe(false)
    expect(manifest.running).toBe(false)
    expect(manifest.stopReason).toBe('zombie-recovery')
    expect(manifest.sidecar.running).toBe(false)
  })

  it('reports packet capture health and sidecar silence in status', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: '', stderr: '' })
    const sidecarPath = 'C:/Users/Redmi/CascadeProjects/vpn/.tmp/vpnte-test-sidecar/vpnte-etw-sidecar.cmd'
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
    execElevatedMock.mockResolvedValue({ stdout: '', stderr: '' })
    const startTime = new Date('2026-06-19T00:00:00.000Z')
    vi.useFakeTimers()
    const sidecarPath = 'C:/Users/Redmi/CascadeProjects/vpn/.tmp/vpnte-test-sidecar/vpnte-etw-sidecar.cmd'
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
    execElevatedMock.mockResolvedValue({ stdout: '', stderr: '' })
    const sidecarPath = 'C:/Users/Redmi/CascadeProjects/vpn/.tmp/vpnte-test-sidecar/vpnte-etw-sidecar.cmd'
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
  })

  it('clears running status when stop artifacts already exist', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: '', stderr: '' })
    const sidecarPath = 'C:/Users/Redmi/CascadeProjects/vpn/.tmp/vpnte-test-sidecar/vpnte-etw-sidecar.cmd'
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
    expect(refreshed.running).toBe(false)
    expect(refreshed.stopReason).toBe('status-reconciled-stop')
    expect(refreshed.sidecar?.running).toBe(false)
    expect(manifest.running).toBe(false)
    expect(manifest.stopReason).toBe('status-reconciled-stop')
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
      .mockResolvedValueOnce({ stdout: '', stderr: '' })

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
    execElevatedMock.mockResolvedValue({ stdout: '', stderr: '' })

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

    const staged = await stageTrafficForensicsArtifacts('C:/Users/Redmi/CascadeProjects/vpn/.tmp/vpnte-traffic-stage')
    expect(staged).toBe(true)
    expect(existsSync('C:/Users/Redmi/CascadeProjects/vpn/.tmp/vpnte-traffic-stage/traffic-forensics/latest-session.json')).toBe(true)
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
    execElevatedMock.mockResolvedValue({ stdout: '', stderr: '' })

    const started = await startTrafficForensicsSession({
      mode: 'directVpn',
      target: 'poland2'
    })
    expect(started.running).toBe(true)

    const staged = await stageTrafficForensicsArtifacts('C:/Users/Redmi/CascadeProjects/vpn/.tmp/vpnte-traffic-stage')
    expect(staged).toBe(true)
    expect(execElevatedMock).toHaveBeenCalledTimes(2)

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
    execElevatedMock.mockResolvedValue({ stdout: '', stderr: '' })

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
    execElevatedMock.mockResolvedValue({ stdout: '', stderr: '' })

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
    execElevatedMock.mockResolvedValue({ stdout: '', stderr: '' })

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
    execElevatedMock.mockResolvedValue({ stdout: '', stderr: '' })

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

  it('bridges app lifecycle events into summary verdict evidence', async () => {
    await resetForensicsState()
    execElevatedMock.mockResolvedValue({ stdout: '', stderr: '' })

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
})
