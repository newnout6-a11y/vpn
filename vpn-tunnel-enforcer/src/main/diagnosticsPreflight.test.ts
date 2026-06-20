import { describe, it, expect, vi, afterEach } from 'vitest'
import { readFileSync, existsSync } from 'fs'
import { join } from 'path'
import { app } from 'electron'

vi.mock('electron', () => ({
  app: {
    isPackaged: false,
    getPath: vi.fn(),
    getVersion: vi.fn()
  }
}))

vi.mock('./appLogger', () => ({
  logEvent: vi.fn()
}))

vi.mock('./settings', () => ({
  settingsStore: {
    get: vi.fn()
  }
}))

vi.mock('./admin', () => ({
  execElevated: vi.fn()
}))

import {
  sidecarExecutableCandidates,
  sidecarArgs,
  buildPktmonStartScript,
  buildPktmonStopScript,
  buildPktmonLiveSnapshotScript,
  createManifest
} from './trafficForensics'

describe('Diagnostics Preflight', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  describe('1. ETW sidecar executable discovery', () => {
    it('should find the sidecar executable in unpacked development mode', () => {
      // In dev mode, app.isPackaged is false.
      const candidates = sidecarExecutableCandidates()
      // We expect the script to look in `resources/vpnte-etw-sidecar.cmd` or similar.
      // The current implementation uses: join(process.cwd(), 'resources', name)
      const expectedDevPath = join(process.cwd(), 'resources', 'vpnte-etw-sidecar.cmd')
      expect(candidates).toContain(expectedDevPath)
      
      // Let's also check if the file actually exists on disk in our repo!
      expect(existsSync(expectedDevPath)).toBe(true)
    })
  })

  describe('2. Sidecar arguments match PS1 param block', () => {
    it('should pass matching parameters to the PowerShell sidecar', () => {
      // 1. Read the actual PS1 script to find its Param block
      const ps1Path = join(process.cwd(), 'resources', 'vpnte-etw-sidecar.ps1')
      const ps1Content = readFileSync(ps1Path, 'utf-8')
      
      // A naive extraction of parameters defined in the script
      const paramMatches = [...ps1Content.matchAll(/\[[a-z]+\]\$([a-zA-Z]+)/gi)]
      const definedParams = paramMatches.map(m => m[1])
      
      expect(definedParams).toContain('Events')
      expect(definedParams).toContain('Session')
      expect(definedParams).toContain('Providers')

      // 2. Generate arguments from trafficForensics
      const args = sidecarArgs('C:/test/events.ndjson', 'session-123', true)
      
      // 3. Verify that trafficForensics passes `-Events`, `-Session`, `-Providers`
      expect(args).toContain('-Events')
      expect(args).toContain('-Session')
      expect(args).toContain('-Providers')
    })

    it('should have valid PowerShell syntax', async () => {
      // Use real PowerShell to parse the script syntax
      const { exec } = await import('child_process')
      const { promisify } = await import('util')
      const execAsync = promisify(exec)

      const ps1Path = join(process.cwd(), 'resources', 'vpnte-etw-sidecar.ps1')
      expect(existsSync(ps1Path)).toBe(true)

      // Get-Command throws an error if the script contains a syntax error
      const command = `powershell -NoProfile -Command "& { Get-Command -Syntax '${ps1Path}' }"`
      
      try {
        const { stdout } = await execAsync(command)
        expect(stdout).toContain('Events')
        expect(stdout).toContain('Session')
      } catch (err: any) {
        throw new Error(`PowerShell syntax check failed for vpnte-etw-sidecar.ps1: ${err.message}`)
      }
    })
  })

  describe('3. pktmon start script', () => {
    it('should contain all required providers and flags', () => {
      const script = buildPktmonStartScript('C:/test/pktmon.etl', 512)
      
      // Must contain all 4 providers
      expect(script).toContain('Microsoft-Windows-TCPIP')
      expect(script).toContain('Microsoft-Windows-WFP')
      expect(script).toContain('Microsoft-Windows-Winsock-AFD')
      expect(script).toContain('Microsoft-Windows-WebIO')
      
      // Must contain correct flags
      expect(script).toContain('--pkt-size 0')
      expect(script).toContain('--log-mode circular')
      expect(script).toContain('--comp nics')
      expect(script).toContain('--file-size 512')
    })
  })

  describe('4. pktmon stop script', () => {
    it('should generate all expected artifacts', () => {
      const script = buildPktmonStopScript('C:/session', 'C:/session/pktmon.etl')
      
      // Base pktmon artifacts
      expect(script).toContain('pktmon-status.txt')
      expect(script).toContain('pktmon-counters.json')
      expect(script).toContain('pktmon-drop-counters.json')
      
      // Trace extraction
      expect(script).toContain('pktmon-trace.txt')
      expect(script).toContain('pktmon-trace.pcapng')
      
      // WFP
      expect(script).toContain('wfp-netevents.xml')
      expect(script).toContain('wfp-state.xml')
      
      // Errors
      expect(script).toContain('traffic-forensics-stop-errors.txt')
      
      // Telemetry (just checking a few key ones)
      expect(script).toContain('nettcp-stop.txt')
      expect(script).toContain('routes-stop.txt')
      expect(script).toContain('dns-cache-stop.txt')
    })
  })

  describe('5. Live snapshot script', () => {
    it('should cover pktmon-live-* and wfp-live-*', () => {
      const script = buildPktmonLiveSnapshotScript('C:/session', 'C:/session/pktmon.etl')
      
      expect(script).toContain('pktmon-live-status.txt')
      expect(script).toContain('pktmon-live-counters.json')
      expect(script).toContain('pktmon-live-drop-counters.json')
      
      // Must copy ETL instead of stopping it
      expect(script).toContain('pktmon-live.etl')
      expect(script).toContain('Copy-Item')
      
      expect(script).toContain('wfp-live-netevents.xml')
      expect(script).toContain('wfp-live-state.xml')
    })
  })

  describe('6. diagnosticsExport order of operations', () => {
    it('should stage forensics before finalizing app-log.json', () => {
      // We will parse the diagnosticsExport.ts source code to verify the order.
      const exportTsPath = join(process.cwd(), 'src', 'main', 'diagnosticsExport.ts')
      const sourceCode = readFileSync(exportTsPath, 'utf-8')
      
      const stageForensicsIndex = sourceCode.indexOf('stageTrafficForensicsArtifacts(stage)')
      expect(stageForensicsIndex).toBeGreaterThan(-1)
      
      // Look for the code that refreshes logs *after* staging forensics
      const refreshLogsIndex = sourceCode.indexOf('const refreshedLogs = await getFullLogs()')
      expect(refreshLogsIndex).toBeGreaterThan(stageForensicsIndex)
      
      const rewriteAppLogIndex = sourceCode.indexOf('writeFile(join(stage, \'app-log.json\')', refreshLogsIndex)
      expect(rewriteAppLogIndex).toBeGreaterThan(refreshLogsIndex)
    })
  })

  describe('7. Manifest initialization', () => {
    it('should create manifest with correct default state', () => {
      const manifest = createManifest({
        sessionId: 'test-session',
        enabled: true,
        running: true,
        engine: 'pktmon',
        mode: 'directVpn',
        target: 'test',
        startedAt: Date.now(),
        stoppedAt: null,
        maxSizeMb: 512,
        retainSessions: 3,
        stopReason: null,
        lastError: null,
        sessionDir: 'C:/session',
        etlPath: 'C:/session/pktmon.etl'
      })
      
      expect(manifest.schemaVersion).toBe(2) // MANIFEST_SCHEMA_VERSION from trafficForensicsSummary
      expect(manifest.sidecar).toBeDefined()
      expect(manifest.sidecar.running).toBe(false)
      expect(manifest.sidecar.eventsPath).toContain('events.ndjson')
    })
  })
})
