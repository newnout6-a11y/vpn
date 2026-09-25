import { spawn, type ChildProcessWithoutNullStreams } from 'child_process'
import { logEvent } from './appLogger'
import { TUN_ADAPTER_ALIAS } from './tunAdapter'

// How often the persistent PowerShell reader samples the adapter counters.
const SAMPLE_INTERVAL_MS = 1000
const SMOOTHING_ALPHA = 0.35
const BURSTINESS_WINDOW_SIZE = 5
// Backoff before respawning the reader after an unexpected exit. Kept well
// above SAMPLE_INTERVAL_MS so a broken PowerShell can't turn into a tight
// spawn loop (the very thing this module was rewritten to avoid).
const RESPAWN_BACKOFF_MS = 3000

export interface TrafficStats {
  ts: number
  running: boolean
  adapterName: string
  adapterFound: boolean
  downloadBps: number
  uploadBps: number
  smoothedDownloadBps: number
  smoothedUploadBps: number
  downloadBurstinessPct: number
  uploadBurstinessPct: number
  totalDownloadBytes: number
  totalUploadBytes: number
  sessionDownloadBytes: number
  sessionUploadBytes: number
  peakDownloadBps: number
  peakUploadBps: number
  startedAt: number | null
}

interface AdapterCounters {
  found: boolean
  name: string
  receivedBytes: number
  sentBytes: number
  ts: number
}

function emptyStats(adapterName = TUN_ADAPTER_ALIAS): TrafficStats {
  return {
    ts: Date.now(),
    running: false,
    adapterName,
    adapterFound: false,
    downloadBps: 0,
    uploadBps: 0,
    smoothedDownloadBps: 0,
    smoothedUploadBps: 0,
    downloadBurstinessPct: 0,
    uploadBurstinessPct: 0,
    totalDownloadBytes: 0,
    totalUploadBytes: 0,
    sessionDownloadBytes: 0,
    sessionUploadBytes: 0,
    peakDownloadBps: 0,
    peakUploadBps: 0,
    startedAt: null
  }
}

let currentStats = emptyStats()
let callbacks: Array<(stats: TrafficStats) => void> = []
// The monitor is "running" between start() and stop(), independent of whether
// the PowerShell reader is momentarily alive (it may be respawning).
let running = false
// Persistent PowerShell reader. We keep ONE process alive for the whole
// session and read a counter sample per second off its stdout, instead of
// spawning a fresh powershell.exe every second (process-creation cost that
// dominated CPU on long-running connections).
let readerProc: ChildProcessWithoutNullStreams | null = null
let readerStdoutBuf = ''
let respawnTimer: ReturnType<typeof setTimeout> | null = null
// Non-Windows dev/test fallback: there is no Get-NetAdapterStatistics, so we
// publish a neutral no-adapter state on a JS timer without pretending the TUN
// interface is running.
let fallbackTimer: ReturnType<typeof setInterval> | null = null
let adapterName = TUN_ADAPTER_ALIAS
let baseCounters: AdapterCounters | null = null
let previousCounters: AdapterCounters | null = null
let peakDownloadBps = 0
let peakUploadBps = 0
let smoothedDownloadBps = 0
let smoothedUploadBps = 0
let downloadSamples: number[] = []
let uploadSamples: number[] = []
let startedAt: number | null = null
let lastTrafficAt = 0

function encodedPowerShell(script: string): string {
  const prelude =
    '$ProgressPreference="SilentlyContinue";' +
    '$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();' +
    '[Console]::InputEncoding=[System.Text.UTF8Encoding]::new();'
  return Buffer.from(prelude + script, 'utf16le').toString('base64')
}

function notify(stats: TrafficStats) {
  callbacks.forEach(cb => cb(stats))
}

function publish(stats: TrafficStats) {
  currentStats = stats
  notify(stats)
}

function publishAdapterNotFound(runningOverride = running) {
  smoothedDownloadBps = 0
  smoothedUploadBps = 0
  downloadSamples = []
  uploadSamples = []
  publish({
    ...currentStats,
    ts: Date.now(),
    running: runningOverride,
    adapterName,
    adapterFound: false,
    downloadBps: 0,
    uploadBps: 0,
    smoothedDownloadBps: 0,
    smoothedUploadBps: 0,
    downloadBurstinessPct: 0,
    uploadBurstinessPct: 0,
    startedAt
  })
}

/**
 * Keep the raw counter delta for diagnostics, but make the number shown in
 * the UI resistant to a single buffered burst. The first sample establishes
 * the level and subsequent samples use a short EMA.
 */
export function smoothTrafficRate(previous: number, current: number, alpha = SMOOTHING_ALPHA): number {
  if (!Number.isFinite(previous) || previous <= 0) return Math.max(0, current)
  const safeAlpha = Math.min(1, Math.max(0.01, alpha))
  return Math.max(0, previous + safeAlpha * (current - previous))
}

/** Relative standard deviation of the recent raw samples, in percent. */
export function calculateBurstiness(samples: number[]): number {
  if (samples.length < 2) return 0
  const finite = samples.filter(value => Number.isFinite(value) && value >= 0)
  if (finite.length < 2) return 0
  const mean = finite.reduce((sum, value) => sum + value, 0) / finite.length
  if (mean <= 0) return 0
  const variance = finite.reduce((sum, value) => sum + (value - mean) ** 2, 0) / finite.length
  return Math.round(Math.min(999, (Math.sqrt(variance) / mean) * 100))
}

function rememberSample(samples: number[], value: number): number[] {
  return [...samples, value].slice(-BURSTINESS_WINDOW_SIZE)
}

// Turn one counter sample into a published TrafficStats update. Mirrors the
// previous poll() math exactly — the only change is where the samples come
// from (a persistent reader stream instead of a per-second PowerShell spawn).
function processCounters(counters: AdapterCounters) {
  if (!counters.found) {
    publishAdapterNotFound()
    return
  }

  if (
    !baseCounters ||
    !previousCounters ||
    counters.receivedBytes < previousCounters.receivedBytes ||
    counters.sentBytes < previousCounters.sentBytes
  ) {
    baseCounters = counters
    previousCounters = counters
    smoothedDownloadBps = 0
    smoothedUploadBps = 0
    downloadSamples = []
    uploadSamples = []
    publish({
      ...emptyStats(counters.name),
      ts: counters.ts,
      running: true,
      adapterFound: true,
      totalDownloadBytes: counters.receivedBytes,
      totalUploadBytes: counters.sentBytes,
      startedAt
    })
    return
  }

  const seconds = Math.max((counters.ts - previousCounters.ts) / 1000, 0.001)
  const downloadBps = Math.max(0, (counters.receivedBytes - previousCounters.receivedBytes) / seconds)
  const uploadBps = Math.max(0, (counters.sentBytes - previousCounters.sentBytes) / seconds)
  if (counters.receivedBytes > previousCounters.receivedBytes || counters.sentBytes > previousCounters.sentBytes) {
    lastTrafficAt = counters.ts || Date.now()
  }
  peakDownloadBps = Math.max(peakDownloadBps, downloadBps)
  peakUploadBps = Math.max(peakUploadBps, uploadBps)
  smoothedDownloadBps = smoothTrafficRate(smoothedDownloadBps, downloadBps)
  smoothedUploadBps = smoothTrafficRate(smoothedUploadBps, uploadBps)
  downloadSamples = rememberSample(downloadSamples, downloadBps)
  uploadSamples = rememberSample(uploadSamples, uploadBps)
  previousCounters = counters

  publish({
    ts: counters.ts,
    running: true,
    adapterName: counters.name,
    adapterFound: true,
    downloadBps,
    uploadBps,
    smoothedDownloadBps,
    smoothedUploadBps,
    downloadBurstinessPct: calculateBurstiness(downloadSamples),
    uploadBurstinessPct: calculateBurstiness(uploadSamples),
    totalDownloadBytes: counters.receivedBytes,
    totalUploadBytes: counters.sentBytes,
    sessionDownloadBytes: Math.max(0, counters.receivedBytes - baseCounters.receivedBytes),
    sessionUploadBytes: Math.max(0, counters.sentBytes - baseCounters.sentBytes),
    peakDownloadBps,
    peakUploadBps,
    startedAt
  })
}

function handleReaderLine(line: string) {
  const raw = line.trim()
  if (!raw) return
  try {
    const parsed = JSON.parse(raw)
    processCounters({
      found: Boolean(parsed.Found),
      name: String(parsed.Name || adapterName),
      receivedBytes: Number(parsed.ReceivedBytes) || 0,
      sentBytes: Number(parsed.SentBytes) || 0,
      ts: Date.now()
    })
  } catch {
    // Non-JSON noise (e.g. a stray PowerShell warning). Ignore the line.
  }
}

// PowerShell that samples the adapter once per second and prints one compact
// JSON line per sample, forever. We keep this single process alive for the
// whole session rather than paying powershell.exe startup ~60 times a minute.
function buildReaderScript(name: string): string {
  const safeName = name.replace(/'/g, "''")
  return `
$ErrorActionPreference='SilentlyContinue'
$adapterName='${safeName}'
while ($true) {
  $stats = Get-NetAdapterStatistics -Name $adapterName -ErrorAction SilentlyContinue
  if ($null -eq $stats) {
    $row = [pscustomobject]@{Found=$false;Name=$adapterName;ReceivedBytes=0;SentBytes=0}
  } else {
    $row = [pscustomobject]@{Found=$true;Name=$stats.Name;ReceivedBytes=[double]$stats.ReceivedBytes;SentBytes=[double]$stats.SentBytes}
  }
  [Console]::Out.WriteLine(($row | ConvertTo-Json -Compress))
  [Console]::Out.Flush()
  Start-Sleep -Milliseconds ${SAMPLE_INTERVAL_MS}
}
`
}

function clearRespawnTimer() {
  if (respawnTimer) {
    clearTimeout(respawnTimer)
    respawnTimer = null
  }
}

function spawnReader() {
  // Dev/test on non-Windows: no Get-NetAdapterStatistics. Keep publishing a
  // neutral no-adapter state so dev UIs do not show a false live tunnel.
  if (process.platform !== 'win32') {
    if (!fallbackTimer) {
      fallbackTimer = setInterval(() => publishAdapterNotFound(false), SAMPLE_INTERVAL_MS)
    }
    publishAdapterNotFound(false)
    return
  }

  clearRespawnTimer()
  readerStdoutBuf = ''
  let proc: ChildProcessWithoutNullStreams
  try {
    proc = spawn(
      'powershell',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encodedPowerShell(buildReaderScript(adapterName))],
      { windowsHide: true }
    )
  } catch (err) {
    logEvent('warn', 'traffic', 'failed to spawn traffic counter reader', err)
    scheduleRespawn()
    return
  }
  readerProc = proc

  proc.stdout.setEncoding('utf8')
  proc.stdout.on('data', (chunk: string) => {
    readerStdoutBuf += chunk
    let nl: number
    while ((nl = readerStdoutBuf.indexOf('\n')) >= 0) {
      const line = readerStdoutBuf.slice(0, nl)
      readerStdoutBuf = readerStdoutBuf.slice(nl + 1)
      handleReaderLine(line)
    }
    // Guard against an unbounded buffer if a newline never arrives.
    if (readerStdoutBuf.length > 64 * 1024) readerStdoutBuf = ''
  })
  proc.on('error', (err) => {
    logEvent('warn', 'traffic', 'traffic counter reader errored', err)
  })
  proc.on('exit', (code, signal) => {
    if (readerProc === proc) readerProc = null
    // Only respawn if the monitor is still meant to be running and we didn't
    // kill it ourselves in stop().
    if (running) {
      logEvent('warn', 'traffic', 'traffic counter reader exited; will respawn', { code, signal })
      scheduleRespawn()
    }
  })
}

function scheduleRespawn() {
  if (!running || respawnTimer) return
  respawnTimer = setTimeout(() => {
    respawnTimer = null
    if (running) spawnReader()
  }, RESPAWN_BACKOFF_MS)
}

function stopReader() {
  clearRespawnTimer()
  if (fallbackTimer) {
    clearInterval(fallbackTimer)
    fallbackTimer = null
  }
  if (readerProc) {
    const proc = readerProc
    readerProc = null
    try {
      proc.kill()
    } catch {
      // already gone
    }
  }
  readerStdoutBuf = ''
}

export const trafficMonitor = {
  start(name = TUN_ADAPTER_ALIAS) {
    if (running) return
    running = true
    adapterName = name
    startedAt = Date.now()
    baseCounters = null
    previousCounters = null
    peakDownloadBps = 0
    peakUploadBps = 0
    smoothedDownloadBps = 0
    smoothedUploadBps = 0
    downloadSamples = []
    uploadSamples = []
    publish({ ...emptyStats(adapterName), running: true, startedAt })
    spawnReader()
  },

  stop() {
    running = false
    stopReader()
    baseCounters = null
    previousCounters = null
    peakDownloadBps = 0
    peakUploadBps = 0
    smoothedDownloadBps = 0
    smoothedUploadBps = 0
    downloadSamples = []
    uploadSamples = []
    startedAt = null
    publish(emptyStats(adapterName))
  },

  getCurrentStats(): TrafficStats {
    return { ...currentStats }
  },

  getLastTrafficAt(): number {
    return lastTrafficAt
  },

  onStatsChange(callback: (stats: TrafficStats) => void) {
    callbacks.push(callback)
    return () => {
      callbacks = callbacks.filter(cb => cb !== callback)
    }
  }
}
