import { spawn, type ChildProcessWithoutNullStreams } from 'child_process'
import { logEvent } from './appLogger'
import { TUN_ADAPTER_ALIAS } from './tunAdapter'

// How often the persistent PowerShell reader samples the adapter counters.
const SAMPLE_INTERVAL_MS = 1000
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
// just keep publishing "running but adapter not found" on a JS timer.
let fallbackTimer: ReturnType<typeof setInterval> | null = null
let adapterName = TUN_ADAPTER_ALIAS
let baseCounters: AdapterCounters | null = null
let previousCounters: AdapterCounters | null = null
let peakDownloadBps = 0
let peakUploadBps = 0
let startedAt: number | null = null

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

function publishAdapterNotFound() {
  publish({
    ...currentStats,
    ts: Date.now(),
    running,
    adapterName,
    adapterFound: false,
    downloadBps: 0,
    uploadBps: 0,
    startedAt
  })
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
  peakDownloadBps = Math.max(peakDownloadBps, downloadBps)
  peakUploadBps = Math.max(peakUploadBps, uploadBps)
  previousCounters = counters

  publish({
    ts: counters.ts,
    running: true,
    adapterName: counters.name,
    adapterFound: true,
    downloadBps,
    uploadBps,
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
  // Dev/test on non-Windows: no Get-NetAdapterStatistics. Keep publishing
  // "running but adapter not found" so start()/stop() semantics are intact.
  if (process.platform !== 'win32') {
    if (!fallbackTimer) {
      fallbackTimer = setInterval(publishAdapterNotFound, SAMPLE_INTERVAL_MS)
    }
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
    startedAt = null
    publish(emptyStats(adapterName))
  },

  getCurrentStats(): TrafficStats {
    return { ...currentStats }
  },

  onStatsChange(callback: (stats: TrafficStats) => void) {
    callbacks.push(callback)
    return () => {
      callbacks = callbacks.filter(cb => cb !== callback)
    }
  }
}
