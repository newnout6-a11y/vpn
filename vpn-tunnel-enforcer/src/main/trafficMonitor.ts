import { exec as execCb } from 'child_process'
import { promisify } from 'util'
import { logEvent } from './appLogger'
import { TUN_ADAPTER_ALIAS } from './tunAdapter'

const exec = promisify(execCb)

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
let intervalId: ReturnType<typeof setInterval> | null = null
let polling = false
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

async function readAdapterCounters(name: string): Promise<AdapterCounters | null> {
  if (process.platform !== 'win32') {
    return {
      found: false,
      name,
      receivedBytes: 0,
      sentBytes: 0,
      ts: Date.now()
    }
  }

  const safeName = name.replace(/'/g, "''")
  const script = `
$adapterName='${safeName}';
$stats=Get-NetAdapterStatistics -Name $adapterName -ErrorAction SilentlyContinue;
if ($null -eq $stats) {
  $row = [pscustomobject]@{Found=$false;Name=$adapterName;ReceivedBytes=0;SentBytes=0}
} else {
  $row = [pscustomobject]@{Found=$true;Name=$stats.Name;ReceivedBytes=[double]$stats.ReceivedBytes;SentBytes=[double]$stats.SentBytes}
}
$row | ConvertTo-Json -Compress
`
  const { stdout } = await exec(
    `powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand ${encodedPowerShell(script)}`,
    {
      windowsHide: true,
      timeout: 5000,
      maxBuffer: 1024 * 1024,
      encoding: 'utf8'
    }
  )
  const raw = stdout.trim()
  if (!raw) return null
  const parsed = JSON.parse(raw)
  return {
    found: Boolean(parsed.Found),
    name: String(parsed.Name || name),
    receivedBytes: Number(parsed.ReceivedBytes) || 0,
    sentBytes: Number(parsed.SentBytes) || 0,
    ts: Date.now()
  }
}

function notify(stats: TrafficStats) {
  callbacks.forEach(cb => cb(stats))
}

function publish(stats: TrafficStats) {
  currentStats = stats
  notify(stats)
}

async function poll() {
  if (polling) return
  polling = true
  try {
    const counters = await readAdapterCounters(adapterName)
    if (!counters || !counters.found) {
      publish({
        ...currentStats,
        ts: Date.now(),
        running: intervalId !== null,
        adapterName,
        adapterFound: false,
        downloadBps: 0,
        uploadBps: 0,
        startedAt
      })
      return
    }

    if (!baseCounters || !previousCounters || counters.receivedBytes < previousCounters.receivedBytes || counters.sentBytes < previousCounters.sentBytes) {
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
  } catch (err) {
    logEvent('warn', 'traffic', 'traffic stats polling failed', err)
    publish({
      ...currentStats,
      ts: Date.now(),
      running: intervalId !== null,
      adapterFound: false,
      downloadBps: 0,
      uploadBps: 0,
      startedAt
    })
  } finally {
    polling = false
  }
}

export const trafficMonitor = {
  start(name = TUN_ADAPTER_ALIAS) {
    if (intervalId) return
    adapterName = name
    startedAt = Date.now()
    baseCounters = null
    previousCounters = null
    peakDownloadBps = 0
    peakUploadBps = 0
    publish({ ...emptyStats(adapterName), running: true, startedAt })
    void poll()
    intervalId = setInterval(() => void poll(), 1000)
  },

  stop() {
    if (intervalId) {
      clearInterval(intervalId)
      intervalId = null
    }
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
