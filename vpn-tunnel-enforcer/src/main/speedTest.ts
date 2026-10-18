/**
 * Speed Test Service — download/upload speed measurement through VPN.
 *
 * Responsibilities:
 * - Measure download speed by fetching a test file from a public CDN
 * - Measure upload speed by POSTing random data to a test endpoint
 * - Measure latency (round-trip time) to the test server
 * - Report progress to the renderer via IPC events
 * - Store speed test history in electron-store
 * - Verify VPN is active before allowing a test
 * - Register IPC handlers for SpeedTestChannels
 */

import { ipcMain, BrowserWindow, type IpcMainInvokeEvent } from 'electron'
import axios from 'axios'
import { randomUUID, randomBytes } from 'crypto'
import { Readable } from 'stream'
import Store from './versionedStore'
import { logEvent } from './appLogger'
import { compactForIpcLog } from './ipcLogging'
import { tunController } from './tunController'
import type { SpeedTestResult } from '../shared/ipc-types'
import { IpcFault } from '../shared/ipc-result'
import { operations } from './operations'
import type { OperationLease } from './operationRegistry'

// ─── Persistent Store ────────────────────────────────────────────────────────

interface SpeedTestStore {
  history: SpeedTestResult[]
}

const store = new Store<SpeedTestStore>({
  name: 'speed-test',
  defaults: {
    history: []
  }
})

// ─── Constants ───────────────────────────────────────────────────────────────

/** Latency probe endpoints. Tried in order — first one that responds wins. */
const LATENCY_URLS = [
  'https://speed.cloudflare.com/__down?bytes=0',
  'https://www.google.com/generate_204',
  'https://connectivitycheck.gstatic.com/generate_204',
  'https://detectportal.firefox.com/success.txt',
  'https://1.1.1.1'
]
/** Download endpoints. Tried in order. Cloudflare supports dynamic payload size. */
const DOWNLOAD_URLS = [
  {
    name: 'Cloudflare',
    url: 'https://speed.cloudflare.com/__down?bytes=10000000'
  },
  {
    name: 'OVH',
    url: 'https://proof.ovh.net/files/100Mb.dat'
  },
  {
    name: 'Tele2',
    url: 'https://speedtest.tele2.net/100MB.zip'
  }
]
/** Cloudflare speed test upload endpoint */
const UPLOAD_URL = 'https://speed.cloudflare.com/__up'
const UPLOAD_SIZE = 2 * 1024 * 1024
const DOWNLOAD_PROBE_BYTES = 10 * 1024 * 1024
const DOWNLOAD_FAST_BYTES_PER_STREAM = 50 * 1024 * 1024
const DOWNLOAD_FAST_STREAMS = 6
const DOWNLOAD_FAST_THRESHOLD_MBPS = 80
const UPLOAD_PROBE_BYTES_PER_STREAM = 2 * 1024 * 1024 // 2 MB per stream for probe
const UPLOAD_PROBE_STREAMS = 4 // 4 streams * 2 MB = 8 MB total probe
const UPLOAD_FAST_BYTES_PER_STREAM = 4 * 1024 * 1024 // 4 MB per stream
const UPLOAD_FAST_STREAMS = 20 // 20 streams total = 80 MB. Required to max out Cloudflare HTTP/1.1 upload.
const UPLOAD_FAST_THRESHOLD_MBPS = 40
/** Maximum history entries to keep */
const MAX_HISTORY = 50

// ─── State ───────────────────────────────────────────────────────────────────

// ─── Progress Reporting ──────────────────────────────────────────────────────

let lastReportedPercent = -1
let lastReportedPhase = ''

/**
 * Sends progress events to all renderer windows.
 * Deduplicates calls to prevent flooding the IPC bridge and blocking the
 * Node.js event loop during high-speed multi-stream downloads.
 */
function sendProgress(lease: OperationLease, percent: number, phase: string): void {
  try { lease.assertActive() } catch { return }
  if (percent === lastReportedPercent && phase === lastReportedPhase) return
  lastReportedPercent = percent
  lastReportedPhase = phase

  for (const win of BrowserWindow.getAllWindows()) {
    try { lease.assertActive() } catch { return }
    if (!win.isDestroyed()) {
      win.webContents.send('speed-test:progress', { percent, phase, operationId: lease.operation.operationId })
    }
  }
}

function mbpsFromBytes(bytes: number, startedAt: number): number {
  const elapsed = Math.max((Date.now() - startedAt) / 1000, 0.001)
  const bitsPerSecond = (bytes * 8) / elapsed
  return Math.round((bitsPerSecond / 1_000_000) * 100) / 100
}

function progressPercent(phase: 'download' | 'upload', loaded: number, total: number): number {
  if (total <= 0) return phase === 'download' ? 5 : 55
  const ratio = Math.min(1, Math.max(0, loaded / total))
  return phase === 'download' ? 5 + Math.round(ratio * 45) : 50 + Math.round(ratio * 50)
}

// ─── Latency Measurement ─────────────────────────────────────────────────────

/**
 * Measures round-trip latency to the test server.
 * Tries each LATENCY_URL in order; for the first one with at least one
 * successful ping, performs 3 pings and returns the median. This way, if
 * Cloudflare is blocked but Google's generate_204 still works, we get a
 * useful number instead of failing the whole test.
 */
async function measureLatency(lease: OperationLease): Promise<number> {
  for (const url of LATENCY_URLS) {
    lease.assertActive()
    const pings: number[] = []
    // Warmup ping (discarded) — avoids cold DNS cache miss skewing the median.
    try { await lease.wait(axios.get(url, { signal: lease.signal, timeout: 10000, headers: { 'Cache-Control': 'no-cache' } })) }
    catch { lease.assertActive() }
    for (let i = 0; i < 5; i++) {
      lease.assertActive()
      const start = Date.now()
      try {
        await lease.wait(axios.get(url, {
          signal: lease.signal,
          timeout: 10000,
          headers: { 'Cache-Control': 'no-cache' }
        }))
        pings.push(Date.now() - start)
      } catch {
        lease.assertActive()
        // Skip failed pings — try the next iteration / URL.
      }
    }
    if (pings.length >= 3) {
      pings.sort((a, b) => a - b)
      // Drop min and max, return median of the remaining samples.
      const trimmed = pings.slice(1, -1)
      return trimmed[Math.floor(trimmed.length / 2)]
    } else if (pings.length > 0) {
      pings.sort((a, b) => a - b)
      return pings[Math.floor(pings.length / 2)]
    }
  }

  throw new Error('Не удалось измерить задержку. Проверьте интернет-соединение и VPN.')
}

// ─── Download Speed Measurement ──────────────────────────────────────────────



// ─── Main Test Runner ────────────────────────────────────────────────────────

/**
 * Runs a full speed test (latency + download + upload).
 * Checks VPN status before starting.
 * Returns a SpeedTestResult.
 */
async function readResponseStream(lease: OperationLease, stream: Readable, onChunk: (bytes: number) => void, signal: AbortSignal): Promise<number> {
  const onAbort = () => { stream.destroy(new IpcFault('cancelled')) }
  signal.addEventListener('abort', onAbort, { once: true })
  if (signal.aborted) onAbort()
  return lease.wait((async () => {
    let bytes = 0
    try {
      for await (const chunk of stream) {
        lease.assertActive()
        if (signal.aborted) throw new IpcFault('cancelled')
        bytes += chunk.length
        onChunk(chunk.length)
      }
      return bytes
    } finally { signal.removeEventListener('abort', onAbort) }
  })())
}

function downloadUrl(target: typeof DOWNLOAD_URLS[number], bytes: number, runId: string, streamIndex: number): string {
  if (target.name === 'Cloudflare') {
    return `https://speed.cloudflare.com/__down?bytes=${bytes}&run=${encodeURIComponent(runId)}&stream=${streamIndex}`
  }
  // For static-file endpoints (OVH, Tele2), append a unique cache-buster
  // so each stream gets a separate download. The ?run=&stream= params are
  // ignored by the server but prevent CDN/proxy caching from returning the
  // same response for parallel streams.
  const separator = target.url.includes('?') ? '&' : '?'
  return `${target.url}${separator}cb=${encodeURIComponent(runId)}${streamIndex}`
}

async function downloadOne(lease: OperationLease, url: string, onChunk: (bytes: number) => void, signal: AbortSignal): Promise<number> {
  lease.assertActive()
  let stream: Readable | undefined
  const onAbort = () => { stream?.destroy() }
  signal.addEventListener('abort', onAbort, { once: true })
  try {
    const response = await lease.wait(axios.get(url, {
      signal,
      responseType: 'stream',
      timeout: 180000,
      headers: { 'Cache-Control': 'no-cache' },
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
      validateStatus: (status) => status >= 200 && status < 300
    }).then(response => {
      stream = response.data as Readable
      if (signal.aborted) {
        onAbort()
        throw new IpcFault('cancelled')
      }
      return response
    }))
    return await readResponseStream(lease, response.data as Readable, onChunk, signal)
  } finally {
    signal.removeEventListener('abort', onAbort)
    if (signal.aborted) onAbort()
  }
}

async function measureDownloadRound(lease: OperationLease, target: typeof DOWNLOAD_URLS[number], bytesPerStream: number, streams: number): Promise<number> {
  const runId = randomUUID()
  const expectedBytes = bytesPerStream * streams
  let receivedBytes = 0
  let startedAt = 0
  const round = new AbortController(), signal = AbortSignal.any([lease.signal, round.signal])

  const downloads = Array.from({ length: streams }, (_, index) => {
    const url = downloadUrl(target, bytesPerStream, runId, index)
    return downloadOne(lease, url, (bytes) => {
      if (startedAt === 0) startedAt = Date.now()
      receivedBytes += bytes
      sendProgress(lease, progressPercent('download', receivedBytes, expectedBytes), 'download')
    }, signal)
  })
  try { await Promise.all(downloads) }
  catch (error) {
    round.abort()
    await lease.wait(Promise.allSettled(downloads))
    throw error
  } finally { round.abort() }

  return mbpsFromBytes(receivedBytes, startedAt || Date.now())
}

async function measureAccurateDownload(lease: OperationLease): Promise<{ mbps: number; name: string }> {
  let lastErr: Error | null = null

  for (const target of DOWNLOAD_URLS) {
    try {
      const probeMbps = await measureDownloadRound(lease, target, DOWNLOAD_PROBE_BYTES, 2)
      if (probeMbps <= 0) {
        lastErr = new Error('Empty response from speed test server')
        continue
      }

      if (probeMbps < DOWNLOAD_FAST_THRESHOLD_MBPS) return { mbps: probeMbps, name: target.name }

      const sustainedMbps = await measureDownloadRound(lease, target, DOWNLOAD_FAST_BYTES_PER_STREAM, DOWNLOAD_FAST_STREAMS)
      return { mbps: Math.max(probeMbps, sustainedMbps), name: target.name }
    } catch (err) {
      lease.assertActive()
      const message = err instanceof Error ? err.message : String(err)
      lastErr = err instanceof Error ? err : new Error(message)
      logEvent('warn', 'speed-test', `download endpoint ${target.name} failed, trying next`, { error: message })
    }
  }

  throw new Error(`Failed to measure download speed. All speed test servers are unavailable.${lastErr ? ` Last error: ${lastErr.message}` : ''}`)
}
async function uploadOne(lease: OperationLease, payloadBytes: number, onProgress: (bytes: number) => void): Promise<number> {
  lease.assertActive()
  // Generate random data (not zeros) to prevent compression from inflating
  // the measured throughput. Zeros are highly compressible — if any hop
  // applies transparent compression, fewer bytes travel over the wire while
  // we report the full count, overstating speed.
  const chunks: Buffer[] = []
  const chunkSize = 65536
  let remaining = payloadBytes
  while (remaining > 0) {
    const sz = Math.min(chunkSize, remaining)
    chunks.push(randomBytes(sz))
    remaining -= sz
  }
  const fullPayload = Buffer.concat(chunks)

  let uploadedBytes = 0
  const stream = new Readable({
    read(size) {
      try { lease.assertActive() } catch { this.push(null); return }
      const chunk = Math.min(size || 65536, payloadBytes - uploadedBytes)
      if (chunk > 0) {
        this.push(fullPayload.subarray(uploadedBytes, uploadedBytes + chunk))
        uploadedBytes += chunk
        onProgress(uploadedBytes)
      } else {
        this.push(null)
      }
    }
  })

  const onAbort = () => { stream.destroy() }
  lease.signal.addEventListener('abort', onAbort, { once: true })
  try { await lease.wait(axios.post(UPLOAD_URL, stream, {
    signal: lease.signal,
    timeout: 180000,
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Length': payloadBytes.toString()
    },
    maxBodyLength: Infinity,
    maxContentLength: Infinity
  })) } finally {
    lease.signal.removeEventListener('abort', onAbort)
    stream.destroy()
  }

  return uploadedBytes
}

async function measureUploadRound(lease: OperationLease, bytesPerStream: number, streams: number): Promise<number> {
  const expectedBytes = bytesPerStream * streams
  const uploadedByStream = new Array(streams).fill(0)
  let start = 0

  await Promise.all(Array.from({ length: streams }).map((_, index) => uploadOne(lease, bytesPerStream, (loaded) => {
    if (start === 0 && loaded > 0) start = Date.now()
    uploadedByStream[index] = loaded
    const uploadedBytes = uploadedByStream.reduce((sum, bytes) => sum + bytes, 0)
    sendProgress(lease, progressPercent('upload', uploadedBytes, expectedBytes), 'upload')
  })))

  // Compute Mbps from actual uploaded bytes, not expected — a stalled stream
  // would otherwise overstate throughput.
  const actualUploaded = uploadedByStream.reduce((sum, bytes) => sum + bytes, 0)
  return mbpsFromBytes(actualUploaded, start || Date.now())
}

async function measureAccurateUpload(lease: OperationLease): Promise<number> {
  const probeMbps = await measureUploadRound(lease, UPLOAD_PROBE_BYTES_PER_STREAM, UPLOAD_PROBE_STREAMS)

  if (probeMbps <= 0) {
    throw new Error('Failed to measure upload speed')
  }

  if (probeMbps < UPLOAD_FAST_THRESHOLD_MBPS) return probeMbps

  const sustainedMbps = await measureUploadRound(lease, UPLOAD_FAST_BYTES_PER_STREAM, UPLOAD_FAST_STREAMS)
  return Math.max(probeMbps, sustainedMbps)
}

async function runSpeedTest(options: { signal?: AbortSignal; timeoutMs?: number } = {}): Promise<SpeedTestResult> {
  return operations.run('speed-test', performSpeedTest, options)
}

async function performSpeedTest(lease: OperationLease): Promise<SpeedTestResult> {
  const status = tunController.getStatus()
  if (!status.running) {
    throw new IpcFault('conflict')
  }

  try {
    logEvent('info', 'speed-test', 'starting speed test')
    sendProgress(lease, 0, 'latency')

    // Phase 1: Latency
    const latencyMs = await measureLatency(lease)
    logEvent('info', 'speed-test', 'latency measured', { latencyMs })

    // Phase 2: Download
    sendProgress(lease, 5, 'download')
    const download = await measureAccurateDownload(lease)
    const downloadMbps = download.mbps
    logEvent('info', 'speed-test', 'download measured', { downloadMbps, server: download.name })

    // Phase 3: Upload
    sendProgress(lease, 50, 'upload')
    const uploadMbps = await measureAccurateUpload(lease)
    logEvent('info', 'speed-test', 'upload measured', { uploadMbps })

    // Verify VPN egress IP — if the tunnel is leaking, the test measured
    // the direct connection, not VPN performance. Log a warning.
    // A failed lookup stays non-critical, but a genuine mismatch is recorded on the result so the user sees it (F-010).
    let egressMismatch = false
    try {
      lease.assertActive()
      const ipResp = await lease.wait(axios.get('https://api.ipify.org?format=json', { signal: lease.signal, timeout: 6000 }))
      const testIp = ipResp.data?.ip
      if (testIp) {
        const { ipMonitor } = await lease.wait(import('./ipMonitor'))
        const currentIp = await lease.wait(ipMonitor.getCurrentIp(() => !lease.signal.aborted, lease.signal))
        if (currentIp.ip && testIp !== currentIp.ip) {
          egressMismatch = true
          logEvent('warn', 'speed-test', 'egress IP mismatch: speed test may not have used the active VPN tunnel')
        }
      }
    } catch { lease.assertActive() /* A failed lookup is non-critical; cancellation is terminal. */ }

    lease.assertActive()
    sendProgress(lease, 100, 'complete')

    // Build result
    const result: SpeedTestResult = {
      id: randomUUID(),
      timestamp: Date.now(),
      downloadMbps,
      uploadMbps,
      latencyMs,
      serverName: download.name,
      profileUsed: status.vpnProfileName || 'Unknown',
      ...(egressMismatch ? { egressMismatch } : {})
    }

    // Save to history
    lease.assertActive()
    saveResult(result)

    logEvent('info', 'speed-test', 'speed test completed', result)
    return result
  } catch (err: any) {
    lease.assertActive()
    logEvent('error', 'speed-test', 'speed test failed', { error: err.message || String(err) })
    sendProgress(lease, 0, 'error')
    throw err
  } finally {
    lastReportedPercent = -1
    lastReportedPhase = ''
  }
}

// ─── History Management ──────────────────────────────────────────────────────

/**
 * Saves a speed test result to history, keeping at most MAX_HISTORY entries.
 */
function saveResult(result: SpeedTestResult): void {
  const history = store.get('history') ?? []
  history.unshift(result)

  // Trim to max history size
  if (history.length > MAX_HISTORY) {
    history.length = MAX_HISTORY
  }

  store.set('history', history)
}

/**
 * Returns all stored speed test results.
 */
function getHistory(): SpeedTestResult[] {
  return store.get('history') ?? []
}

// ─── IPC Handlers ────────────────────────────────────────────────────────────

function handleLogged<T>(
  channel: string,
  listener: (event: IpcMainInvokeEvent, ...args: any[]) => Promise<T> | T
): void {
  ipcMain.handle(channel, async (event, ...args) => {
    const started = Date.now()
    logEvent('debug', 'ipc', `${channel} started`, { args: compactForIpcLog(args) })
    try {
      const result = await listener(event, ...args)
      logEvent('debug', 'ipc', `${channel} finished`, { ms: Date.now() - started })
      return result
    } catch (err: any) {
      logEvent('error', 'ipc', `${channel} failed`, { error: err.message || String(err) })
      throw err
    }
  })
}

/**
 * Registers all speed test IPC handlers.
 * Should be called once during app initialization.
 */
export function registerSpeedTestHandlers(): void {
  handleLogged('speed-test:run', async () => {
    return await runSpeedTest()
  })

  handleLogged('speed-test:history', async () => {
    return getHistory()
  })
}

// ─── Exports ─────────────────────────────────────────────────────────────────

export const speedTest = {
  run: runSpeedTest,
  getHistory,
  isRunning: () => operations.isBusy('speed-test'),
  cancel: (operationId: string) => {
    const operation = operations.list().find(item => item.operationId === operationId && item.kind === 'speed-test')
    return operation ? operations.cancel(operationId) : false
  },
  registerHandlers: registerSpeedTestHandlers
}
