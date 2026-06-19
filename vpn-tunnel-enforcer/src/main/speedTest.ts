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
import type { Readable } from 'stream'
import Store from 'electron-store'
import { logEvent } from './appLogger'
import { tunController } from './tunController'
import type { SpeedTestResult } from '../shared/ipc-types'

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
  'https://detectportal.firefox.com/success.txt'
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
const DOWNLOAD_FAST_STREAMS = 4
const DOWNLOAD_FAST_THRESHOLD_MBPS = 80
const UPLOAD_PROBE_BYTES = 8 * 1024 * 1024
const UPLOAD_FAST_BYTES_PER_STREAM = 16 * 1024 * 1024
const UPLOAD_FAST_STREAMS = 4
const UPLOAD_FAST_THRESHOLD_MBPS = 40
/** Maximum history entries to keep */
const MAX_HISTORY = 50

// ─── State ───────────────────────────────────────────────────────────────────

let testInProgress = false

// ─── Progress Reporting ──────────────────────────────────────────────────────

/**
 * Sends progress events to all renderer windows.
 */
function sendProgress(percent: number, phase: string): void {
  for (const win of BrowserWindow.getAllWindows()) {
    if (!win.isDestroyed()) {
      win.webContents.send('speed-test:progress', { percent, phase })
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
async function measureLatency(): Promise<number> {
  for (const url of LATENCY_URLS) {
    const pings: number[] = []
    for (let i = 0; i < 3; i++) {
      const start = Date.now()
      try {
        await axios.get(url, {
          timeout: 5000,
          headers: { 'Cache-Control': 'no-cache' }
        })
        pings.push(Date.now() - start)
      } catch {
        // Skip failed pings — try the next iteration / URL.
      }
    }
    if (pings.length > 0) {
      pings.sort((a, b) => a - b)
      return pings[Math.floor(pings.length / 2)]
    }
  }

  throw new Error('Не удалось измерить задержку. Проверьте интернет-соединение и VPN.')
}

// ─── Download Speed Measurement ──────────────────────────────────────────────

/**
 * Measures download speed by fetching a test file.
 * Tries each DOWNLOAD_URL in order until one succeeds, so a single blocked
 * CDN doesn't fail the whole test. Reports progress during download.
 * Returns the speed in Mbps along with the name of the server that worked.
 */
async function measureDownload(): Promise<{ mbps: number; name: string }> {
  let lastErr: Error | null = null

  for (const target of DOWNLOAD_URLS) {
    const start = Date.now()
    let receivedBytes = 0

    try {
      const response = await axios.get(target.url, {
        responseType: 'arraybuffer',
        timeout: 30000,
        onDownloadProgress: (progressEvent) => {
          if (progressEvent.total) {
            const percent = Math.round((progressEvent.loaded / progressEvent.total) * 50)
            sendProgress(percent, 'download')
          }
          receivedBytes = progressEvent.loaded
        }
      })

      const elapsed = (Date.now() - start) / 1000 // seconds
      const bytes = response.data.byteLength || receivedBytes

      if (elapsed === 0 || bytes === 0) {
        lastErr = new Error('Сервер вернул пустой ответ')
        continue
      }

      // Convert bytes/sec to Mbps (megabits per second)
      const bitsPerSecond = (bytes * 8) / elapsed
      const mbps = Math.round((bitsPerSecond / 1_000_000) * 100) / 100
      return { mbps, name: target.name }
    } catch (err: any) {
      lastErr = err
      logEvent('warn', 'speed-test', `download endpoint ${target.name} failed, trying next`, { error: err.message || String(err) })
    }
  }

  throw new Error(`Не удалось измерить скорость загрузки. Все тестовые серверы недоступны.${lastErr ? ` Последняя ошибка: ${lastErr.message}` : ''}`)
}

// ─── Upload Speed Measurement ────────────────────────────────────────────────

/**
 * Measures upload speed by POSTing random data.
 * Reports progress during upload.
 * Returns speed in Mbps.
 */
async function measureUpload(): Promise<number> {
  const payload = randomBytes(UPLOAD_SIZE)
  const start = Date.now()

  await axios.post(UPLOAD_URL, payload, {
    timeout: 30000,
    headers: {
      'Content-Type': 'application/octet-stream'
    },
    onUploadProgress: (progressEvent) => {
      if (progressEvent.total) {
        // Upload progress is 50-100% of total test
        const percent = 50 + Math.round((progressEvent.loaded / progressEvent.total) * 50)
        sendProgress(percent, 'upload')
      }
    }
  })

  const elapsed = (Date.now() - start) / 1000 // seconds

  if (elapsed === 0) {
    throw new Error('Не удалось измерить скорость отдачи')
  }

  // Convert bytes/sec to Mbps
  const bitsPerSecond = (UPLOAD_SIZE * 8) / elapsed
  return Math.round((bitsPerSecond / 1_000_000) * 100) / 100
}

// ─── Main Test Runner ────────────────────────────────────────────────────────

/**
 * Runs a full speed test (latency + download + upload).
 * Checks VPN status before starting.
 * Returns a SpeedTestResult.
 */
async function readResponseStream(stream: Readable, onChunk: (bytes: number) => void): Promise<number> {
  return await new Promise((resolve, reject) => {
    let bytes = 0
    stream.on('data', (chunk: Buffer) => {
      bytes += chunk.length
      onChunk(chunk.length)
    })
    stream.on('end', () => resolve(bytes))
    stream.on('error', reject)
  })
}

function downloadUrl(target: typeof DOWNLOAD_URLS[number], bytes: number, runId: string, streamIndex: number): string {
  if (target.name === 'Cloudflare') {
    return `https://speed.cloudflare.com/__down?bytes=${bytes}&run=${encodeURIComponent(runId)}&stream=${streamIndex}`
  }
  const separator = target.url.includes('?') ? '&' : '?'
  return `${target.url}${separator}run=${encodeURIComponent(runId)}&stream=${streamIndex}`
}

async function downloadOne(url: string, onChunk: (bytes: number) => void): Promise<number> {
  const response = await axios.get(url, {
    responseType: 'stream',
    timeout: 45000,
    headers: { 'Cache-Control': 'no-cache' },
    maxContentLength: Infinity,
    maxBodyLength: Infinity,
    validateStatus: (status) => status >= 200 && status < 300
  })
  return await readResponseStream(response.data as Readable, onChunk)
}

async function measureDownloadRound(target: typeof DOWNLOAD_URLS[number], bytesPerStream: number, streams: number): Promise<number> {
  const runId = randomUUID()
  const expectedBytes = bytesPerStream * streams
  let receivedBytes = 0
  let startedAt = 0

  await Promise.all(Array.from({ length: streams }, (_, index) => {
    const url = downloadUrl(target, bytesPerStream, runId, index)
    return downloadOne(url, (bytes) => {
      if (startedAt === 0) startedAt = Date.now()
      receivedBytes += bytes
      sendProgress(progressPercent('download', receivedBytes, expectedBytes), 'download')
    })
  }))

  return mbpsFromBytes(receivedBytes, startedAt || Date.now())
}

async function measureAccurateDownload(): Promise<{ mbps: number; name: string }> {
  let lastErr: Error | null = null

  for (const target of DOWNLOAD_URLS) {
    try {
      const probeMbps = await measureDownloadRound(target, DOWNLOAD_PROBE_BYTES, 2)
      if (probeMbps <= 0) {
        lastErr = new Error('Empty response from speed test server')
        continue
      }

      if (probeMbps < DOWNLOAD_FAST_THRESHOLD_MBPS) return { mbps: probeMbps, name: target.name }

      const sustainedMbps = await measureDownloadRound(target, DOWNLOAD_FAST_BYTES_PER_STREAM, DOWNLOAD_FAST_STREAMS)
      return { mbps: Math.max(probeMbps, sustainedMbps), name: target.name }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      lastErr = err instanceof Error ? err : new Error(message)
      logEvent('warn', 'speed-test', `download endpoint ${target.name} failed, trying next`, { error: message })
    }
  }

  throw new Error(`Failed to measure download speed. All speed test servers are unavailable.${lastErr ? ` Last error: ${lastErr.message}` : ''}`)
}

async function uploadOne(payload: Buffer, onProgress: (bytes: number) => void): Promise<number> {
  await axios.post(UPLOAD_URL, payload, {
    timeout: 30000,
    headers: {
      'Content-Type': 'application/octet-stream'
    },
    maxBodyLength: Infinity,
    maxContentLength: Infinity,
    onUploadProgress: (progressEvent) => {
      onProgress(progressEvent.loaded)
    }
  })
  return payload.length
}

async function measureUploadRound(bytesPerStream: number, streams: number): Promise<number> {
  const payloads = Array.from({ length: streams }, () => randomBytes(bytesPerStream))
  const expectedBytes = bytesPerStream * streams
  const uploadedByStream = new Array(streams).fill(0)
  let start = 0

  await Promise.all(payloads.map((payload, index) => uploadOne(payload, (loaded) => {
    if (start === 0 && loaded > 0) start = Date.now()
    uploadedByStream[index] = loaded
    const uploadedBytes = uploadedByStream.reduce((sum, bytes) => sum + bytes, 0)
    sendProgress(progressPercent('upload', uploadedBytes, expectedBytes), 'upload')
  })))

  return mbpsFromBytes(expectedBytes, start || Date.now())
}

async function measureAccurateUpload(): Promise<number> {
  const probeMbps = await measureUploadRound(UPLOAD_PROBE_BYTES, 1)

  if (probeMbps <= 0) {
    throw new Error('Failed to measure upload speed')
  }

  if (probeMbps < UPLOAD_FAST_THRESHOLD_MBPS) return probeMbps

  const sustainedMbps = await measureUploadRound(UPLOAD_FAST_BYTES_PER_STREAM, UPLOAD_FAST_STREAMS)
  return Math.max(probeMbps, sustainedMbps)
}

async function runSpeedTest(): Promise<SpeedTestResult> {
  // Check if VPN is active
  const status = tunController.getStatus()
  if (!status.running) {
    throw new Error('VPN не подключён. Подключите VPN перед запуском теста скорости.')
  }

  if (testInProgress) {
    throw new Error('Тест скорости уже выполняется')
  }

  testInProgress = true

  try {
    logEvent('info', 'speed-test', 'starting speed test')
    sendProgress(0, 'latency')

    // Phase 1: Latency
    const latencyMs = await measureLatency()
    logEvent('info', 'speed-test', 'latency measured', { latencyMs })

    // Phase 2: Download
    sendProgress(5, 'download')
    const download = await measureAccurateDownload()
    const downloadMbps = download.mbps
    logEvent('info', 'speed-test', 'download measured', { downloadMbps, server: download.name })

    // Phase 3: Upload
    sendProgress(50, 'upload')
    const uploadMbps = await measureAccurateUpload()
    logEvent('info', 'speed-test', 'upload measured', { uploadMbps })

    sendProgress(100, 'complete')

    // Build result
    const result: SpeedTestResult = {
      id: randomUUID(),
      timestamp: Date.now(),
      downloadMbps,
      uploadMbps,
      latencyMs,
      serverName: download.name,
      profileUsed: status.vpnProfileName || 'Unknown'
    }

    // Save to history
    saveResult(result)

    logEvent('info', 'speed-test', 'speed test completed', result)
    return result
  } catch (err: any) {
    logEvent('error', 'speed-test', 'speed test failed', { error: err.message || String(err) })
    sendProgress(0, 'error')
    throw err
  } finally {
    testInProgress = false
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
    logEvent('debug', 'ipc', `${channel} started`, { args })
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
  isRunning: () => testInProgress,
  registerHandlers: registerSpeedTestHandlers
}
