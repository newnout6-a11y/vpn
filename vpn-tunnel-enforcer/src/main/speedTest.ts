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
/** Download endpoints. Tried in order. Each one is ~10 MB. */
const DOWNLOAD_URLS = [
  { url: 'https://speed.cloudflare.com/__down?bytes=10000000', name: 'Cloudflare' },
  { url: 'https://proof.ovh.net/files/10Mb.dat', name: 'OVH' },
  { url: 'https://speedtest.tele2.net/10MB.zip', name: 'Tele2' }
]
/** Cloudflare speed test upload endpoint */
const UPLOAD_URL = 'https://speed.cloudflare.com/__up'
/** Upload payload size in bytes (2 MB) */
const UPLOAD_SIZE = 2 * 1024 * 1024
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
    const download = await measureDownload()
    const downloadMbps = download.mbps
    logEvent('info', 'speed-test', 'download measured', { downloadMbps, server: download.name })

    // Phase 3: Upload
    sendProgress(50, 'upload')
    const uploadMbps = await measureUpload()
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
