import { Readable } from 'stream'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const sendMock = vi.hoisted(() => vi.fn())
const axiosGetMock = vi.hoisted(() => vi.fn())
const axiosPostMock = vi.hoisted(() => vi.fn())

vi.mock('electron', () => ({
  BrowserWindow: {
    getAllWindows: () => [{
      isDestroyed: () => false,
      webContents: { send: sendMock }
    }]
  },
  ipcMain: {
    handle: vi.fn()
  }
}))

vi.mock('axios', () => ({
  default: {
    get: axiosGetMock,
    post: axiosPostMock
  }
}))

vi.mock('electron-store', () => ({
  default: class MockStore {
    private data: Record<string, unknown>
    constructor(options: { defaults?: Record<string, unknown> }) {
      this.data = { ...(options.defaults ?? {}) }
    }
    get(key: string) {
      return this.data[key]
    }
    set(key: string, value: unknown) {
      this.data[key] = value
    }
  }
}))

vi.mock('./appLogger', () => ({
  logEvent: vi.fn()
}))

vi.mock('./tunController', () => ({
  tunController: {
    getStatus: () => ({
      running: true,
      vpnProfileName: 'poland1'
    })
  }
}))

const currentIpMock = vi.hoisted(() => vi.fn())
vi.mock('./ipMonitor', () => ({ ipMonitor: { getCurrentIp: currentIpMock } }))

import { speedTest } from './speedTest'

function streamOfSize(bytes: number): Readable {
  return new Readable({
    objectMode: true,
    read() {
      const chunk = { length: bytes }
      this.push(chunk)
      this.push(null)
    }
  })
}

describe('speedTest', () => {
  beforeEach(() => {
    sendMock.mockClear()
    axiosGetMock.mockReset()
    axiosPostMock.mockReset()
    currentIpMock.mockReset()
    currentIpMock.mockResolvedValue({ ip: null, isLeak: false, vpnIp: null })
  })

  // F-010: a different egress IP must reach the result instead of being swallowed.
  const mockTransfers = (ipifyIp: string | null) => {
    axiosGetMock.mockImplementation(async (url: string) => {
      if (String(url).includes('ipify')) return { data: { ip: ipifyIp } }
      const bytes = Number(new URL(url).searchParams.get('bytes')) || 10 * 1024 * 1024
      return { data: streamOfSize(bytes) }
    })
    axiosPostMock.mockImplementation(async (_url, payloadStream) => {
      if (payloadStream && typeof payloadStream.on === 'function') {
        payloadStream.on('data', () => {})
        await new Promise(r => payloadStream.on('end', r))
      }
      return { status: 200 }
    })
  }

  it('flags egressMismatch when the test IP differs from the current IP', async () => {
    mockTransfers('203.0.113.7')
    currentIpMock.mockResolvedValue({ ip: '198.51.100.9', isLeak: false, vpnIp: null })
    expect((await speedTest.run()).egressMismatch).toBe(true)
  })

  it('does not flag egressMismatch when the IPs match', async () => {
    mockTransfers('203.0.113.7')
    currentIpMock.mockResolvedValue({ ip: '203.0.113.7', isLeak: false, vpnIp: null })
    expect((await speedTest.run()).egressMismatch).toBeUndefined()
  })

  it('uses larger multi-stream rounds on fast links', async () => {
    axiosGetMock.mockImplementation(async (url: string) => {
      const bytes = Number(new URL(url).searchParams.get('bytes')) || 10 * 1024 * 1024
      return { data: streamOfSize(bytes) }
    })
    axiosPostMock.mockImplementation(async (_url, payloadStream, options) => {
      if (payloadStream && typeof payloadStream.on === 'function') {
        payloadStream.on('data', () => {})
        await new Promise(r => payloadStream.on('end', r))
      }
      return { status: 200 }
    })

    const result = await speedTest.run()

    expect(result.profileUsed).toBe('poland1')
    expect(result.downloadMbps).toBeGreaterThan(0)
    expect(result.uploadMbps).toBeGreaterThan(0)
    expect(axiosGetMock).toHaveBeenCalled()
    expect(axiosGetMock.mock.calls.some(([url]) => String(url).includes('bytes=52428800'))).toBe(true)
    expect(axiosPostMock.mock.calls.some(([, , options]) => options?.headers?.['Content-Length'] === String(4 * 1024 * 1024))).toBe(true)
    expect(sendMock).toHaveBeenCalledWith('speed-test:progress', expect.objectContaining({ phase: 'complete', percent: 100 }))
  })
})
