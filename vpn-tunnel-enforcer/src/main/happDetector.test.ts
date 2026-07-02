import { EventEmitter } from 'events'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const fsState = vi.hoisted(() => ({
  hasConfig: false,
  content: ''
}))
const axiosGetMock = vi.hoisted(() => vi.fn())
const createConnectionMock = vi.hoisted(() => vi.fn())
const socksCreateConnectionMock = vi.hoisted(() => vi.fn())
const execMock = vi.hoisted(() => vi.fn())
const openPorts = vi.hoisted(() => new Set<number>())

;(execMock as any)[Symbol.for('nodejs.util.promisify.custom')] = () =>
  Promise.resolve({ stdout: '', stderr: '' })

class FakeSocket extends EventEmitter {
  setTimeout() {
    return this
  }

  destroy() {}

  write() {
    setTimeout(() => {
      this.emit('data', Buffer.from('HTTP/1.1 200 OK\r\n\r\n{"ip":"203.0.113.8"}'))
    }, 0)
  }
}

const fsPromisesMock = vi.hoisted(() => {
  const stat = vi.fn(async () => {
    if (!fsState.hasConfig) {
      const err: any = new Error('not found')
      err.code = 'ENOENT'
      throw err
    }
    return {}
  })
  const readdir = vi.fn(async () => fsState.hasConfig
    ? [{ name: 'config.yaml', isFile: () => true }]
    : [])
  const readFile = vi.fn(async () => fsState.content)
  return { stat, readdir, readFile }
})

vi.mock('fs/promises', () => ({
  ...fsPromisesMock,
  default: fsPromisesMock
}))

vi.mock('net', async (importOriginal) => {
  const actual = await importOriginal<typeof import('net')>()
  return {
    ...actual,
    createConnection: createConnectionMock,
    default: { ...actual, createConnection: createConnectionMock }
  }
})

vi.mock('node:net', async (importOriginal) => {
  const actual = await importOriginal<typeof import('net')>()
  return {
    ...actual,
    createConnection: createConnectionMock,
    default: { ...actual, createConnection: createConnectionMock }
  }
})

vi.mock('child_process', () => ({
  exec: execMock,
  default: { exec: execMock }
}))

vi.mock('axios', () => ({
  default: {
    get: axiosGetMock
  }
}))

vi.mock('socks', () => ({
  SocksClient: {
    createConnection: socksCreateConnectionMock
  }
}))

function installConnectionMock(): void {
  createConnectionMock.mockImplementation((options: { port: number }, onConnect: () => void) => {
    const socket = new FakeSocket()
    setTimeout(() => {
      if (openPorts.has(Number(options.port))) onConnect()
      else socket.emit('error', new Error('closed'))
    }, 0)
    return socket
  })
}

describe('happDetector config and port probing', () => {
  beforeEach(() => {
    vi.resetModules()
    fsState.hasConfig = false
    fsState.content = ''
    openPorts.clear()
    createConnectionMock.mockReset()
    axiosGetMock.mockReset()
    socksCreateConnectionMock.mockReset()
    execMock.mockClear()
    for (const name of ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']) {
      delete process.env[name]
    }
    installConnectionMock()
    socksCreateConnectionMock.mockRejectedValue(new Error('not socks'))
    axiosGetMock.mockRejectedValue(new Error('not an http proxy'))
  })

  it('ignores commented and unrelated ports in config before verifying a proxy candidate', async () => {
    fsState.hasConfig = true
    fsState.content = [
      '# mixed-port: 9999',
      'remote_port: 8888',
      'server: example.com:7777',
      'http-port: 10808'
    ].join('\n')
    openPorts.add(10808)
    axiosGetMock.mockImplementation(async (_url: string, options: any) => {
      if (options.proxy?.port === 10808) return { data: { ip: '203.0.113.10' } }
      throw new Error('unexpected port')
    })
    const { happDetector } = await import('./happDetector')

    const result = await happDetector._detectUncached()

    expect(result).toMatchObject({
      host: '127.0.0.1',
      port: 10808,
      type: 'http',
      verified: true
    })
    expect(axiosGetMock.mock.calls.every(([, options]) => options.proxy?.port !== 9999)).toBe(true)
    expect(axiosGetMock.mock.calls.every(([, options]) => options.proxy?.port !== 8888)).toBe(true)
    expect(axiosGetMock.mock.calls.every(([, options]) => options.proxy?.port !== 7777)).toBe(true)
  })

  it('can discover a verified loopback HTTP proxy on port 443', async () => {
    openPorts.add(443)
    axiosGetMock.mockImplementation(async (_url: string, options: any) => {
      if (options.proxy?.port === 443) return { data: { ip: '203.0.113.20' } }
      throw new Error('unexpected port')
    })
    const { happDetector } = await import('./happDetector')

    const result = await happDetector._detectUncached()

    expect(result).toMatchObject({
      host: '127.0.0.1',
      port: 443,
      type: 'http',
      verified: true
    })
  })
})
