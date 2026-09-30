import { afterEach, describe, expect, it, vi } from 'vitest'

vi.mock('electron', () => ({
  ipcMain: {
    handle: vi.fn()
  }
}))

import { assertSafeIpcPayload, assertTrustedIpcSender, registerTrustedRenderer } from './ipcSecurity'

const entry = 'file:///C:/Program%20Files/VPNTunnel/resources/app.asar/out/renderer/index.html'
function event(url: string, sameFrame = true, registered = true): any {
  const mainFrame = { url }
  const sender = { mainFrame }
  if (registered) registerTrustedRenderer(sender as any, process.env.NODE_ENV === 'development' ? process.env.ELECTRON_RENDERER_URL! : entry, process.env.NODE_ENV === 'development')
  return { senderFrame: sameFrame ? mainFrame : { url }, sender }
}

describe('trusted IPC boundary (AT-01-003)', () => {
  const previousDevUrl = process.env.ELECTRON_RENDERER_URL
  const previousNodeEnv = process.env.NODE_ENV

  afterEach(() => {
    if (previousDevUrl === undefined) delete process.env.ELECTRON_RENDERER_URL
    else process.env.ELECTRON_RENDERER_URL = previousDevUrl
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV
    else process.env.NODE_ENV = previousNodeEnv
  })

  it('accepts the packaged main renderer frame', () => {
    delete process.env.ELECTRON_RENDERER_URL
    process.env.NODE_ENV = 'production'
    expect(() => assertTrustedIpcSender(event('file:///C:/Program%20Files/VPNTunnel/resources/app.asar/out/renderer/index.html'))).not.toThrow()
  })

  it('rejects a hostile file renderer and every subframe', () => {
    delete process.env.ELECTRON_RENDERER_URL
    process.env.NODE_ENV = 'production'
    expect(() => assertTrustedIpcSender(event('file:///C:/Users/Public/hostile.html'))).toThrow(/untrusted renderer origin/)
    expect(() => assertTrustedIpcSender(event('file:///C:/app/renderer/index.html', false))).toThrow(/subframes/)
    expect(() => assertTrustedIpcSender(event('file:///C:/Users/Public/renderer/index.html'))).toThrow(/untrusted renderer origin/)
    expect(() => assertTrustedIpcSender(event(entry, true, false))).toThrow(/unregistered/)
    expect(() => assertTrustedIpcSender(event(entry + '?untrusted=1'))).toThrow(/untrusted renderer origin/)
    expect(() => assertTrustedIpcSender(event(entry + '#/settings'))).not.toThrow()
  })

  it('pins development IPC to the configured origin', () => {
    process.env.ELECTRON_RENDERER_URL = 'http://127.0.0.1:5173'
    process.env.NODE_ENV = 'development'
    expect(() => assertTrustedIpcSender(event('http://127.0.0.1:5173/settings'))).not.toThrow()
    expect(() => assertTrustedIpcSender(event('http://localhost:5173/settings'))).toThrow(/untrusted development origin/)
  })
})

describe('generic IPC payload envelope (AT-01-004)', () => {
  it.each([NaN, Infinity, -Infinity])('rejects non-finite numbers before dispatch: %s', value => {
    expect(() => assertSafeIpcPayload({ nested: [value] })).toThrow(/finite/)
  })
  it('accepts bounded structured-clone data', () => {
    expect(() => assertSafeIpcPayload([{ id: 'profile-1', options: { enabled: true } }])).not.toThrow()
  })

  it('rejects dangerous prototypes, unsupported values and deep payloads', () => {
    expect(() => assertSafeIpcPayload(new Date())).toThrow(/plain objects/)
    expect(() => assertSafeIpcPayload(Symbol('hostile'))).toThrow(/unsupported symbol/)
    let value: unknown = 'leaf'
    for (let index = 0; index < 20; index += 1) value = { child: value }
    expect(() => assertSafeIpcPayload(value)).toThrow(/nesting is too deep/)
  })
})
