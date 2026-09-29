import { ipcMain, type IpcMainInvokeEvent } from 'electron'

const PATCH_MARK = Symbol.for('vpnte.ipc.trusted-boundary.installed')
const MAX_IPC_DEPTH = 12
const MAX_IPC_NODES = 20_000
const MAX_IPC_STRING_LENGTH = 2 * 1024 * 1024
const FORBIDDEN_KEYS = new Set(['__proto__', 'prototype', 'constructor'])

type PatchedIpcMain = typeof ipcMain & {
  [PATCH_MARK]?: boolean
}

function normalizedOrigin(url: string): string | null {
  try {
    return new URL(url).origin
  } catch {
    return null
  }
}

function isPackagedRendererUrl(url: string): boolean {
  if (!url.startsWith('file://')) return false
  try {
    const parsed = new URL(url)
    const pathname = decodeURIComponent(parsed.pathname).replace(/\\/g, '/')
    return pathname.endsWith('/renderer/index.html')
  } catch {
    return false
  }
}

/**
 * Enforces Electron's trusted-renderer boundary for every invoke handler.
 *
 * Security invariants:
 * - only the main frame may invoke privileged main-process APIs;
 * - packaged builds accept only our file:// renderer entry point;
 * - development accepts only the configured Vite renderer origin;
 * - missing/opaque origins fail closed outside unit tests.
 */
export function assertTrustedIpcSender(event: IpcMainInvokeEvent): void {
  const frame = event.senderFrame
  if (!frame) {
    if (process.env.NODE_ENV === 'test') return
    throw new Error('Rejected IPC request: sender frame is unavailable')
  }

  if (frame !== event.sender.mainFrame) {
    throw new Error('Rejected IPC request: subframes are not trusted')
  }

  const frameUrl = frame.url || ''
  const devUrl = process.env.ELECTRON_RENDERER_URL
  if (devUrl) {
    const expectedOrigin = normalizedOrigin(devUrl)
    const actualOrigin = normalizedOrigin(frameUrl)
    if (expectedOrigin && actualOrigin === expectedOrigin) return
    throw new Error('Rejected IPC request: untrusted development origin')
  }

  if (isPackagedRendererUrl(frameUrl)) return
  if (process.env.NODE_ENV === 'test' && (frameUrl === '' || frameUrl === 'about:blank')) return
  throw new Error('Rejected IPC request: untrusted renderer origin')
}

export function assertSafeIpcPayload(value: unknown): void {
  let nodes = 0
  const seen = new Set<object>()

  const visit = (candidate: unknown, depth: number): void => {
    nodes += 1
    if (nodes > MAX_IPC_NODES) throw new Error('Invalid IPC payload: too many values')
    if (depth > MAX_IPC_DEPTH) throw new Error('Invalid IPC payload: nesting is too deep')
    if (
      candidate === null ||
      candidate === undefined ||
      typeof candidate === 'boolean' ||
      typeof candidate === 'number'
    ) return
    if (typeof candidate === 'string') {
      if (candidate.length > MAX_IPC_STRING_LENGTH) throw new Error('Invalid IPC payload: string is too long')
      return
    }
    if (typeof candidate !== 'object') {
      throw new Error(`Invalid IPC payload: unsupported ${typeof candidate} value`)
    }
    if (Buffer.isBuffer(candidate) || candidate instanceof Uint8Array) {
      if (candidate.byteLength > MAX_IPC_STRING_LENGTH) throw new Error('Invalid IPC payload: binary value is too large')
      return
    }
    if (seen.has(candidate)) throw new Error('Invalid IPC payload: cyclic object')
    seen.add(candidate)
    try {
      if (Array.isArray(candidate)) {
        for (const item of candidate) visit(item, depth + 1)
        return
      }
      const prototype = Object.getPrototypeOf(candidate)
      if (prototype !== Object.prototype && prototype !== null) {
        throw new Error('Invalid IPC payload: only plain objects are allowed')
      }
      for (const [key, item] of Object.entries(candidate as Record<string, unknown>)) {
        if (FORBIDDEN_KEYS.has(key)) throw new Error(`Invalid IPC payload: forbidden key ${key}`)
        visit(item, depth + 1)
      }
    } finally {
      seen.delete(candidate)
    }
  }

  visit(value, 0)
}

/**
 * Installs one process-wide guard before feature modules register handlers.
 * This deliberately wraps ipcMain.handle itself so a newly added channel
 * cannot accidentally bypass the boundary by using a local helper.
 */
export function installTrustedIpcBoundary(): void {
  const target = ipcMain as PatchedIpcMain
  if (target[PATCH_MARK]) return

  const originalHandle = ipcMain.handle.bind(ipcMain)
  ipcMain.handle = ((channel: string, listener: Parameters<typeof ipcMain.handle>[1]) => {
    return originalHandle(channel, async (event, ...args) => {
      assertTrustedIpcSender(event)
      assertSafeIpcPayload(args)
      return listener(event, ...args)
    })
  }) as typeof ipcMain.handle

  target[PATCH_MARK] = true
}
