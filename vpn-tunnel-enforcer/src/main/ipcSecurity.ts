import { ipcMain, type IpcMainInvokeEvent, type WebContents } from 'electron'
import * as electron from 'electron'

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

const trustedRenderers = new WeakMap<WebContents, { entryUrl: string; devOrigin: string | null }>()
export function registerTrustedRenderer(sender: WebContents, entryUrl: string, development = false): void {
  const packaged = 'app' in electron && electron.app?.isPackaged === true
  const parsed = new URL(entryUrl)
  if (development && packaged) throw new Error('Packaged IPC cannot trust a development origin')
  if (development) {
    if (!['http:','https:'].includes(parsed.protocol) || !['localhost','127.0.0.1','[::1]'].includes(parsed.hostname)) throw new Error('Development renderer must be a loopback HTTP origin')
  } else if (parsed.protocol !== 'file:' || parsed.host || parsed.search) throw new Error('Packaged renderer must be an exact local entry file')
  parsed.hash = ''
  trustedRenderers.set(sender, { entryUrl: parsed.href, devOrigin: development ? parsed.origin : null })
  sender.once?.('destroyed', () => trustedRenderers.delete(sender))
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
    // Unit harnesses invoking handlers without real WebContents. This escape
    // cannot be enabled in a packaged app by setting NODE_ENV externally.
    const packaged = 'app' in electron && electron.app?.isPackaged === true
    if (process.env.NODE_ENV === 'test' && !packaged) return
    throw new Error('Rejected IPC request: sender frame is unavailable')
  }
  if (frame !== event.sender.mainFrame) throw new Error('Rejected IPC request: subframes are not trusted')
  const trusted = trustedRenderers.get(event.sender)
  if (!trusted || event.sender.isDestroyed?.()) throw new Error('Rejected IPC request: unregistered renderer WebContents')
  const frameUrl = frame.url || ''
  if (trusted.devOrigin) {
    if (normalizedOrigin(frameUrl) === trusted.devOrigin) return
    throw new Error('Rejected IPC request: untrusted development origin')
  }
  try {
    const candidate = new URL(frameUrl)
    candidate.hash = ''
    if (candidate.protocol === 'file:' && !candidate.host && !candidate.search && candidate.href === trusted.entryUrl) return
  } catch { /* Malformed URLs fail closed. */ }
  throw new Error('Rejected IPC request: untrusted renderer origin')
}

export function assertSafeIpcPayload(value: unknown): void {
  let nodes = 0
  const seen = new Set<object>()

  const visit = (candidate: unknown, depth: number): void => {
    nodes += 1
    if (nodes > MAX_IPC_NODES) throw new Error('Invalid IPC payload: too many values')
    if (depth > MAX_IPC_DEPTH) throw new Error('Invalid IPC payload: nesting is too deep')
    if (typeof candidate === 'number' && !Number.isFinite(candidate)) {
      throw new Error('Invalid IPC payload: number must be finite')
    }
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
