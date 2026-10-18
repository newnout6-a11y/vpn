import { expect, it, vi } from 'vitest'
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'

const state = vi.hoisted(() => ({ work: '', handlers: new Map<string, (...args: any[]) => Promise<any>>() }))
vi.mock('electron', () => ({ app: { isPackaged: true, getPath: () => state.work }, shell: {}, ipcMain: {
  handle: (channel: string, listener: (...args: any[]) => Promise<any>) => state.handlers.set(channel, listener)
} }))

// AT-00-004/005, F-074/F-143: use actual logger AND credential redactor, not a spy.
it('keeps an exact reversible response correlation in the redacted on-disk audit log', async () => {
  const root = resolve('.tmp')
  mkdirSync(root, { recursive: true })
  state.work = mkdtempSync(join(root, 'ipc-audit-'))
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.spyOn(console, 'log').mockImplementation(() => {})
  try {
    const { ipcMain } = await import('electron')
    const { installTrustedIpcBoundary, registerTrustedRenderer } = await import('./ipcSecurity')
    const { logEvent, getAppLogPath } = await import('./appLogger')
    installTrustedIpcBoundary()
    ipcMain.handle('get-settings', () => { throw new Error('raw-secret C:\\private\\file') })
    const frame = { url: 'file:///C:/app/index.html' }, sender = { mainFrame: frame, id: 1 }
    registerTrustedRenderer(sender as never, frame.url)
    const failed = await state.handlers.get('get-settings')!({ sender, senderFrame: frame })
    const rejected = await state.handlers.get('get-settings')!({ sender, senderFrame: frame }, 'extra')
    logEvent('info', 'positive-control', 'bare credential-shaped UUID remains redacted', { correlationId: '8093a2ec-f028-4e3c-96a7-b301efaf23dd' })
    const path = getAppLogPath()
    await expect.poll(() => { try { return readFileSync(path, 'utf8') } catch { return '' } }).toContain('positive-control')
    const raw = readFileSync(path, 'utf8')
    const rows = raw.trim().split('\n').map(line => JSON.parse(line))
    const audit = rows.filter(row => row.scope === 'ipc-security')
    expect(audit.map(row => row.details.correlationId)).toEqual([failed, rejected].map(response => response.correlationId))
    expect(rows.at(-1).details.correlationId).toBe('<redacted-uuid>')
    expect(raw).not.toMatch(/raw-secret|private|file:\/\//)
  } finally {
    vi.restoreAllMocks()
    if (dirname(state.work) !== root) throw new Error('Unsafe owned audit fixture cleanup')
    rmSync(state.work, { recursive: true, force: true })
  }
})
