import { afterEach, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({ handlers: new Map<string, (...args: any[]) => Promise<unknown>>() }))
vi.mock('electron', () => ({ app: { isPackaged: true }, ipcMain: {
  handle: vi.fn((channel: string, listener: (...args: any[]) => Promise<unknown>) => state.handlers.set(channel, listener))
} }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('axios')

afterEach(() => vi.restoreAllMocks())

// AT-00-001 / AT-01-003: importing a module must not register an unguarded handler.
it('registers IP monitor controls only explicitly, through the installed boundary', async () => {
  vi.stubGlobal('process', Object.assign(Object.create(process), { type: 'browser' }))
  try {
    const { ipMonitor, registerIpMonitorIpcHandlers } = await import('./ipMonitor')
    expect(state.handlers.size).toBe(0)
    const { installTrustedIpcBoundary, registerTrustedRenderer } = await import('./ipcSecurity')
    installTrustedIpcBoundary()
    registerIpMonitorIpcHandlers()
    const frame = { url: 'file:///C:/app/index.html' }, sender = { id: 1, mainFrame: frame }
    registerTrustedRenderer(sender as never, frame.url)
    for (const [channel, method] of [['ip-monitor:suspend', 'suspend'], ['ip-monitor:resume', 'resume']] as const) {
      const effect = vi.spyOn(ipMonitor, method).mockImplementation(() => {})
      const listener = state.handlers.get(channel)!
      await expect(listener({ sender, senderFrame: { ...frame } })).resolves.toMatchObject({ ok: false, error: { category: 'permission' } })
      expect(effect).not.toHaveBeenCalled()
      await expect(listener({ sender, senderFrame: frame })).resolves.toMatchObject({ version: 1, ok: true, result: { ok: true } })
      expect(effect).toHaveBeenCalledTimes(1)
    }
  } finally { vi.unstubAllGlobals() }
})
