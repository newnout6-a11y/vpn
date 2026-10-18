import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ipcRenderer } from 'electron'

const exposed = vi.hoisted(() => ({ api: null as any }))
const invokeMock = vi.hoisted(() => vi.fn())

vi.mock('electron', () => ({
  contextBridge: {
    exposeInMainWorld: vi.fn((_name: string, api: any) => {
      exposed.api = api
    })
  },
  ipcRenderer: {
    invoke: invokeMock,
    on: vi.fn(),
    removeListener: vi.fn()
  }
}))

async function loadApi() {
  vi.resetModules()
  exposed.api = null
  await import('./index')
  return exposed.api
}

describe('preload IPC argument validation', () => {
  beforeEach(() => {
    vi.stubGlobal('navigator', { language: 'en-US' })
    invokeMock.mockReset()
    invokeMock.mockResolvedValue({ version: 1, correlationId: '00000000-0000-4000-8000-000000000000', ok: true, result: undefined })
  })
  afterEach(() => vi.unstubAllGlobals())

  // AT-00-001/004: transport envelopes must not change public domain results.
  it.each([undefined, { running: false }, { ok: false, error: 'domain result' }])('decodes successful transport result %j', async result => {
    const api = await loadApi()
    invokeMock.mockResolvedValue({ version: 1, correlationId: '00000000-0000-4000-8000-000000000000', ok: true, result })
    await expect(api.getTunStatus()).resolves.toEqual(result)
  })

  it('returns a canonical remote error with correlation and no exception text', async () => {
    const api = await loadApi()
    invokeMock.mockResolvedValue({ version: 1, correlationId: '00000000-0000-4000-8000-000000000000', ok: false,
      error: { category: 'permission', code: 'unknown', message: 'raw-secret at C:\\private\\file' } })
    await expect(api.getTunStatus()).rejects.toMatchObject({ name: 'IpcRemoteError', category: 'permission',
      code: 'IPC_PERMISSION_DENIED', message: 'Permission denied', correlationId: '00000000-0000-4000-8000-000000000000' })
  })

  it('sanitizes malformed responses and rejected Electron transports', async () => {
    const api = await loadApi()
    invokeMock.mockResolvedValueOnce({ raw: 'raw-secret at C:\\private\\file' })
    invokeMock.mockRejectedValueOnce(new Error('raw-secret at C:\\private\\file'))
    for (let attempt = 0; attempt < 2; attempt++) {
      await expect(api.getTunStatus()).rejects.toMatchObject({ category: 'internal', code: 'IPC_INTERNAL_ERROR', message: 'Operation failed' })
    }
  })

  it.each(['en', 'ru'])('uses persisted %s for canonical errors without trusting main error text', async locale => {
    const api = await loadApi()
    invokeMock.mockResolvedValueOnce({ version: 1, correlationId: '00000000-0000-4000-8000-000000000000', ok: true, result: locale })
    await api.i18nGetLocale()
    invokeMock.mockResolvedValueOnce({ version: 1, correlationId: '00000000-0000-4000-8000-000000000000', ok: false, error: { category: 'permission', message: 'raw-secret' } })
    await expect(api.getTunStatus()).rejects.toMatchObject({ code: 'IPC_PERMISSION_DENIED',
      message: locale === 'en' ? 'Permission denied' : 'Недостаточно прав для операции' })
  })

  it('updates error language after a successful setting change and cross-window event', async () => {
    const api = await loadApi()
    await api.i18nSetLocale('ru')
    invokeMock.mockRejectedValueOnce(new Error('raw-secret'))
    await expect(api.getTunStatus()).rejects.toMatchObject({ message: 'Не удалось выполнить операцию' })
    const callback = vi.fn()
    api.onI18nLocaleChanged(callback)
    const handler = [...vi.mocked(ipcRenderer.on).mock.calls].reverse().find(call => call[0] === 'i18n:locale-changed')![1]
    handler({} as never, 'en')
    invokeMock.mockRejectedValueOnce(new Error('raw-secret'))
    await expect(api.getTunStatus()).rejects.toMatchObject({ message: 'Operation failed' })
    expect(callback).toHaveBeenCalledWith('en')
  })

  it('rejects oversized VPN inspection input before ipcRenderer.invoke', async () => {
    const api = await loadApi()

    expect(() => api.inspectVpnInput('x'.repeat(256 * 1024 + 1))).toThrow(/too large/)
    expect(invokeMock).not.toHaveBeenCalled()
  })

  it('rejects non-object settings before ipcRenderer.invoke', async () => {
    const api = await loadApi()

    expect(() => api.saveSettings('not-an-object')).toThrow(/settings must be an object/)
    expect(invokeMock).not.toHaveBeenCalled()
  })

  it('rejects invalid enum and port arguments', async () => {
    const api = await loadApi()

    expect(() => api.killSwitchSetLevel('maximum')).toThrow(/level is invalid/)
    expect(() => api.serversPingOne('example.com', 70000)).toThrow(/port/)
    expect(invokeMock).not.toHaveBeenCalled()
  })

  // AT-01-004/008, F-139/F-144: reject malformed export modes at the bridge.
  it.each([null, false, 1, '', 'with-secrets', 'REDACTED', {}, ['secrets']])('rejects invalid config export mode %j without invoking IPC', async mode => {
    const api = await loadApi()

    expect(() => api.configExport(mode)).toThrow(TypeError)
    expect(invokeMock).not.toHaveBeenCalled()
  })

  it.each([undefined, 'redacted', 'secrets'])('passes supported config export mode %s through IPC', async mode => {
    const api = await loadApi()

    await api.configExport(mode)

    expect(invokeMock).toHaveBeenCalledExactlyOnceWith('config:export', mode ?? 'redacted')
  })

  it('defaults omitted config export mode to redacted', async () => {
    const api = await loadApi()
    await api.configExport()
    expect(invokeMock).toHaveBeenCalledExactlyOnceWith('config:export', 'redacted')
  })

  it('passes validated arguments through to ipcRenderer.invoke', async () => {
    const api = await loadApi()

    await api.serversAdd('vless://u@example.com:443', { clientDevice: 'android' })

    expect(invokeMock).toHaveBeenCalledWith('servers:add', 'vless://u@example.com:443', { clientDevice: 'android' })
  })

  it('passes the optional external proxy country filter through preload', async () => {
    const api = await loadApi()

    await api.externalProxyList('Netherlands')

    expect(invokeMock).toHaveBeenCalledWith('external-proxy:list', 'Netherlands')
  })

  it('does not expose legacy Store repair buttons through the renderer bridge', async () => {
    const api = await loadApi()

    expect(api.runStoreRepair).toBeUndefined()
    expect(api.runStoreDiagnostics).toBeUndefined()
  })

  it('does not expose direct TUN baseline apply through the renderer bridge', async () => {
    const api = await loadApi()

    expect(api.applyTunNetworkBaseline).toBeUndefined()
  })

  it('requires the firewall reset confirmation token to be passed through preload', async () => {
    const api = await loadApi()

    await api.firewallNuclearReset('RESET_WINDOWS_FIREWALL_CONFIRMED')

    expect(invokeMock).toHaveBeenCalledWith('firewall:nuclear-reset', 'RESET_WINDOWS_FIREWALL_CONFIRMED')
  })
})
