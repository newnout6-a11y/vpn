import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ipcRenderer } from 'electron'
import { isIpcRemoteErrorData } from '../shared/ipc-result'

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

async function expectLocalValidation(action: () => unknown): Promise<void> {
  const result = action()
  expect(result).toBeInstanceOf(Promise)
  const failure = await Promise.resolve(result).catch((error: unknown) => error)
  expect(failure).toMatchObject({ name: 'IpcRemoteError', category: 'validation', code: 'IPC_VALIDATION_ERROR', message: 'Invalid operation parameters' })
  expect(failure).not.toBeInstanceOf(Error)
  expect(failure).not.toHaveProperty('stack')
}

describe('preload IPC argument validation', () => {
  beforeEach(() => {
    vi.stubGlobal('navigator', { language: 'en-US' })
    invokeMock.mockReset()
    invokeMock.mockResolvedValue({ version: 1, correlationId: '00000000-0000-4000-8000-000000000000', ok: true, result: undefined })
  })
  afterEach(() => vi.unstubAllGlobals())

  // AT-00-001: trailing cancellation tokens preserve every legacy call shape.
  it.each([
    ['urlAvailabilityCheck', 'url-availability:check', ['https://example.test/']],
    ['groupsCheckHealth', 'groups:check-health', ['a']],
    ['serversCopyKey', 'servers:copy-key', ['a']], ['serversExportKey', 'servers:export-key', ['a']],
    ['serversExportKeyToFile', 'servers:export-key-file', ['a']],
    ['serversExportAllKeysToFile', 'servers:export-all-keys-file', []],
    ['serversExportAllProxiesToFile', 'servers:export-all-proxies-file', []]
  ])('forwards the optional requester token for %s', async (method, channel, args) => {
    const api = await loadApi(), token = '11111111-1111-4111-8111-111111111111'
    await api[method](...args)
    expect(invokeMock).toHaveBeenLastCalledWith(channel, ...args)
    await api[method](...args, token)
    expect(invokeMock).toHaveBeenLastCalledWith(channel, ...args, token)
    invokeMock.mockClear()
    await expectLocalValidation(() => api[method](...args, { forged: true }))
    expect(invokeMock).not.toHaveBeenCalled()
  })

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
    const failure = await api.getTunStatus().catch((error: unknown) => error)
    expect(isIpcRemoteErrorData(structuredClone(failure))).toBe(true)
    expect(failure).not.toBeInstanceOf(Error)
    expect(failure).not.toHaveProperty('stack')
  })

  it('preserves synchronous subscriptions, callback values and unsubscribe handles', async () => {
    const api = await loadApi(), callback = vi.fn()
    vi.mocked(ipcRenderer.on).mockClear()
    const unsubscribe = api.onAppResumedFromSleep(callback)
    const [channel, handler] = vi.mocked(ipcRenderer.on).mock.calls[0]
    expect(channel).toBe('app:resumed-from-sleep')
    handler({} as never)
    expect(callback).toHaveBeenCalledOnce()
    expect(typeof unsubscribe).toBe('function')
    unsubscribe()
    expect(ipcRenderer.removeListener).toHaveBeenCalledWith(channel, handler)
  })

  it('sanitizes malformed responses and rejected Electron transports', async () => {
    const api = await loadApi()
    invokeMock.mockResolvedValueOnce({ raw: 'raw-secret at C:\\private\\file' })
    invokeMock.mockRejectedValueOnce(new Error('raw-secret at C:\\private\\file'))
    for (let attempt = 0; attempt < 2; attempt++) {
      await expect(api.getTunStatus()).rejects.toMatchObject({ category: 'internal', code: 'IPC_INTERNAL_ERROR', message: 'Operation failed' })
    }
  })

  it.each([new TypeError('raw-secret'), new RangeError('raw-secret')])('keeps unexpected synchronous preload failures internal', async error => {
    const api = await loadApi()
    invokeMock.mockImplementationOnce(() => { throw error })
    await expect(api.getTunStatus()).rejects.toMatchObject({ category: 'internal', code: 'IPC_INTERNAL_ERROR', message: 'Operation failed' })
  })

  it('rejects unserializable input as validation without IPC effects', async () => {
    const api = await loadApi(), circular: Record<string, unknown> = {}
    circular.self = circular
    await expectLocalValidation(() => api.saveSettings(circular))
    expect(invokeMock).not.toHaveBeenCalled()
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

    await expectLocalValidation(() => api.inspectVpnInput('x'.repeat(256 * 1024 + 1)))
    expect(invokeMock).not.toHaveBeenCalled()
  })

  it('rejects non-object settings before ipcRenderer.invoke', async () => {
    const api = await loadApi()

    await expectLocalValidation(() => api.saveSettings('not-an-object'))
    expect(invokeMock).not.toHaveBeenCalled()
  })

  it.each([
    { autoStart: 'false' }, { strictAdapterLockdown: 'false' }, { proxyEngine: 'mihomo' },
    { directVpnCachedProfiles: [{ name: 'Profile', protocol: 'vless', outbound: { tls: { enabled: () => true } } }] },
    { directVpnCachedProfiles: [{ name: 'Profile', protocol: 'vless', outbound: { server: new Date(0) } }] },
    { directVpnCachedProfiles: [{ name: 'Profile', protocol: 'vless', outbound: { port: NaN } }] },
  ])('rejects malformed settings fields before any IPC effects', async settings => {
    const api = await loadApi()
    await expectLocalValidation(() => api.saveSettings(settings))
    expect(invokeMock).not.toHaveBeenCalled()
  })

  it('keeps typed settings patches unchanged before feature normalization', async () => {
    const api = await loadApi()
    const patch = { autoStart: false, checkInterval: -5, directVpnCachedAt: null,
      directVpnCachedProfiles: [{ name: 'Profile', protocol: 'vless', outbound: { server: 'example.test', tls: { enabled: true } } }] }
    await api.saveSettings(patch)
    expect(invokeMock).toHaveBeenCalledExactlyOnceWith('save-settings', patch)
  })

  it('bounds nested outbound JSON before any IPC effects', async () => {
    const api = await loadApi()
    let deep: Record<string, unknown> = {}
    for (let index = 0; index < 14; index++) deep = { child: deep }
    for (const outbound of [deep, { values: Array.from({ length: 20_000 }, () => 0) }]) {
      await expectLocalValidation(() => api.saveSettings({ directVpnCachedProfiles: [{ name: 'Profile', protocol: 'vless', outbound }] }))
    }
    expect(invokeMock).not.toHaveBeenCalled()
  })

  // AT-00-001/004: the public bridge uses the same nested schemas as main.
  it.each([
    ['schedulerUpdate', ['id', { days: [7] }]],
    ['rotationSetConfig', [{ currentIndex: 0.5 }]],
    ['dnsUpdate', ['id', { type: 'udp' }]],
    ['notificationsSetPrefs', [{ sound: 'yes' }]],
    ['themeCreate', [{ name: 'Theme', mode: 'dark', colors: {} }]],
    ['serverLiveCheckHistory', [{ host: ['example.test'] }]],
    ['rollbackAutoconfig', [new Array(1)]],
  ])('rejects invalid nested %s arguments without IPC effects', async (method, args) => {
    const api = await loadApi()
    await expectLocalValidation(() => api[method as string](...args as unknown[]))
    expect(invokeMock).not.toHaveBeenCalled()
  })

  it('preserves empty patches and optional DNS defaults in public calls', async () => {
    const api = await loadApi()
    await api.schedulerUpdate('id', {})
    await api.rotationSetConfig({ intervalMinutes: 5000, nextRotationAt: null })
    await api.dnsCreate({ name: 'DNS', primary: '1.1.1.1', type: 'plain' })
    expect(invokeMock.mock.calls).toEqual([
      ['scheduler:update', 'id', {}],
      ['rotation:set-config', { intervalMinutes: 5000, nextRotationAt: null }],
      ['dns:create', { name: 'DNS', primary: '1.1.1.1', type: 'plain' }],
    ])
  })

  it('rejects invalid enum and port arguments', async () => {
    const api = await loadApi()

    await expectLocalValidation(() => api.killSwitchSetLevel('maximum'))
    await expectLocalValidation(() => api.serversPingOne('example.com', 70000))
    expect(invokeMock).not.toHaveBeenCalled()
  })

  // AT-01-004/008, F-139/F-144: reject malformed export modes at the bridge.
  it.each([null, false, 1, '', 'with-secrets', 'REDACTED', {}, ['secrets']])('rejects invalid config export mode %j without invoking IPC', async mode => {
    const api = await loadApi()

    await expectLocalValidation(() => api.configExport(mode))
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

  // AT-00-001/003: execute the production bridge, preserving legacy arity.
  it('forwards the optional diagnostic requester token and preserves zero arguments', async () => {
    const api = await loadApi()
    await api.exportDiagnostics()
    await api.exportDiagnostics('11111111-1111-4111-8111-111111111111')
    expect(invokeMock.mock.calls).toEqual([
      ['export-diagnostics'], ['export-diagnostics', '11111111-1111-4111-8111-111111111111']
    ])
    invokeMock.mockClear()
    await expectLocalValidation(() => api.exportDiagnostics({ signal: 'forged' }))
    expect(invokeMock).not.toHaveBeenCalled()
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
