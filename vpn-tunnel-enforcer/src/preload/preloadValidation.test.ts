import { beforeEach, describe, expect, it, vi } from 'vitest'

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
    invokeMock.mockReset()
    invokeMock.mockResolvedValue(undefined)
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
