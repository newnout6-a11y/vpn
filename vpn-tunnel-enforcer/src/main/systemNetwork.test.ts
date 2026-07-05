import { mkdtemp, stat } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const paths = {
  programData: '',
  userData: ''
}

vi.mock('electron', () => ({
  app: {
    getPath: (name: string) => {
      if (name === 'programData') {
        if (paths.programData === '__throw__') throw new Error("Failed to get 'programData' path")
        return paths.programData
      }
      if (name === 'userData') return paths.userData
      return paths.userData
    }
  }
}))

vi.mock('./admin', () => ({
  execElevated: vi.fn(async (cmd: string) => {
    const state = (globalThis as any).__systemNetworkMock ?? {}
    if (state.failNetsh && cmd.startsWith('netsh winhttp reset proxy')) {
      const err: any = new Error('netsh failed')
      err.stderr = 'netsh failed'
      throw err
    }
    return { stdout: '', stderr: '' }
  })
}))

vi.mock('./appLogger', () => ({
  logEvent: vi.fn()
}))

vi.mock('child_process', () => ({
  default: {
    exec: vi.fn((cmd: string, _opts: any, cb: Function) => {
      const state = (globalThis as any).__systemNetworkMock ?? {}
      if (cmd.startsWith('reg export') && state.failRegExport !== false) {
        cb(new Error('reg export failed'), '', 'reg export failed')
        return
      }
      if (state.failProxyEnable && cmd.includes('/v ProxyEnable')) {
        cb(new Error('reg add failed'), '', 'reg add failed')
        return
      }
      cb(null, '', '')
    })
  },
  exec: vi.fn((cmd: string, _opts: any, cb: Function) => {
    const state = (globalThis as any).__systemNetworkMock ?? {}
    if (cmd.startsWith('reg export') && state.failRegExport !== false) {
      cb(new Error('reg export failed'), '', 'reg export failed')
      return
    }
    if (state.failProxyEnable && cmd.includes('/v ProxyEnable')) {
      cb(new Error('reg add failed'), '', 'reg add failed')
      return
    }
    cb(null, '', '')
  })
}))

describe('systemNetwork baseline manifest', () => {
  beforeEach(async () => {
    const root = await mkdtemp(join(tmpdir(), 'vpnte-system-network-'))
    paths.programData = join(root, 'ProgramData')
    paths.userData = join(root, 'UserData')
    ;(globalThis as any).__systemNetworkMock = { failRegExport: true }
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    vi.resetModules()
  })

  it('stores the baseline manifest under ProgramData, not userData', async () => {
    const { getTunNetworkBaselineManifestPath } = await import('./systemNetwork')
    expect(getTunNetworkBaselineManifestPath()).toBe(
      join(paths.programData, 'VPN-Tunnel-Enforcer', 'network-backups', 'latest-tun-network-baseline.json')
    )
  })

  it('falls back to process.env.ProgramData when Electron has no programData path', async () => {
    const fallbackRoot = join(paths.userData, '..', 'FallbackProgramData')
    paths.programData = '__throw__'
    process.env.ProgramData = fallbackRoot
    vi.resetModules()

    const { getTunNetworkBaselineManifestPath } = await import('./systemNetwork')

    expect(getTunNetworkBaselineManifestPath()).toBe(
      join(fallbackRoot, 'VPN-Tunnel-Enforcer', 'network-backups', 'latest-tun-network-baseline.json')
    )
  })

  it('does not leave a sticky applied marker when the required backup fails', async () => {
    const { applyTunNetworkBaseline, getTunNetworkBaselineManifestPath } = await import('./systemNetwork')

    const result = await applyTunNetworkBaseline()
    expect(result.success).toBe(false)

    await expect(stat(getTunNetworkBaselineManifestPath())).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('surfaces non-fatal reset command failures as warnings', async () => {
    ;(globalThis as any).__systemNetworkMock = {
      failRegExport: false,
      failNetsh: true,
      failProxyEnable: true
    }
    const { applyTunNetworkBaseline } = await import('./systemNetwork')

    const result = await applyTunNetworkBaseline()

    expect(result.success).toBe(true)
    expect(result.warnings).toEqual(expect.arrayContaining([
      expect.stringContaining('netsh winhttp reset proxy failed'),
      expect.stringContaining('reg add')
    ]))
    expect(result.details).toContain('warnings:')
  })

  it('treats missing baseline manifest as an idempotent rollback no-op', async () => {
    const { rollbackTunNetworkBaseline } = await import('./systemNetwork')

    const result = await rollbackTunNetworkBaseline()

    expect(result.success).toBe(true)
    expect(result.skipped).toBe(true)
    expect(result.message).toContain('baseline')
  })

  it('serializes concurrent baseline applications without sharing a temp manifest path', async () => {
    ;(globalThis as any).__systemNetworkMock = { failRegExport: false }
    const { applyTunNetworkBaseline } = await import('./systemNetwork')

    const results = await Promise.all([
      applyTunNetworkBaseline(),
      applyTunNetworkBaseline()
    ])

    expect(results.every((result) => result.success)).toBe(true)
  })
})
