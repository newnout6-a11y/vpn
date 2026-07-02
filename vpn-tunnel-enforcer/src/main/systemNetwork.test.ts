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
      if (name === 'programData') return paths.programData
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
})
