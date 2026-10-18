// AT-00-008: tray consumes the same production FSM as the renderer.
import { describe, expect, it, vi } from 'vitest'
vi.mock('electron', () => ({ Tray: class {}, Menu: {}, nativeImage: {}, BrowserWindow: class {}, app: {} }))
import { trayStatusForTunnel } from './tray'
import { TunnelStateMachine } from './tunnelStateMachine'
import { ConnectionLifecycle } from './connectionLifecycle'

describe('canonical tray state', () => {
  it('distinguishes degraded competing-interface evidence from a failed server', async () => {
    const os = { running: false, pid: null as number | null, softApplied: false }
    const model = new TunnelStateMachine(() => os)
    const lane = new ConnectionLifecycle(() => {}, undefined, undefined, model)
    const connect = lane.start(async () => { os.running = true; os.pid = 1; return { success: true } })
    expect(trayStatusForTunnel(model.snapshot, false)).toBe('starting')
    await connect
    expect(trayStatusForTunnel(model.snapshot, false)).toBe('protected')
    model.runtimeChanged('competing-tun:Other VPN')
    expect(trayStatusForTunnel(model.snapshot, false)).toBe('unknown')
    model.runtimeChanged('proxy-down')
    model.runtimeChanged('competing-tun-cleared')
    expect(trayStatusForTunnel(model.snapshot, false)).toBe('proxy-down')
    expect(trayStatusForTunnel(model.snapshot, true)).toBe('leak')
    model.fault('blocked')
    expect(trayStatusForTunnel(model.snapshot, false)).toBe('killswitch')
    model.runtimeChanged('running')
    expect(trayStatusForTunnel(model.snapshot, false)).toBe('killswitch')
  })
})
