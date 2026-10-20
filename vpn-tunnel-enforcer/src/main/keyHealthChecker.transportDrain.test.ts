// AT-00-003: cancel the owned proxy transport even before SOCKS negotiation.
import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({ sockets: [] as any[], negotiate: vi.fn() }))
vi.mock('electron', () => ({ ipcMain: { handle: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./tunController', () => ({ tunController: { getStatus: () => ({ running: false }) } }))
vi.mock('net', async original => ({ ...await original<typeof import('net')>(), Socket: class extends EventEmitter {
  closed = false
  connect = vi.fn(() => this)
  destroy = vi.fn(() => this)
  constructor() { super(); state.sockets.push(this) }
} }))
vi.mock('socks', () => ({ SocksClient: { createConnection: state.negotiate } }))
import { openTcpViaSocks } from './keyHealthChecker'
const flush = async () => { for (let i = 0; i < 40; i++) await Promise.resolve() }
beforeEach(() => { vi.useFakeTimers(); state.sockets = []; state.negotiate.mockReset().mockImplementation(async options => ({ socket: options.existing_socket })) })
afterEach(() => { for (const socket of state.sockets) socket.emit('close'); vi.useRealTimers() })
describe('owned SOCKS TCP dial', () => {
  it.each(['cancel', 'timeout'])('destroys a stalled TCP dial on %s and retains actual close', async boundary => {
    const owner = new AbortController(), drains: Promise<unknown>[] = []
    const result = openTcpViaSocks({ host: '127.0.0.1', port: 10809 }, 'fixture.example', 443, 100, owner.signal, task => { drains.push(task) }).catch(error => error)
    await flush(); expect(state.sockets).toHaveLength(1)
    if (boundary === 'cancel') owner.abort(); else await vi.advanceTimersByTimeAsync(100)
    expect((await result).message).toBe(boundary === 'cancel' ? 'Cancelled' : 'timeout')
    expect(state.sockets[0].destroy).toHaveBeenCalledOnce(); expect(state.negotiate).not.toHaveBeenCalled()
    let drained = false; const drain = Promise.all(drains).then(() => { drained = true })
    await flush(); expect(drained).toBe(false); state.sockets[0].emit('close'); await drain
    expect(vi.getTimerCount()).toBe(0)
  })
  it('negotiates only over the connected owned transport and preserves it for the caller', async () => {
    const drains: Promise<unknown>[] = []
    const task = openTcpViaSocks({ host: '127.0.0.1', port: 10809 }, 'fixture.example', 443, 100, undefined, value => { drains.push(value) })
    expect(state.negotiate).not.toHaveBeenCalled(); state.sockets[0].emit('connect')
    expect(await task).toBe(state.sockets[0]); expect(state.negotiate.mock.calls[0][0].existing_socket).toBe(state.sockets[0])
    expect(state.sockets[0].destroy).not.toHaveBeenCalled(); expect(vi.getTimerCount()).toBe(0)
    state.sockets[0].emit('close'); await Promise.all(drains)
  })
})
