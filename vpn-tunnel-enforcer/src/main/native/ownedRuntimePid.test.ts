// AT-00-002 / AT-02-002: protocol shape and native-read failures must not become fabricated PIDs.
import { beforeEach, expect, it, vi } from 'vitest'
import { EventEmitter } from 'node:events'
import { createHostClient, type HostProcess } from './hostClient'
import type { HostRequest } from './hostProtocol'
const call = vi.hoisted(() => vi.fn())
vi.mock('./nativeHost', () => ({ callNativeHost: call }))
import { readOwnedRuntimePidNative } from './ownedRuntimePid'

beforeEach(() => { call.mockReset() })
it('requests the exact executable without shortening the shared host deadline', async () => {
  call.mockResolvedValue(731)
  expect(await readOwnedRuntimePidNative('C:\\VPNTE\\runtime\\vpnte-sing-box.exe')).toBe(731)
  expect(call).toHaveBeenCalledExactlyOnceWith('owned-runtime-pid', { executable: 'C:\\VPNTE\\runtime\\vpnte-sing-box.exe' })
})
it.each([null, undefined, '731', {}, 0, -1, 1.5, NaN, Infinity, 0x100000000])('refuses invalid host PID output %j', async value => {
  call.mockResolvedValue(value)
  await expect(readOwnedRuntimePidNative('C:\\VPNTE\\runtime\\vpnte-sing-box.exe')).rejects.toThrow(/response is invalid/)
})
it('preserves refusal/unavailability so the controller can obtain a fresh PowerShell proof', async () => {
  const error = new Error('native read refused'); call.mockRejectedValue(error)
  await expect(readOwnedRuntimePidNative('C:\\VPNTE\\runtime\\vpnte-sing-box.exe')).rejects.toBe(error)
})

it('does not kill a shared host or its other requests when PID waits beyond 1500 ms (AT-00-003/AT-02-002)', async () => {
  vi.useFakeTimers()
  const events = new EventEmitter(), sent: HostRequest[] = [], kill = vi.fn(() => true)
  const host: HostProcess = { on: events.on.bind(events), kill,
    postMessage: message => { sent.push(message as HostRequest) } }
  const client = createHostClient({ fork: () => host })
  call.mockImplementation((op, args, timeout) => client.call(op, args, timeout))
  try {
    const pid = readOwnedRuntimePidNative('C:\\VPNTE\\runtime\\vpnte-sing-box.exe')
    const routes = client.call('routes', { prefixes: [] })
    const settled = Promise.allSettled([pid, routes])
    await vi.advanceTimersByTimeAsync(1600)
    expect(kill).not.toHaveBeenCalled()
    expect(client.status()).toEqual({ running: true, disabled: false, deaths: 0 })
    events.emit('message', { id: sent[0].id, ok: true, value: 731 })
    events.emit('message', { id: sent[1].id, ok: true, value: [] })
    expect(await settled).toEqual([{ status: 'fulfilled', value: 731 }, { status: 'fulfilled', value: [] }])
  } finally { client.shutdown(); vi.useRealTimers() }
})
