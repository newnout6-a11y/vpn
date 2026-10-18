import { beforeAll, describe, expect, it, vi } from 'vitest'
import { IPC_REQUESTS, type IpcArgumentSchema, type IpcChannel, assertIpcRequest } from '../shared/ipc-contract'
import { IPC_ERRORS, IpcFault, IpcRemoteError, IpcValidationError, unwrapIpcResult, type IpcResult } from '../shared/ipc-result'
const state = vi.hoisted(() => ({ handlers: new Map<string, (...args: unknown[]) => Promise<IpcResult<unknown>>>() }))
vi.mock('electron', () => ({ app: { isPackaged: true }, ipcMain: {
  handle: (channel: string, fn: (...args: unknown[]) => Promise<IpcResult<unknown>>) => state.handlers.set(channel, fn)
} }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
import { ipcMain } from 'electron'
import { logEvent } from './appLogger'
import { installTrustedIpcBoundary, registerTrustedRenderer } from './ipcSecurity'

function example(schema: IpcArgumentSchema): unknown {
  if (schema.optional) return undefined
  if (schema.nullable) return null
  switch (schema.type) {
    case 'string': return 'value'
    case 'boolean': return false
    case 'enum': return schema.values![0]
    case 'integer': case 'number': return schema.min ?? 1
    case 'strings': return Array.from({ length: schema.min ?? 0 }, () => 'value')
    case 'object': return Object.fromEntries(Object.entries(schema.fields ?? {}).map(([key, field]) => [key, example(field)]))
  }
}
const channels = Object.keys(IPC_REQUESTS) as IpcChannel[]
const url = 'file:///C:/app/out/renderer/index.html'
const frame = { url }, sender = { id: 23, mainFrame: frame }
const event = { sender, senderFrame: frame }
beforeAll(() => { installTrustedIpcBoundary(); registerTrustedRenderer(sender as never, url) })

describe('wire contracts on every registered channel (AT-00-001/004; F-138/F-074)', () => {
  it.each(channels)('%s validates before dispatch and returns a versioned envelope', async channel => {
    const effect = vi.fn(() => ({ domainResult: { ok: false } }))
    ipcMain.handle(channel, effect)
    const handler = state.handlers.get(channel)!
    const args = IPC_REQUESTS[channel].args.map(example)
    const response = await handler(event, ...args)
    expect(unwrapIpcResult(response)).toEqual({ domainResult: { ok: false } })
    expect(effect).toHaveBeenCalledTimes(1)
    const extra = [...args, 'unexpected']
    expect(await handler(event, ...extra)).toMatchObject({ version: 1, ok: false, error: { category: 'validation' } })
    for (let index = 0; index < args.length; index++) {
      const invalid = [...args]
      invalid[index] = IPC_REQUESTS[channel].args[index].type === 'object' ? [] : {}
      expect(await handler(event, ...invalid)).toMatchObject({ ok: false, error: { category: 'validation' } })
    }
    expect(effect).toHaveBeenCalledTimes(1)
    const failure = await handler({ ...event, senderFrame: { url } }, ...args)
    expect(failure).toMatchObject({ ok: false, error: { category: 'permission' } })
    expect(effect).toHaveBeenCalledTimes(1)
    expect(logEvent).toHaveBeenCalledWith('warn', 'ipc-security', 'IPC request rejected', expect.objectContaining({ correlationId: `ipc_${failure.correlationId.replaceAll('-', '')}` }))
  })
  it.each(channels)('%s sanitizes every error category', async channel => {
    const errors = {
      validation: new IpcValidationError('raw-secret C:\\private\\file'),
      permission: Object.assign(new Error('raw-secret'), { code: 'EACCES' }),
      network: Object.assign(new Error('raw-secret'), { code: 'ECONNREFUSED' }),
      conflict: new IpcFault('conflict'), internal: new Error('raw-secret at C:\\private\\file:1'),
      cancelled: Object.assign(new Error('raw-secret'), { name: 'AbortError' }),
      timeout: Object.assign(new Error('raw-secret'), { code: 'ETIMEDOUT' })
    }
    for (const [category, error] of Object.entries(errors)) {
      ipcMain.handle(channel, () => { throw error })
      const response = await state.handlers.get(channel)!(event, ...IPC_REQUESTS[channel].args.map(example))
      expect(response).toMatchObject({ ok: false, error: { category, ...IPC_ERRORS[category as keyof typeof IPC_ERRORS] } })
      expect(JSON.stringify(response)).not.toMatch(/raw-secret|C:\\private|at /)
      expect(() => unwrapIpcResult(response)).toThrow(IpcRemoteError)
    }
  })
  it('rejects registration drift and unsafe names', () => {
    expect(() => ipcMain.handle('unknown:channel', vi.fn())).toThrow(IpcValidationError)
    expect(() => assertIpcRequest('__proto__', [])).toThrow(IpcValidationError)
  })
  it('contains exceptions with hostile code/name getters inside the safe envelope', async () => {
    for (const error of [Object.defineProperty({}, 'code', { get() { throw new Error('raw-secret') } }),
      Object.defineProperty(new Error(), 'name', { get() { throw new Error('raw-secret') } })]) {
      ipcMain.handle('get-settings', () => { throw error })
      await expect(state.handlers.get('get-settings')!(event)).resolves.toMatchObject({ ok: false, error: { category: 'internal' } })
    }
  })
  it.each([undefined, null, {}, { version: 2, ok: true, result: 1 }, { version: 1, ok: true, result: 1, correlationId: 'wrong' }])('rejects malformed wire response %j', value => {
    expect(() => unwrapIpcResult(value)).toThrow(IpcRemoteError)
  })
})
