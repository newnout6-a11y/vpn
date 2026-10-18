import { describe, expect, it } from 'vitest'
import { IPC_ERRORS, IpcFault, IpcValidationError, IpcRemoteError, ipcError, isIpcRemoteErrorData, serializeIpcError, type IpcErrorCategory } from './ipc-result'

const correlationId = '00000000-0000-4000-8000-000000000000'
describe('cloneable IPC failure data (AT-00-004; F-074)', () => {
  it.each(Object.keys(IPC_ERRORS) as IpcErrorCategory[])('preserves %s code/category/correlation, with canonical messages in both locales', category => {
    for (const locale of ['en', 'ru'] as const) {
      const error = new IpcRemoteError({ ...ipcError(category), message: 'raw-secret at C:\\private\\file' }, correlationId)
      Object.assign(error, { cause: { password: 'raw-secret' } })
      const data = structuredClone(serializeIpcError(error, locale))
      expect(data).toEqual({ name: 'IpcRemoteError', ...ipcError(category, locale), correlationId })
      expect(isIpcRemoteErrorData(data)).toBe(true)
      expect(data).not.toBeInstanceOf(Error)
      expect(JSON.stringify(data)).not.toMatch(/raw-secret|private|stack|cause/)
    }
  })
  it('classifies local validators without inventing a main-process correlation', () => {
    expect(serializeIpcError(new IpcValidationError('raw-secret'), 'en')).toEqual({ name: 'IpcRemoteError', ...ipcError('validation', 'en') })
  })
  it.each([new TypeError('raw-secret'), new RangeError('raw-secret')])('keeps unexpected preload errors internal', error => {
    expect(serializeIpcError(error, 'en')).toEqual({ name: 'IpcRemoteError', ...ipcError('internal', 'en') })
  })
  it('contains malformed typed faults and throwing getters', () => {
    const invalid = Object.defineProperty(new IpcFault('network'), 'category', { value: 'not-a-category' })
    const hostile = Object.defineProperty(new IpcRemoteError(ipcError('network')), 'category', { get() { throw new Error('raw-secret') } })
    for (const error of [invalid, hostile, 'raw-secret', null]) {
      expect(serializeIpcError(error, 'en')).toEqual({ name: 'IpcRemoteError', ...ipcError('internal', 'en') })
    }
  })
  it.each([undefined, null, [], {}, { name: 'IpcRemoteError', ...ipcError('permission'), code: 'IPC_NETWORK_ERROR' },
    { name: 'IpcRemoteError', ...ipcError('permission'), message: 'raw-secret' },
    { name: 'IpcRemoteError', ...ipcError('permission'), correlationId: 'wrong' },
    Object.defineProperty({}, 'name', { get() { throw new Error('raw-secret') } })])('rejects confused failure data', value => {
    expect(isIpcRemoteErrorData(value)).toBe(false)
  })
})
