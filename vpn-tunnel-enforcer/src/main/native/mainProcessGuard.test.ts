// AT-07-002 / AT-12-007: koffi must never run in the Electron main process (process.type === 'browser').
// A fatal koffi error there aborts the whole elevated application (#26); the guard turns it into a catchable throw
// so callers fall back to PowerShell. Under plain Node (tests, tooling) and in the utility host nothing changes.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const koffi = vi.hoisted(() => ({ requested: 0 }))
vi.mock('koffi', () => {
  koffi.requested++
  return { default: { load: () => { throw new Error('koffi.load must not be reached in main') } } }
})

import { readRawAdapters, readRawIfConfigs, readRawRoutes } from './ipHelperReads'
import { createKoffiSource, resetKoffiSourceForTests } from './physicalAdapterCore'
import { notifyWinInetInProcess, resetWinInetNativeForTests } from './winInetCore'
import { assertKoffiAllowedHere } from './koffiTypes'

const platform = Object.getOwnPropertyDescriptor(process, 'platform')!
const type = Object.getOwnPropertyDescriptor(process, 'type')

function setProcessType(value: string | undefined): void {
  Object.defineProperty(process, 'type', { value, configurable: true, writable: true })
}

beforeEach(() => {
  Object.defineProperty(process, 'platform', { value: 'win32' })
  resetKoffiSourceForTests()
  resetWinInetNativeForTests()
  koffi.requested = 0
})
afterEach(() => {
  Object.defineProperty(process, 'platform', platform)
  if (type) Object.defineProperty(process, 'type', type); else delete (process as { type?: string }).type
})

describe('koffi main-process guard', () => {
  it.each(['readRawAdapters', 'readRawIfConfigs', 'readRawRoutes(4)'] as const)('%s throws in the main process before touching koffi', name => {
    setProcessType('browser')
    const run = { readRawAdapters, readRawIfConfigs, 'readRawRoutes(4)': () => readRawRoutes(4) }[name]
    expect(run).toThrow(/must not run in the Electron main process/)
  })

  it('createKoffiSource throws in the main process', () => {
    setProcessType('browser')
    expect(() => createKoffiSource(new Map())).toThrow(/native-read host/)
  })

  it('the WinINet loader rejects in the main process (catchable, so callers fall back)', async () => {
    setProcessType('browser')
    await expect(notifyWinInetInProcess()).rejects.toThrow(/must not run in the Electron main process/)
  })

  it('does not block the utility host or plain Node', () => {
    for (const value of ['utility', undefined]) {
      setProcessType(value)
      expect(() => assertKoffiAllowedHere('x')).not.toThrow()
    }
  })

  it('a guard failure is a plain Error, never a fatal abort', () => {
    setProcessType('browser')
    expect(() => assertKoffiAllowedHere('x')).toThrow(Error)
  })
})
