// AT-00-003 / AT-01-008: POSIX policy branch, filesystem/identity boundary controlled.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({ uid: 1000n, gid: 10n, mode: 0o600n, denied: false, ignoreGroup: false, changeGroup: vi.fn(), changeMode: vi.fn() }))
const destination = () => ({ dev: 1n, ino: 2n, size: 3n, mtimeNs: 4n, ctimeNs: 5n, uid: 1000n, gid: 20n, mode: 0o640n, isFile: () => true })
vi.mock('fs/promises', () => ({
  lstat: vi.fn(async (path: string) => path === 'destination' ? destination() : { uid: state.uid, gid: state.gid, mode: state.mode }),
  chown: async (_path: string, uid: number, gid: number) => {
    state.changeGroup(uid, gid)
    if (state.denied) throw Object.assign(new Error('private group failure'), { code: 'EPERM' })
    state.uid = BigInt(uid); if (!state.ignoreGroup) state.gid = BigInt(gid)
  },
  chmod: async (_path: string, mode: number) => { state.changeMode(mode); state.mode = BigInt(mode) }
}))
vi.mock('fs', () => ({ lstatSync: () => destination() }))
import { prepareConfigExport } from './configExportSecurity'
const platform = Object.getOwnPropertyDescriptor(process, 'platform')!
const getuid = Object.getOwnPropertyDescriptor(process, 'getuid')
beforeEach(() => {
  state.uid = 1000n; state.gid = 10n; state.mode = 0o600n; state.denied = false; state.ignoreGroup = false
  vi.clearAllMocks()
  Object.defineProperty(process, 'platform', { value: 'linux', configurable: true })
  Object.defineProperty(process, 'getuid', { value: () => 1000, configurable: true })
})
afterEach(() => {
  Object.defineProperty(process, 'platform', platform)
  if (getuid) Object.defineProperty(process, 'getuid', getuid)
  else Reflect.deleteProperty(process, 'getuid')
})
describe('POSIX export destination policy', () => {
  it('copies and verifies the existing group before admitting plaintext', async () => {
    const verify = await prepareConfigExport('empty-staging', 'destination')
    expect(state.changeGroup).toHaveBeenCalledWith(1000, 20)
    expect(state.gid).toBe(20n); expect(state.mode).toBe(0o640n)
    expect(state.changeGroup.mock.invocationCallOrder[0]).toBeLessThan(state.changeMode.mock.invocationCallOrder[0])
    expect(verify).not.toThrow()
  })
  it('rejects replacement when the original group cannot be preserved', async () => {
    state.denied = true
    await expect(prepareConfigExport('empty-staging', 'destination')).rejects.toMatchObject({ code: 'EPERM' })
    expect(state.mode).toBe(0o600n)
  })
  it('rejects a silent group mismatch after chown', async () => {
    state.ignoreGroup = true
    await expect(prepareConfigExport('empty-staging', 'destination')).rejects.toMatchObject({ category: 'permission' })
  })
})
