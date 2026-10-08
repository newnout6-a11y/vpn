// AT-00-007 / AT-02-005 / AT-03-006/007/012: real queues, fake owned native processes.
import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const mocks = vi.hoisted(() => ({ spawn: vi.fn(), elevated: vi.fn(async () => true) }))
vi.mock('child_process', () => ({ spawn: mocks.spawn }))
vi.mock('./admin', () => ({ isProcessElevated: mocks.elevated }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
function nativeProcess() {
  const proc = Object.assign(new EventEmitter(), { pid: 123, stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), kill: vi.fn(() => true) })
  const writes: Array<{ id: number; request: { op: string } }> = []
  const reply = (id: number, value: string) => proc.stdout.write(JSON.stringify({ id, ok: true, value }) + '\n')
  proc.stdin.on('data', data => {
    const line = data.toString().trim()
    if (line === '__EXIT__') { queueMicrotask(() => proc.emit('close', 0)); return }
    writes.push(JSON.parse(line))
  })
  queueMicrotask(() => reply(0, 'RECOVERY_WORKER_READY'))
  return { proc, writes, reply }
}
let processes: ReturnType<typeof nativeProcess>[] = []
beforeEach(() => {
  vi.resetModules(); vi.clearAllMocks(); processes = []
  mocks.spawn.mockImplementation(() => { const p = nativeProcess(); processes.push(p); return p.proc })
})
afterEach(async () => {
  for (const p of processes) p.proc.emit('close', 0)
  await (await import('./recoveryPsWorker')).stopRecoveryPsWorker()
})
describe.skipIf(process.platform !== 'win32')('isolated adapter inspection ownership', () => {
  it('keeps runtime ACL reads independent of a held full adapter snapshot', async () => {
    const api = await import('./recoveryPsWorker')
    let settled = false
    const snapshot = api.executeAdapterInspection('inspect-physical-adapters', 20000).then(value => { settled = true; return value })
    await vi.waitFor(() => expect(processes[0]?.writes).toHaveLength(1))
    const acl = api.executeRecoveryOperation({ op: 'inspect-runtime-acl', runtimeDir: 'C:\\fixture' })
    await vi.waitFor(() => expect(processes[1]?.writes).toHaveLength(1))
    processes[1].reply(processes[1].writes[0].id, 'FRESH_ACL')
    expect(await acl).toBe('FRESH_ACL'); expect(settled).toBe(false)
    processes[0].reply(processes[0].writes[0].id, '[]')
    expect(await snapshot).toBe('[]')
    expect(mocks.spawn).toHaveBeenCalledTimes(2)
  })
  it('reuses one inspection process while returning fresh observations', async () => {
    const api = await import('./recoveryPsWorker')
    for (const [op, value] of [['inspect-physical-adapters', 'FIRST'], ['inspect-transition-adapters', '{}'], ['inspect-physical-adapters', 'CHANGED']] as const) {
      const pending = api.executeAdapterInspection(op, 20000)
      const count = processes[0]?.writes.length || 0
      await vi.waitFor(() => expect(processes[0]?.writes).toHaveLength(count + 1))
      const p = processes[0]; p.reply(p.writes.at(-1)!.id, value)
      expect(await pending).toBe(value)
    }
    expect(mocks.spawn).toHaveBeenCalledOnce()
  })
  it('keeps narrow DNS and fresh TUN proof in the prepared adapter process (AT-03-006/010)', async () => {
    const api = await import('./recoveryPsWorker')
    const requests = [{op:'inspect-physical-dns'}, {op:'inspect-tun',alias:'Ethernet 5'}] as const
    for (const request of requests) {
      const pending = api.executeRecoveryOperation(request)
      const count = processes[0]?.writes.length || 0
      await vi.waitFor(() => expect(processes[0]?.writes).toHaveLength(count + 1))
      const p = processes[0]; p.reply(p.writes.at(-1)!.id, 'FRESH')
      expect(await pending).toBe('FRESH')
    }
    expect(mocks.spawn).toHaveBeenCalledOnce()
  })
  it('waits admitted work in both processes before shutdown and closes both admissions', async () => {
    const api = await import('./recoveryPsWorker')
    const adapter = api.executeAdapterInspection('inspect-physical-adapters')
    const recovery = api.executeRecoveryOperation({ op: 'ensure' })
    await vi.waitFor(() => expect(processes).toHaveLength(2))
    await vi.waitFor(() => expect(processes.every(p => p.writes.length === 1)).toBe(true))
    let stopped = false
    const stopping = api.stopRecoveryPsWorker().then(() => { stopped = true })
    await expect(api.executeAdapterInspection('inspect-physical-adapters')).rejects.toMatchObject({ code: 'closed' })
    await expect(api.executeRecoveryOperation({ op: 'ensure' })).rejects.toMatchObject({ code: 'closed' })
    expect(stopped).toBe(false)
    for (const p of processes) p.reply(p.writes[0].id, 'DONE')
    await Promise.all([adapter, recovery, stopping])
    expect(stopped).toBe(true)
    for (const p of processes) expect(p.proc.kill).not.toHaveBeenCalled()
  })
  it('rejects mutation, arbitrary scripts and invalid deadlines before spawning', async () => {
    const api = await import('./recoveryPsWorker')
    for (const op of ['remove', 'stop-runtime', 'Get-NetAdapter', 'INSPECT-PHYSICAL-ADAPTERS']) {
      await expect(api.executeAdapterInspection(op as any)).rejects.toThrow()
    }
    await expect(api.executeAdapterInspection('inspect-physical-adapters', 0)).rejects.toThrow()
    expect(mocks.spawn).not.toHaveBeenCalled()
  })
  it('does not spawn a deferred process after shutdown closes admission', async () => {
    let finish!: (value: boolean) => void
    mocks.elevated.mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
    const api = await import('./recoveryPsWorker')
    const pending = api.executeAdapterInspection('inspect-physical-adapters').catch(error => error)
    await Promise.resolve()
    const stopping = api.stopRecoveryPsWorker()
    finish(true)
    expect(await pending).toMatchObject({code:'closed'})
    await stopping
    expect(mocks.spawn).not.toHaveBeenCalled()
  })
})
