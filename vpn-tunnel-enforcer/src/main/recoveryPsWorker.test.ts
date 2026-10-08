// AT-00-007 / AT-02-005 / AT-03-007/012: real transport, fake owned process boundary.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import type { ChildProcess, spawn } from 'node:child_process'
import { spawn as nativeSpawn } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { gzipSync, gunzipSync } from 'node:zlib'
import { createHash } from 'node:crypto'
vi.mock('./admin', () => ({ isProcessElevated: vi.fn(async () => false) }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
import { RecoveryPsWorker } from './recoveryPsWorker'
import { validateRecoveryRequest } from './recoveryPsProtocol'

function fixture() {
  const process = Object.assign(new EventEmitter(), {
    pid: 123, stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), kill: vi.fn(() => true)
  })
  const writes: Array<{id: number; request: any}> = []
  let ended = false
  process.stdin.on('data', data => {
    const line = data.toString().trim()
    if (line === '__EXIT__') { ended = true; queueMicrotask(() => process.emit('close', 0)); return }
    writes.push(JSON.parse(line))
  })
  const worker = new RecoveryPsWorker('C:\\ProgramData', (() => process as unknown as ChildProcess) as typeof spawn)
  const reply = (id: number, value: string) => process.stdout.write(JSON.stringify({ id, ok: true, value }) + '\n')
  reply(0, 'RECOVERY_WORKER_READY')
  return { worker, process, writes, reply, get ended() { return ended } }
}
afterEach(() => vi.useRealTimers())
describe('typed recovery worker ownership', () => {
  it('holds a 5-second runtime query until confirmed child close on timeout', async () => {
    vi.useFakeTimers()
    const f = fixture()
    let settled = false
    const pending = f.worker.execute({ op: 'inspect-runtime', runtimeDir: 'C:\\VPNTE-fixture-runtime' }, 5000)
      .catch(error => { settled = true; return error })
    await Promise.resolve()
    expect(f.writes[0].request).toEqual({ op: 'inspect-runtime', runtimeDir: 'C:\\VPNTE-fixture-runtime' })
    await vi.advanceTimersByTimeAsync(4999)
    expect(f.process.kill).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    expect(f.process.kill).toHaveBeenCalledOnce()
    f.reply(f.writes[0].id, 'false')
    expect(settled).toBe(false)
    f.process.emit('close', 1)
    expect(await pending).toMatchObject({ code: 'timeout' })
  })
  it.each([
    {op:'ensure',script:'Get-Item'}, {op:'protect',name:'firewall.json'}, {op:'read',name:'../x'},
    {op:'read',name:'a\\b'}, {op:'read',name:'x',path:'C:\\x'}, {op:'inspect-tun',alias:'Ethernet 5;evil'}, {op:'unknown'},
    {op:'quarantine',name:'../firewall.json',contentHash:'a'.repeat(64)}, {op:'quarantine',name:'firewall.json',contentHash:'evil'},
    {op:'quarantine',name:'firewall.json',contentHash:'a'.repeat(64),script:'evil'},
    {op:'inspect-runtime-acl',runtimeDir:'C:\\runtime',script:'Get-Acl'},
    ...['relative', 'C:\\..\\runtime', 'C:\\runtime:stream'].map(runtimeDir => ({op:'inspect-runtime-acl',runtimeDir})),
    {op:'inspect-physical-adapters',script:'Get-NetAdapter'}, {op:'inspect-physical-adapters',alias:'Wi-Fi'}
  ])('rejects unexpected fields, paths and operations before dispatch: %j', request => {
    expect(() => validateRecoveryRequest(request as any)).toThrow('Invalid')
  })
  it('serializes concurrent operations and validates IDs (AT-00-007)', async () => {
    const f = fixture()
    const a = f.worker.execute({op:'read',name:'firewall.json'})
    const b = f.worker.execute({op:'ensure'})
    await Promise.resolve()
    expect(f.writes).toHaveLength(1)
    f.reply(f.writes[0].id,'RECOVERY_ARTIFACT_ABSENT')
    expect(await a).toBe('RECOVERY_ARTIFACT_ABSENT')
    expect(f.writes).toHaveLength(2)
    f.reply(f.writes[1].id,'RECOVERY_STORAGE_VERIFIED')
    await b
    await f.worker.stop()
    expect(f.ended).toBe(true)
  })
  it('retains a timed-out native operation until actual process close (AT-02-005)', async () => {
    vi.useFakeTimers()
    const f = fixture()
    let settled = false
    const operation = f.worker.execute({op:'protect',name:'tmp-00000000-0000-0000-0000-000000000001'},20)
    const result = operation.catch(error => {settled=true;return error})
    await Promise.resolve()
    await vi.advanceTimersByTimeAsync(20)
    expect(f.process.kill).toHaveBeenCalledOnce()
    expect(settled).toBe(false)
    // A late response after timeout cannot commit/resolve the operation.
    f.reply(f.writes[0].id,'RECOVERY_TEMP_VERIFIED')
    expect(settled).toBe(false)
    f.process.emit('close',1)
    expect(await result).toMatchObject({code:'timeout'})
    expect(f.worker.hasExited).toBe(true)
  })
  it('waits admitted work before shutdown and refuses new commands (AT-02-005)', async () => {
    const f = fixture()
    const pending = f.worker.execute({op:'remove',name:'firewall.json'})
    await Promise.resolve()
    const stopping = f.worker.stop()
    await expect(f.worker.execute({op:'ensure'})).rejects.toMatchObject({code:'closed'})
    expect(f.ended).toBe(false)
    expect(f.process.kill).not.toHaveBeenCalled()
    f.reply(f.writes[0].id,'RECOVERY_ARTIFACT_REMOVED')
    await pending
    await stopping
    expect(f.ended).toBe(true)
  })
  it('does not confuse a command error with worker availability (AT-03-007)', async () => {
    const f = fixture()
    const pending = f.worker.execute({op:'ensure'})
    await Promise.resolve()
    f.process.stdout.write(JSON.stringify({id:f.writes[0].id,ok:false,error:'ACL rejected'})+'\n')
    await expect(pending).rejects.toMatchObject({code:'rejected'})
    await f.worker.stop()
  })
  it.each(['wrong-id','malformed','oversized','wrong-value'])('fails closed on %s response after confirmed close', async variant => {
    const f = fixture()
    const pending = f.worker.execute({op:'ensure'}).catch(error=>error)
    await Promise.resolve()
    const frame = variant==='wrong-id'?JSON.stringify({id:999,ok:true,value:'x'}) : variant==='wrong-value'?JSON.stringify({id:f.writes[0].id,ok:true,value:0}) : variant==='oversized'?'x'.repeat(13*1024*1024):'not json'
    f.process.stdout.write(frame+'\n')
    expect(f.process.kill).toHaveBeenCalledOnce()
    f.process.emit('close',1)
    expect(await pending).toMatchObject({code:'protocol'})
  })
  it('decodes split UTF8 without corrupting trusted JSON contents', async () => {
    const f=fixture()
    const pending=f.worker.execute({op:'read',name:'firewall.json'})
    await Promise.resolve()
    const data=Buffer.from(JSON.stringify({id:f.writes[0].id,ok:true,value:'сеть'})+'\n')
    for(const byte of data)f.process.stdout.write(Buffer.from([byte]))
    expect(await pending).toBe('сеть')
    await f.worker.stop()
  })
  it('bounds admitted requests without dispatching overflow (AT-00-007)', async () => {
    const f=fixture()
    const admitted=Array.from({length:8},()=>f.worker.execute({op:'ensure'}).catch(error=>error))
    await Promise.resolve()
    await expect(f.worker.execute({op:'ensure'})).rejects.toMatchObject({code:'busy'})
    expect(f.writes).toHaveLength(1)
    f.process.emit('close',1)
    expect((await Promise.all(admitted)).every(e=>e.code==='exited')).toBe(true)
  })
  it('forces only an idle worker after the exit grace and still awaits close', async () => {
    vi.useFakeTimers()
    const f=fixture()
    // Simulate a worker ignoring stdin EOF; no active native command remains.
    f.process.stdin.removeAllListeners('data')
    let settled=false
    const stopping=f.worker.stop().then(()=>{settled=true})
    await vi.advanceTimersByTimeAsync(1000)
    expect(f.process.kill).toHaveBeenCalledOnce()
    expect(settled).toBe(false)
    f.process.emit('close',0)
    await stopping
    expect(settled).toBe(true)
  })
  it.skipIf(process.platform !== 'win32')('executes real fixed JSON framing and read-only module warm-up, then confirms owned exit', async () => {
    const worker=new RecoveryPsWorker(process.env.ProgramData || 'C:\\ProgramData')
    try {
      expect(await worker.execute({op:'warmup'})).toBe('RECOVERY_MODULES_READY')
      expect(await worker.execute({op:'warmup'})).toBe('RECOVERY_MODULES_READY')
    } finally { await worker.stop() }
    expect(worker.hasExited).toBe(true)
  },25000)

  it.skipIf(process.platform !== 'win32')('reads native Get-Content strings through production framing without serializing provider metadata (AT-03-002/003)', async () => {
    const root = mkdtempSync(join(process.cwd(), '.tmp', 'recovery-native-read-'))
    const report = '  {"schemaVersion":1,"owner":"VPNTE","completedAt":1,"status":"warnings","messages":[{"time":1,"message":"Сеть \\u2603 — проверка"}]}\r\n'
    writeFileSync(join(root, 'recovery-result.json'), '\ufeff' + report, 'utf8')
    writeFileSync(join(root, 'second.json'), '{"second":"строка\\nс кавычками \\" и слешем \\\\"}\n', 'utf8')
    writeFileSync(join(root, 'empty.json'), '')
    // Only the trusted storage boundary is stubbed; dispatcher, Get-Item,
    // Get-Content, PS 5.1 serialization, pipes and JS receiver are production.
    const isolatedSpawn: typeof nativeSpawn = ((command: string, args: string[], options: any) => {
      const launcher = Buffer.from(args.at(-1)!, 'base64').toString('utf16le')
      const compressed = launcher.match(/FromBase64String\('([^']+)'\)/)![1]
      const script = gunzipSync(Buffer.from(compressed, 'base64')).toString('utf8')
      const isolated = script.replace("[Console]::Out.WriteLine('{\"id\":0", `
function Get-RecoveryRoot { return '${root.replace(/'/g, "''")}' }
function Assert-RecoveryDirectories($root, [bool]$create) { return $true }
function Assert-TrustedArtifact($path, $directory) { }
[Console]::Out.WriteLine('{"id":0`)
      const isolatedLauncher = launcher.replace(compressed, gzipSync(Buffer.from(isolated, 'utf8')).toString('base64'))
      return nativeSpawn(command, [...args.slice(0, -1), Buffer.from(isolatedLauncher, 'utf16le').toString('base64')], options)
    }) as typeof nativeSpawn
    const worker = new RecoveryPsWorker(process.env.ProgramData || 'C:\\ProgramData', isolatedSpawn)
    try {
      const reads = await Promise.all([
        worker.execute({ op: 'read', name: 'recovery-result.json' }),
        worker.execute({ op: 'read', name: 'second.json' }),
        worker.execute({ op: 'read', name: 'recovery-result.json' })
      ])
      expect(reads[0]).toBe(report)
      expect(reads[2]).toBe(report)
      expect(JSON.parse(reads[0]).messages[0].message).toBe('Сеть ☃ — проверка')
      expect(reads[1]).not.toContain('PSPath')
      expect(JSON.parse(reads[1]).second).toContain('строка')
      expect(await worker.execute({ op: 'read', name: 'absent.json' })).toBe('RECOVERY_ARTIFACT_ABSENT')
      await expect(worker.execute({ op: 'read', name: 'empty.json' })).rejects.toMatchObject({ code: 'rejected' })
      expect(await worker.execute({ op: 'read', name: 'recovery-result.json' })).toBe(report)
      writeFileSync(join(root, 'corrupt.json'), '{\r\n', 'utf8')
      await expect(worker.execute({ op: 'quarantine', name: 'corrupt.json', contentHash: 'a'.repeat(64) })).rejects.toMatchObject({ code: 'rejected' })
      expect(await worker.execute({ op: 'quarantine', name: 'corrupt.json', contentHash: createHash('sha256').update('{').digest('hex') })).toBe('RECOVERY_ARTIFACT_QUARANTINED')
      expect(await worker.execute({ op: 'read', name: 'corrupt.json' })).toBe('RECOVERY_ARTIFACT_ABSENT')
    } finally { await worker.stop(); rmSync(root, { recursive: true, force: true }) }
    expect(worker.hasExited).toBe(true)
  },25000)
})
