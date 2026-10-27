// AT-03-007 / F-033: native transport only; no registry, tasks or network changes.
import { describe, expect, it, vi } from 'vitest'

vi.mock('child_process', async importOriginal => {
  const actual = await importOriginal<typeof import('child_process')>()
  const execFile = (file: string, args: string[], options: any, callback: Function) => {
    // Exercise the production elevated branch without asking for elevation.
    if (file === 'cmd.exe') return callback(null, { stdout: 'true', stderr: '' })
    return actual.execFile(file, args, options, (error, stdout, stderr) => callback(error, { stdout, stderr }))
  }
  return { ...actual, execFile, default: { ...actual, execFile } }
})
import { clearElevatedCache, execElevated } from './admin'

describe.skipIf(process.platform !== 'win32')('native PowerShell recovery transport', () => {
  // The long-command boundary is covered with mocked child_process in
  // admin.test.ts. An artificial 5000-character encoded comment triggered
  // Defender; sending that synthetic payload to a real interpreter adds no
  // coverage of recovery behavior and must not run on developer machines.
  it('propagates an actual PowerShell failure instead of reporting success', async () => {
    clearElevatedCache()
    const script = "$ErrorActionPreference='Stop';throw 'NATIVE_TRANSPORT_FAILURE'"
    const command = `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${Buffer.from(script, 'utf16le').toString('base64')}`
    await expect(execElevated(command)).rejects.toThrow('NATIVE_TRANSPORT_FAILURE')
  })
})
