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
  it('executes a harmless payload longer than the failing baseline invocation', async () => {
    clearElevatedCache()
    const script = "$ErrorActionPreference='Stop';Write-Output 'TRANSPORT_OK'\n#" + 'x'.repeat(5000)
    const command = `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${Buffer.from(script, 'utf16le').toString('base64')}`
    expect(command.length).toBeGreaterThan(10482)
    expect((await execElevated(command)).stdout.trim()).toBe('TRANSPORT_OK')
  })
  it('propagates an actual PowerShell failure instead of reporting success', async () => {
    const script = "$ErrorActionPreference='Stop';throw 'NATIVE_TRANSPORT_FAILURE'"
    const command = `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${Buffer.from(script, 'utf16le').toString('base64')}`
    await expect(execElevated(command)).rejects.toThrow('NATIVE_TRANSPORT_FAILURE')
  })
})
