// AT-00-002 / AT-02-002: real read-only Win32/CIM comparison against harmless, test-owned Node processes.
// Their name is deliberately unrelated to the live VPN runtime; this test never switches a VPN.
import { copyFileSync, lstatSync, mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs'
import { spawn, execFileSync, type ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import { dirname, join, resolve } from 'node:path'
import { performance } from 'node:perf_hooks'
import { describe, expect, it } from 'vitest'
import { readOwnedRuntimePidInProcess } from './ownedRuntimePidCore'

describe.runIf(process.platform === 'win32' && ['x64', 'arm64'].includes(process.arch))('Win32 owned PID on real Windows', () => {
  it('agrees with CIM, keeps foreign siblings alive, refuses duplicate owners and rereads after exit', async () => {
    const root = resolve('.tmp'); mkdirSync(root, { recursive: true })
    const dir = mkdtempSync(join(root, 'owned-pid-Тест-')), children: ChildProcess[] = []
    const executable = join(dir, 'vpnte-pid-fixture.exe')
    const launch = async (path: string) => {
      const child = spawn(path, ['-e', "process.stdout.write('ready'); setInterval(()=>{},1000)"],
        { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
      children.push(child)
      let timer: ReturnType<typeof setTimeout> | undefined
      try {
        await Promise.race([once(child.stdout, 'data'), once(child, 'error').then(() => { throw new Error('Fixture launch failed') }),
          new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Fixture readiness timeout')), 5000) })])
      } finally { clearTimeout(timer) }
      return child
    }
    const stop = async (child: ChildProcess) => {
      if (child.exitCode !== null || child.signalCode !== null) return
      const exited = once(child, 'exit'); child.kill(); await exited
    }
    try {
      copyFileSync(process.execPath, executable)
      const owned = await launch(executable)
      const start = performance.now(), nativePid = readOwnedRuntimePidInProcess(executable)
      const nativeMs = performance.now() - start
      expect(nativePid).toBe(owned.pid)
      expect(readOwnedRuntimePidInProcess(executable.toUpperCase())).toBe(owned.pid)
      const quote = (value: string) => `'${value.replaceAll("'", "''")}'`
      const script = `$ErrorActionPreference='Stop'; $rows=@(Get-CimInstance Win32_Process -Filter "Name='vpnte-pid-fixture.exe'");
if (@($rows | Where-Object { [string]::IsNullOrWhiteSpace($_.ExecutablePath) }).Count) { throw 'Path unavailable' }
$owned=@($rows | Where-Object { [string]::Equals($_.ExecutablePath,${quote(executable)},[StringComparison]::OrdinalIgnoreCase) });
if ($owned.Count -ne 1) { throw 'Exactly one required' }; [string]$owned[0].ProcessId`
      const psStart = performance.now()
      const oldPid = Number(execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
        { windowsHide: true, timeout: 10000, encoding: 'utf8', stdio: 'pipe' }).trim())
      expect(oldPid).toBe(nativePid)
      console.log(JSON.stringify({ fixture: 'owned-PID-read-only', nativeMs, powershellMs: performance.now() - psStart }))

      const sibling = join(dir, 'другой-каталог'); mkdirSync(sibling)
      const otherExecutable = join(sibling, 'vpnte-pid-fixture.exe'); copyFileSync(process.execPath, otherExecutable)
      const foreign = await launch(otherExecutable)
      expect(readOwnedRuntimePidInProcess(executable)).toBe(owned.pid)
      const duplicate = await launch(executable)
      expect(() => readOwnedRuntimePidInProcess(executable)).toThrow(/exactly one owned process/)
      await stop(duplicate)
      expect(readOwnedRuntimePidInProcess(executable)).toBe(owned.pid)
      await stop(owned)
      expect(() => readOwnedRuntimePidInProcess(executable)).toThrow(/exactly one owned process/)
      expect(foreign.exitCode).toBeNull()
      expect(foreign.signalCode).toBeNull()
    } finally {
      for (const child of children) await stop(child)
      if (dirname(dir) !== root || dirname(realpathSync(dir)) !== realpathSync(root) || lstatSync(dir).isSymbolicLink()) {
        throw new Error('Unsafe owned PID fixture directory')
      }
      rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 })
    }
  }, 20000)
})
