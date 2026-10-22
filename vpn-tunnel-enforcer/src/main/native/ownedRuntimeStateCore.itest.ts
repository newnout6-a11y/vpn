// AT-02-001/005, AT-03-007/012: real read-only presence/absence, with harmless test-owned Node fixtures.
// No VPN is started/stopped; only the ChildProcess objects created here are terminated.
import { copyFileSync, lstatSync, mkdirSync, mkdtempSync, realpathSync, rmSync } from 'node:fs'
import { spawn, execFileSync, type ChildProcess } from 'node:child_process'
import { once } from 'node:events'
import { dirname, join, resolve } from 'node:path'
import { performance } from 'node:perf_hooks'
import { expect, it } from 'vitest'
import { readOwnedRuntimeStateInProcess } from './ownedRuntimePidCore'
import { OWNED_RUNTIME_STATUS_QUERY_SCRIPT } from '../recoveryPsProtocol'

it.runIf(process.platform === 'win32' && ['x64', 'arm64'].includes(process.arch))('observes fresh fixture state and compares with CIM when its executable paths are readable', async () => {
  const root = resolve('.tmp'); mkdirSync(root, { recursive: true })
  const dir = mkdtempSync(join(root, 'runtime-state-Тест-')), children: ChildProcess[] = []
  const runtimeDir = join(dir, 'runtime'), sibling = join(dir, 'runtime-evil')
  mkdirSync(runtimeDir); mkdirSync(sibling)
  const nativeMs: number[] = [], powershellMs: number[] = []
  let comparisons = 0, unavailable = 0
  const observe = (expected: boolean) => {
    const start = performance.now(), running = readOwnedRuntimeStateInProcess(runtimeDir)
    nativeMs.push(performance.now() - start); expect(running).toBe(expected)
    const script = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$runtimeDir='${runtimeDir.replaceAll("'", "''")}';\n${OWNED_RUNTIME_STATUS_QUERY_SCRIPT}`
    const psStart = performance.now()
    let legacy: string
    try {
      legacy = execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
        { windowsHide: true, encoding: 'utf8', timeout: 10000, stdio: 'pipe' }).trim().toLowerCase()
    } catch (error) {
      // Unelevated CIM can hide an unrelated elevated process's ExecutablePath
      // although QUERY_LIMITED_INFORMATION returns it. This is unknown CIM evidence.
      if (process.env.VPNTE_REQUIRE_CIM_RUNTIME_COMPARISON === '1' ||
          !String((error as { stderr?: unknown }).stderr).includes('Cannot prove runtime exit: executable path unavailable')) throw error
      unavailable++; return
    } finally { powershellMs.push(performance.now() - psStart) }
    expect(['true', 'false']).toContain(legacy)
    expect(legacy === 'true').toBe(running); comparisons++
  }
  const launch = async (directory: string) => {
    const file = join(directory, 'vpnte-sing-box.exe'); copyFileSync(process.execPath, file)
    const child = spawn(file, ['-e', "process.stdout.write('ready');setInterval(()=>{},1000)"], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
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
    observe(false)
    const foreign = await launch(sibling); observe(false)
    const owned = await launch(runtimeDir); observe(true)
    await stop(owned); observe(false)
    expect(foreign.exitCode).toBeNull(); expect(foreign.signalCode).toBeNull()
    if (process.env.VPNTE_REQUIRE_CIM_RUNTIME_COMPARISON === '1') expect(comparisons).toBe(4)
    console.log(JSON.stringify({ fixture: 'runtime-state-read-only', nativeMs, powershellMs, comparisons, cimUnknown: unavailable }))
  } finally {
    for (const child of children) await stop(child)
    if (dirname(dir) !== root || dirname(realpathSync(dir)) !== realpathSync(root) || lstatSync(dir).isSymbolicLink()) {
      throw new Error('Unsafe runtime fixture directory')
    }
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 })
  }
}, 30000)
