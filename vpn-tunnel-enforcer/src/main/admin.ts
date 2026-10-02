import { exec as execCb, execFile as execFileCb } from 'child_process'
import util, { promisify } from 'util'

// Node 22/24 removed util.isObject and util.isFunction which sudo-prompt uses internally.
if (typeof (util as any).isObject !== 'function') {
  ;(util as any).isObject = (arg: any): arg is object => typeof arg === 'object' && arg !== null
}
if (typeof (util as any).isFunction !== 'function') {
  ;(util as any).isFunction = (arg: any): arg is Function => typeof arg === 'function'
}

import sudo from 'sudo-prompt'

const exec = promisify(execCb)
const execFile = promisify(execFileCb)

const ADMIN_CHECK_FAST = 'net session >nul 2>&1 && echo true || echo false'
const ADMIN_CHECK_PS =
  '[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).' +
  'IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'

function encodedPowerShell(script: string): string {
  return Buffer.from(script, 'utf-16le').toString('base64')
}

function psQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}

let elevatedCache: boolean | null = null
let elevatedPromise: Promise<boolean> | null = null

export function clearElevatedCache(): void {
  elevatedCache = null
  elevatedPromise = null
}

export async function isProcessElevated(): Promise<boolean> {
  if (process.platform !== 'win32') return false
  if (elevatedCache !== null) return elevatedCache
  if (elevatedPromise) return elevatedPromise

  elevatedPromise = (async () => {
    try {
      const { stdout } = await execFile('cmd.exe', ['/d', '/s', '/c', ADMIN_CHECK_FAST], {
        windowsHide: true,
        timeout: 3000,
        encoding: 'utf8'
      })
      elevatedCache = stdout.trim().toLowerCase().includes('true')
      if (elevatedCache) return elevatedCache
    } catch {
      // Fast check failed — fall through to PowerShell for a definitive answer.
    }

    try {
      const { stdout } = await execFile(
        'powershell.exe',
        ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encodedPowerShell(ADMIN_CHECK_PS)],
        {
          windowsHide: true,
          timeout: 5000,
          encoding: 'utf8'
        }
      )
      elevatedCache = stdout.trim().toLowerCase() === 'true'
      return elevatedCache
    } catch {
      elevatedCache = false
      return false
    } finally {
      elevatedPromise = null
    }
  })()

  return elevatedPromise
}

export async function execElevated(
  command: string,
  options: { timeout?: number; maxBuffer?: number } = {}
): Promise<{ stdout: string; stderr: string }> {
  if (process.platform !== 'win32' || await isProcessElevated()) {
    const execOptions = {
      windowsHide: true,
      timeout: options.timeout ?? 30000,
      maxBuffer: options.maxBuffer ?? 1024 * 1024,
      encoding: 'utf8' as const
    }
    // Avoid cmd.exe's 8191-character limit for this fixed generated command.
    // Arbitrary shell commands retain their existing execution semantics.
    const encodedPowerShell = /^powershell\.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ([A-Za-z0-9+/]+={0,2})$/.exec(command)
    if (encodedPowerShell) {
      return execFile('powershell.exe', [
        '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encodedPowerShell[1]
      ], execOptions)
    }
    return exec(command, execOptions)
  }

  return new Promise((resolve, reject) => {
    sudo.exec(command, { name: 'VPN Tunnel Enforcer' }, (error, stdout, stderr) => {
      if (error) {
        reject(new Error(error.message || String(stderr || '') || 'Elevated command failed'))
      } else {
        resolve({ stdout: String(stdout ?? ''), stderr: String(stderr ?? '') })
      }
    })
  })
}

export async function relaunchElevatedIfNeeded(): Promise<boolean> {
  if (process.platform !== 'win32' || await isProcessElevated()) return false

  const exe = process.execPath
  const args = process.argv
    .slice(1)
    .filter(arg => !arg.startsWith('--inspect'))
  const psArgs = args.map(psQuote).join(', ')
  const relaunchScript = `
$ErrorActionPreference='Stop'
$file=${psQuote(exe)}
$vpnteArgs=@(${psArgs})
Start-Process -FilePath $file -ArgumentList $vpnteArgs -Verb RunAs
`
  await execFile(
    'powershell.exe',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encodedPowerShell(relaunchScript)],
    { windowsHide: true, timeout: 10000 }
  )
  return true
}
