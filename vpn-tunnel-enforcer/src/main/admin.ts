import { exec as execCb, execFile as execFileCb } from 'child_process'
import { promisify } from 'util'
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

export async function isProcessElevated(): Promise<boolean> {
  if (process.platform !== 'win32') return false
  if (elevatedCache !== null) return elevatedCache

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
  }
}

export async function execElevated(
  command: string,
  options: { timeout?: number; maxBuffer?: number } = {}
): Promise<{ stdout: string; stderr: string }> {
  if (process.platform !== 'win32' || await isProcessElevated()) {
    return exec(command, {
      windowsHide: true,
      timeout: options.timeout ?? 30000,
      maxBuffer: options.maxBuffer ?? 1024 * 1024,
      encoding: 'utf8'
    })
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
