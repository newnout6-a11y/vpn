import { exec as execCb } from 'child_process'
import { promisify } from 'util'
import sudo from 'sudo-prompt'

const exec = promisify(execCb)

const ADMIN_CHECK_FAST = 'cmd /c "net session >nul 2>&1 && echo true || echo false"'
const ADMIN_CHECK_PS =
  'powershell -NoProfile -ExecutionPolicy Bypass -Command ' +
  '"[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).' +
  'IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"'

let elevatedCache: boolean | null = null

export async function isProcessElevated(): Promise<boolean> {
  if (process.platform !== 'win32') return false
  if (elevatedCache !== null) return elevatedCache

  try {
    const { stdout } = await exec(ADMIN_CHECK_FAST, {
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
    const { stdout } = await exec(ADMIN_CHECK_PS, {
      windowsHide: true,
      timeout: 5000,
      encoding: 'utf8'
    })
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

  const exe = process.execPath.replace(/"/g, '\\"')
  const args = process.argv
    .slice(1)
    .filter(arg => !arg.startsWith('--inspect'))
    .map(arg => `'${arg.replace(/'/g, "''")}'`)
    .join(',')
  const argumentList = args ? ` -ArgumentList @(${args})` : ''
  await exec(
    `powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '${exe}'${argumentList} -Verb RunAs"`,
    { windowsHide: true, timeout: 10000 }
  )
  return true
}
