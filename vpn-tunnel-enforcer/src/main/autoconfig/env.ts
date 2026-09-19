import { execFile } from 'child_process'
import { mkdir, readFile, unlink, writeFile } from 'fs/promises'
import { homedir } from 'os'
import { join } from 'path'
import { promisify } from 'util'

const execFileAsync = promisify(execFile)

export interface EnvProxyBackup {
  createdAt: number
  httpProxy: string | null
  httpsProxy: string | null
  allProxy: string | null
  noProxy: string | null
}

function backupPath(): string {
  return join(homedir(), '.vpnte', 'env-proxy-backup.json')
}

function proxyUrl(proxyAddr: string, proxyType: 'socks5' | 'http'): string {
  const lastColon = proxyAddr.lastIndexOf(':')
  const host = lastColon >= 0 ? proxyAddr.slice(0, lastColon) : proxyAddr
  const port = lastColon >= 0 ? proxyAddr.slice(lastColon + 1) : ''
  // For SOCKS5 we use socks5h:// (h = resolve DNS through the proxy too).
  // curl, pip, npm, git, requests/httpx all accept this scheme. Plain socks5://
  // would resolve DNS locally, which would defeat the kill-switch (DNS could
  // leak to the ISP if Hard mode TUN is not active for the env-mode user).
  return proxyType === 'socks5' ? `socks5h://${host}:${port}` : `http://${host}:${port}`
}

async function broadcastEnvironmentChanged(): Promise<void> {
  const script = [
    '$sig = \'[DllImport("user32.dll", SetLastError=true, CharSet=CharSet.Auto)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);\'',
    '$type = Add-Type -MemberDefinition $sig -Name Win32SendMessageTimeout -Namespace Native -PassThru',
    '$result = [UIntPtr]::Zero',
    '$null = $type::SendMessageTimeout([IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, "Environment", 2, 5000, [ref]$result)'
  ].join(';')
  await execFileAsync('powershell', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script], {
    windowsHide: true,
    timeout: 10000
  }).catch(() => undefined)
}

async function getUserEnvValue(name: string): Promise<string | null> {
  try {
    const { stdout } = (await execFileAsync('reg', ['query', 'HKCU\\Environment', '/v', name], {
      windowsHide: true,
      timeout: 10000,
      encoding: 'utf8'
    })) as { stdout: string; stderr: string }
    const lines = stdout.split(/\r?\n/)
    for (const line of lines) {
      const trimmed = line.trim()
      if (trimmed.startsWith(name)) {
        const parts = trimmed.split(/\s+/)
        if (parts.length >= 3) {
          return parts.slice(2).join(' ')
        }
      }
    }
    return null
  } catch {
    return null
  }
}

async function setUserEnvValue(name: string, value: string): Promise<void> {
  await execFileAsync('setx', [name, value], {
    windowsHide: true,
    timeout: 10000
  })
}

async function deleteUserEnvValue(name: string): Promise<void> {
  await execFileAsync('reg', ['delete', 'HKCU\\Environment', '/v', name, '/f'], {
    windowsHide: true,
    timeout: 10000
  }).catch(() => undefined)
}

async function saveBackupIfMissing(): Promise<void> {
  try {
    await readFile(backupPath(), 'utf8')
    return
  } catch {
    // no backup yet
  }
  await mkdir(join(homedir(), '.vpnte'), { recursive: true })
  const backup: EnvProxyBackup = {
    createdAt: Date.now(),
    httpProxy: await getUserEnvValue('HTTP_PROXY'),
    httpsProxy: await getUserEnvValue('HTTPS_PROXY'),
    allProxy: await getUserEnvValue('ALL_PROXY'),
    noProxy: await getUserEnvValue('NO_PROXY')
  }
  await writeFile(backupPath(), JSON.stringify(backup, null, 2), 'utf8')
}

export const env = {
  name: 'Environment Variables',
  scope: 'user-global' as const,
  warning:
    'Sets user-global environment variables (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY); pre-existing variables are backed up and restored on rollback.',
  backupPath,

  async apply(proxyAddr: string, proxyType: 'socks5' | 'http' = 'socks5'): Promise<boolean> {
    const url = proxyUrl(proxyAddr, proxyType)
    try {
      await saveBackupIfMissing()
      // Set user-level environment variables (survives reboot)
      await setUserEnvValue('HTTP_PROXY', url)
      await setUserEnvValue('HTTPS_PROXY', url)
      await setUserEnvValue('ALL_PROXY', url)
      await setUserEnvValue('NO_PROXY', 'localhost,127.0.0.1,::1')
      process.env.HTTP_PROXY = url
      process.env.HTTPS_PROXY = url
      process.env.ALL_PROXY = url
      process.env.NO_PROXY = 'localhost,127.0.0.1,::1'
      await broadcastEnvironmentChanged()
      return true
    } catch {
      await this.rollback().catch(() => undefined)
      return false
    }
  },

  async rollback(): Promise<boolean> {
    try {
      let backup: EnvProxyBackup | null = null
      try {
        backup = JSON.parse(await readFile(backupPath(), 'utf8')) as EnvProxyBackup
      } catch {
        backup = null
      }

      const restoreOrDelete = async (name: string, value: string | null | undefined) => {
        if (value) {
          await setUserEnvValue(name, value).catch(() => undefined)
          process.env[name] = value
        } else {
          await deleteUserEnvValue(name)
          delete process.env[name]
        }
      }

      await restoreOrDelete('HTTP_PROXY', backup?.httpProxy ?? null)
      await restoreOrDelete('HTTPS_PROXY', backup?.httpsProxy ?? null)
      await restoreOrDelete('ALL_PROXY', backup?.allProxy ?? null)
      await restoreOrDelete('NO_PROXY', backup?.noProxy ?? null)

      await unlink(backupPath()).catch(() => undefined)
      await broadcastEnvironmentChanged()
      return true
    } catch {
      return false
    }
  },

  async isApplied(): Promise<boolean> {
    try {
      const { stdout } = (await execFileAsync('reg', ['query', 'HKCU\\Environment', '/v', 'HTTP_PROXY'], {
        windowsHide: true,
        timeout: 10000,
        encoding: 'utf8'
      })) as { stdout: string; stderr: string }
      return stdout.includes('HTTP_PROXY')
    } catch {
      return false
    }
  }
}
