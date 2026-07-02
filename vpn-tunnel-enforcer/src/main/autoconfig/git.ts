import { execFile } from 'child_process'
import { mkdir, readFile, unlink, writeFile } from 'fs/promises'
import { homedir } from 'os'
import { join } from 'path'
import { promisify } from 'util'

const execFileAsync = promisify(execFile)

interface GitProxyBackup {
  createdAt: number
  httpProxy: string | null
  httpsProxy: string | null
}

function backupPath(): string {
  return join(homedir(), '.vpnte', 'git-proxy-backup.json')
}

function proxyUrl(proxyAddr: string, proxyType: 'socks5' | 'http'): string {
  const [host, port] = proxyAddr.split(':')
  // Git supports socks5h:// natively (curl backend). socks5h forces DNS through
  // the proxy. Plain http://host:socksPort would attempt HTTP CONNECT against
  // a SOCKS port and fail for every clone/fetch.
  return proxyType === 'socks5' ? `socks5h://${host}:${port}` : `http://${host}:${port}`
}

async function gitConfig(args: string[]): Promise<{ stdout: string; stderr: string }> {
  return execFileAsync('git', ['config', ...args], {
    windowsHide: true,
    timeout: 10000,
    encoding: 'utf8'
  }) as Promise<{ stdout: string; stderr: string }>
}

async function getGlobalProxy(key: 'http.proxy' | 'https.proxy'): Promise<string | null> {
  try {
    const { stdout } = await gitConfig(['--global', '--get', key])
    const value = stdout.trim()
    return value || null
  } catch {
    return null
  }
}

async function saveBackupIfMissing(): Promise<void> {
  try {
    await readFile(backupPath(), 'utf8')
    return
  } catch {
    // no backup yet
  }
  await mkdir(join(homedir(), '.vpnte'), { recursive: true })
  const backup: GitProxyBackup = {
    createdAt: Date.now(),
    httpProxy: await getGlobalProxy('http.proxy'),
    httpsProxy: await getGlobalProxy('https.proxy')
  }
  await writeFile(backupPath(), JSON.stringify(backup, null, 2), 'utf8')
}

async function restoreGlobalProxy(key: 'http.proxy' | 'https.proxy', value: string | null): Promise<void> {
  if (value) {
    await gitConfig(['--global', key, value])
    return
  }
  await gitConfig(['--global', '--unset', key]).catch(() => undefined)
}

export const git = {
  name: 'Git',
  scope: 'user-global' as const,
  warning: 'Writes user-global git config while applied; previous global proxy is restored on rollback.',
  managedPath: () => '~/.gitconfig',
  backupPath,

  async apply(proxyAddr: string, proxyType: 'socks5' | 'http' = 'socks5'): Promise<boolean> {
    const url = proxyUrl(proxyAddr, proxyType)
    try {
      await saveBackupIfMissing()
      await gitConfig(['--global', 'http.proxy', url])
      await gitConfig(['--global', 'https.proxy', url])
      return true
    } catch {
      return false
    }
  },

  async rollback(): Promise<boolean> {
    try {
      let backup: GitProxyBackup | null = null
      try {
        backup = JSON.parse(await readFile(backupPath(), 'utf8')) as GitProxyBackup
      } catch {
        backup = null
      }
      await restoreGlobalProxy('http.proxy', backup?.httpProxy ?? null)
      await restoreGlobalProxy('https.proxy', backup?.httpsProxy ?? null)
      await unlink(backupPath()).catch(() => undefined)
      return true
    } catch {
      return false
    }
  },

  async isApplied(): Promise<boolean> {
    try {
      const { stdout } = await gitConfig(['--global', '--get', 'http.proxy'])
      return stdout.trim().length > 0
    } catch {
      return false
    }
  }
}
