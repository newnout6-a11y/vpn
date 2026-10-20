import { execFile } from 'child_process'
import { mkdir, readFile, unlink, writeFile } from 'fs/promises'
import { homedir } from 'os'
import { join } from 'path'
import { promisify } from 'util'
import { assertDocumentSchema, StoreSchemaError } from '../storeSchema'

const execFileAsync = promisify(execFile)

interface GitProxyBackup {
  schemaVersion?: number
  createdAt: number
  httpProxy: string | null
  httpsProxy: string | null
}

async function readBackup(): Promise<GitProxyBackup | null> {
  try {
    const value = JSON.parse(await readFile(backupPath(), 'utf8')) as GitProxyBackup
    assertDocumentSchema('git-proxy-backup', value)
    return value
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw error
  }
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
  if (await readBackup()) return
  await mkdir(join(homedir(), '.vpnte'), { recursive: true })
  const backup: GitProxyBackup = {
    schemaVersion: 0,
    createdAt: Date.now(),
    httpProxy: await getGlobalProxy('http.proxy'),
    httpsProxy: await getGlobalProxy('https.proxy')
  }
  if (await readBackup()) return
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
    } catch (error) {
      if (error instanceof StoreSchemaError) throw error
      return false
    }
  },

  async rollback(): Promise<boolean> {
    try {
      let backup: GitProxyBackup | null = null
      try {
        backup = await readBackup()
      } catch (error) {
        if (error instanceof StoreSchemaError) throw error
        backup = null
      }
      if (!backup) return false
      await restoreGlobalProxy('http.proxy', backup?.httpProxy ?? null)
      await restoreGlobalProxy('https.proxy', backup?.httpsProxy ?? null)
      await unlink(backupPath()).catch(() => undefined)
      return true
    } catch (error) {
      if (error instanceof StoreSchemaError) throw error
      return false
    }
  },

  async isApplied(): Promise<boolean> {
    try {
      await readBackup()
      const { stdout } = await gitConfig(['--global', '--get', 'http.proxy'])
      return stdout.trim().length > 0
    } catch (error) {
      if (error instanceof StoreSchemaError) throw error
      return false
    }
  }
}
