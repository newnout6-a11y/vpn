import { readFile, writeFile, mkdir, rename } from 'fs/promises'
import { join } from 'path'
import { homedir } from 'os'

function getGradlePropsPath(): string {
  return join(homedir(), '.gradle', 'gradle.properties')
}

function getGradleBackupPath(): string {
  return getGradlePropsPath() + '.vpn-backup'
}

async function writeAtomic(path: string, content: string): Promise<void> {
  const tmp = `${path}.vpnte-${process.pid}-${Date.now()}.tmp`
  await writeFile(tmp, content, 'utf-8')
  await rename(tmp, path)
}

async function writeBackupIfMissing(path: string, content: string): Promise<void> {
  const backupPath = getGradleBackupPath()
  try {
    await readFile(backupPath, 'utf-8')
    return
  } catch {
    await writeAtomic(backupPath, content)
  }
}

export const gradle = {
  name: 'Gradle',
  scope: 'user-global' as const,
  warning: 'Writes the user-global ~/.gradle/gradle.properties file while applied; the original file is restored on rollback.',
  managedPath: getGradlePropsPath,
  backupPath: getGradleBackupPath,

  async apply(proxyAddr: string, proxyType: 'socks5' | 'http' = 'socks5'): Promise<boolean> {
    const [host, port] = proxyAddr.split(':')
    const propsPath = getGradlePropsPath()
    const gradleDir = join(homedir(), '.gradle')

    try {
      await mkdir(gradleDir, { recursive: true })
      let content = ''
      try {
        content = await readFile(propsPath, 'utf-8')
      } catch { content = '' }

      // Keep the original backup across repeated Apply clicks.
      await writeBackupIfMissing(propsPath, content)

      // Remove old VPN entries
      content = content.replace(/# VPN Tunnel Enforcer[\s\S]*?(?=\n[^\n]|\n*$)/g, '').trimEnd()

      // Gradle's JVM proxy switches differ for SOCKS vs HTTP. Mismatched scheme
      // (socksProxyHost pointed at an HTTP port, or http.proxyHost at a SOCKS
      // port) silently breaks every dependency download.
      const proxyLines = proxyType === 'socks5'
        ? `\n# VPN Tunnel Enforcer\nsystemProp.socksProxyHost=${host}\nsystemProp.socksProxyPort=${port}\nsystemProp.http.nonProxyHosts=localhost|127.*|[::1]\n`
        : `\n# VPN Tunnel Enforcer\nsystemProp.http.proxyHost=${host}\nsystemProp.http.proxyPort=${port}\nsystemProp.https.proxyHost=${host}\nsystemProp.https.proxyPort=${port}\nsystemProp.http.nonProxyHosts=localhost|127.*|[::1]\n`
      content += proxyLines

      await writeAtomic(propsPath, content)
      return true
    } catch {
      return false
    }
  },

  async rollback(): Promise<boolean> {
    const propsPath = getGradlePropsPath()
    try {
      const backup = await readFile(propsPath + '.vpn-backup', 'utf-8')
      await writeAtomic(propsPath, backup)
      return true
    } catch {
      return false
    }
  },

  async isApplied(): Promise<boolean> {
    const propsPath = getGradlePropsPath()
    try {
      const content = await readFile(propsPath, 'utf-8')
      return content.includes('VPN Tunnel Enforcer')
    } catch {
      return false
    }
  }
}
