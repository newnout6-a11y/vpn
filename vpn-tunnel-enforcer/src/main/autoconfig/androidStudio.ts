import { readFile, writeFile, mkdir, stat, readdir, unlink } from 'fs/promises'
import { join } from 'path'
import { homedir } from 'os'
import { exec } from 'child_process'
import { promisify } from 'util'
import net from 'net'

const execAsync = promisify(exec)

function getConfigDir(): string {
  // On Windows, Android Studio config lives in %APPDATA%\Google
  if (process.platform === 'win32') {
    return join(process.env.APPDATA || join(homedir(), 'AppData', 'Roaming'), 'Google')
  }
  return join(homedir(), '.config', 'Google')
}

async function findAndroidStudioDirs(): Promise<string[]> {
  const configDir = getConfigDir()
  try {
    const entries = await readdir(configDir)
    return entries
      .filter((e: string) => e.startsWith('AndroidStudio'))
      .map((e: string) => join(configDir, e))
  } catch {
    return []
  }
}

export function parseProxyAddr(proxyAddr: string): { host: string; port: string } | null {
  if (!proxyAddr || typeof proxyAddr !== 'string') return null
  const trimmed = proxyAddr.trim()
  let host = ''
  let portStr = ''

  if (trimmed.startsWith('[')) {
    const closeBracket = trimmed.indexOf(']')
    if (closeBracket === -1) return null
    host = trimmed.slice(1, closeBracket).trim()
    const after = trimmed.slice(closeBracket + 1)
    if (!after.startsWith(':')) return null
    portStr = after.slice(1)
  } else {
    const lastColon = trimmed.lastIndexOf(':')
    if (lastColon <= 0) return null
    // If there are multiple colons and no brackets, it's an unbracketed IPv6 without a distinct port
    if (trimmed.indexOf(':') !== lastColon) return null
    host = trimmed.slice(0, lastColon).trim()
    portStr = trimmed.slice(lastColon + 1)
  }

  if (trimmed.startsWith('[') && net.isIP(host) !== 6) return null
  // Host must be non-empty
  if (!host || host.length === 0) return null

  // Port must be strictly integer digits (no trailing junk or decimal numbers)
  if (!/^\d+$/.test(portStr)) {
    return null
  }

  const portNum = parseInt(portStr, 10)
  if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
    return null
  }

  // Validate host: either valid IP (v4/v6) or valid hostname
  if (net.isIP(host) === 0) {
    if (!/^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(host)) {
      return null
    }
  }

  return { host, port: String(portNum) }
}

async function writeBackupIfMissing(filePath: string, content: string): Promise<void> {
  try { await stat(filePath + '.vpn-created'); return } catch (err: any) { if (err?.code !== 'ENOENT') throw err }
  const backupPath = filePath + '.vpn-backup'
  try {
    await stat(backupPath)
    // Backup already exists from earlier run; preserve it
  } catch (err: any) {
    if (err?.code !== 'ENOENT') throw err
    await writeFile(backupPath, content, 'utf-8')
  }
}

export const androidStudio = {
  name: 'Android Studio',

  async apply(proxyAddr: string, proxyType: 'socks5' | 'http' = 'socks5'): Promise<boolean> {
    const parsed = parseProxyAddr(proxyAddr)
    if (!parsed) return false
    const { host, port } = parsed
    const isSocks = proxyType === 'socks5'
    const dirs = await findAndroidStudioDirs()

    // If no config dir exists yet (first run), create one for the newest-looking folder
    const targetDirs = dirs.length > 0 ? dirs : [join(getConfigDir(), 'AndroidStudio')]
    if (dirs.length === 0) {
      try {
        await mkdir(targetDirs[0], { recursive: true })
      } catch {
        return false
      }
    }

    let allSuccess = targetDirs.length > 0

    for (const dir of targetDirs) {
      let dirSuccess = true

      // 1. Patch options/other.xml using correct JetBrains component name
      const optionsDir = join(dir, 'options')
      try {
        await mkdir(optionsDir, { recursive: true })
        const otherXmlPath = join(optionsDir, 'other.xml')

        let content = ''
        let hadFile = true
        try {
          content = await readFile(otherXmlPath, 'utf-8')
        } catch (err: any) {
          if (err?.code !== 'ENOENT') throw err
          content = '<application>\n</application>'
          hadFile = false
        }

        if (hadFile) {
          await writeBackupIfMissing(otherXmlPath, content)
        } else {
          await writeFile(otherXmlPath + '.vpn-created', 'created', 'utf-8')
        }

        const proxyEntry = `<component name="HttpConfigurable">
    <option name="USE_HTTP_PROXY" value="true" />
    <option name="PROXY_HOST" value="${host}" />
    <option name="PROXY_PORT" value="${port}" />
    <option name="PROXY_TYPE_IS_SOCKS" value="${isSocks}" />
  </component>`

        if (/component\s+name="HttpConfigurable"/.test(content)) {
          content = content.replace(/<component\s+name="HttpConfigurable"[\s\S]*?<\/component>/, proxyEntry)
        } else if (content.includes('</application>')) {
          content = content.replace('</application>', `  ${proxyEntry}\n</application>`)
        } else {
          content = `<application>\n  ${proxyEntry}\n</application>`
        }
        await writeFile(otherXmlPath, content, 'utf-8')
      } catch {
        dirSuccess = false
      }

      // 2. Write user vmoptions with JVM-level proxy args (required for First Run Wizard)
      const vmoptsPath = join(dir, 'studio64.exe.vmoptions')
      try {
        let content = ''
        let hadFile = true
        try {
          content = await readFile(vmoptsPath, 'utf-8')
        } catch (err: any) {
          if (err?.code !== 'ENOENT') throw err
          content = ''
          hadFile = false
        }

        if (hadFile) {
          await writeBackupIfMissing(vmoptsPath, content)
        } else {
          await writeFile(vmoptsPath + '.vpn-created', 'created', 'utf-8')
        }

        const marker = '# VPN-Tunnel-Enforcer'
        const proxyBlock = isSocks
          ? `${marker}\n-DsocksProxyHost=${host}\n-DsocksProxyPort=${port}\n-Dhttp.nonProxyHosts=localhost|127.0.0.1\n# /VPN-Tunnel-Enforcer\n`
          : `${marker}\n-Dhttp.proxyHost=${host}\n-Dhttp.proxyPort=${port}\n-Dhttps.proxyHost=${host}\n-Dhttps.proxyPort=${port}\n-Dhttp.nonProxyHosts=localhost|127.0.0.1\n# /VPN-Tunnel-Enforcer\n`

        if (content.includes(marker)) {
          content = content.replace(/# VPN-Tunnel-Enforcer[\s\S]*?# \/VPN-Tunnel-Enforcer\n?/, proxyBlock)
        } else {
          content = (content.trimEnd() + '\n' + proxyBlock).trimStart()
        }
        await writeFile(vmoptsPath, content, 'utf-8')
      } catch {
        dirSuccess = false
      }

      if (!dirSuccess) {
        allSuccess = false
      }
    }

    return allSuccess
  },

  async rollback(): Promise<boolean> {
    const dirs = await findAndroidStudioDirs()
    let success = true
    for (const dir of dirs) {
      for (const file of [join(dir, 'options', 'other.xml'), join(dir, 'studio64.exe.vmoptions')]) {
        const readOptional = async (path: string) => {
          try { return await readFile(path, 'utf-8') }
          catch (err: any) { if (err?.code === 'ENOENT') return null; throw err }
        }
        const remove = async (path: string) => {
          try { await unlink(path) }
          catch (err: any) { if (err?.code !== 'ENOENT') throw err }
        }
        try {
          const created = await readOptional(file + '.vpn-created')
          const backup = await readOptional(file + '.vpn-backup')
          if (created !== null) {
            // Remove only our component/block, preserving edits made since apply.
            const current = await readOptional(file)
            if (current !== null) {
              const cleaned = file.endsWith('.xml')
                ? current.replace(/<component\s+name="HttpConfigurable"[\s\S]*?<\/component>\n?/, '')
                : current.replace(/# VPN-Tunnel-Enforcer[\s\S]*?# \/VPN-Tunnel-Enforcer\n?/, '')
              if (!cleaned.replace(/<application>\s*<\/application>/, '').trim()) await remove(file)
              else await writeFile(file, cleaned, 'utf-8')
            }
            await remove(file + '.vpn-created')
            if (backup !== null) await remove(file + '.vpn-backup')
          } else if (backup !== null) {
            await writeFile(file, backup, 'utf-8')
            await remove(file + '.vpn-backup')
          }
          // No provenance: do not delete somebody else's proxy settings.
        } catch { success = false }
      }
    }
    return success
  },

  async isApplied(): Promise<boolean> {
    const dirs = await findAndroidStudioDirs()
    for (const dir of dirs) {
      try {
        const content = await readFile(join(dir, 'studio64.exe.vmoptions'), 'utf-8')
        if (content.includes('VPN-Tunnel-Enforcer')) return true
      } catch { /* */ }
      try {
        const content = await readFile(join(dir, 'options', 'other.xml'), 'utf-8')
        if (/HttpConfigurable[\s\S]*?USE_HTTP_PROXY"\s+value="true"/.test(content)) return true
      } catch { /* */ }
    }
    return false
  }
}
