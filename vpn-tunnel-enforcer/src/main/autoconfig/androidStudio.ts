import { readFile, writeFile, mkdir, stat, readdir } from 'fs/promises'
import { join } from 'path'
import { homedir } from 'os'
import { exec } from 'child_process'
import { promisify } from 'util'

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

export const androidStudio = {
  name: 'Android Studio',

  async apply(proxyAddr: string, proxyType: 'socks5' | 'http' = 'socks5'): Promise<boolean> {
    const lastColon = proxyAddr.lastIndexOf(':')
    const host = lastColon >= 0 ? proxyAddr.slice(0, lastColon) : proxyAddr
    const port = lastColon >= 0 ? proxyAddr.slice(lastColon + 1) : ''
    const isSocks = proxyType === 'socks5'
    const dirs = await findAndroidStudioDirs()

    // If no config dir exists yet (first run), create one for the newest-looking folder
    const targetDirs = dirs.length > 0 ? dirs : [join(getConfigDir(), 'AndroidStudio')]
    if (dirs.length === 0) {
      try { await mkdir(targetDirs[0], { recursive: true }) } catch { /* */ }
    }

    for (const dir of targetDirs) {
      // 1. Patch options/other.xml using correct JetBrains component name
      const optionsDir = join(dir, 'options')
      try {
        await mkdir(optionsDir, { recursive: true })
        const otherXmlPath = join(optionsDir, 'other.xml')

        let content = ''
        let hadFile = true
        try {
          content = await readFile(otherXmlPath, 'utf-8')
        } catch { content = '<application>\n</application>'; hadFile = false }

        if (hadFile) {
          await writeFile(otherXmlPath + '.vpn-backup', content, 'utf-8')
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
      } catch { /* skip */ }

      // 2. Write user vmoptions with JVM-level proxy args (required for First Run Wizard)
      const vmoptsPath = join(dir, 'studio64.exe.vmoptions')
      try {
        let content = ''
        let hadFile = true
        try {
          content = await readFile(vmoptsPath, 'utf-8')
        } catch { content = ''; hadFile = false }

        if (hadFile) {
          await writeFile(vmoptsPath + '.vpn-backup', content, 'utf-8')
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
      } catch { /* skip */ }
    }

    return targetDirs.length > 0
  },

  async rollback(): Promise<boolean> {
    const dirs = await findAndroidStudioDirs()
    for (const dir of dirs) {
      const otherXmlPath = join(dir, 'options', 'other.xml')
      const vmoptsPath = join(dir, 'studio64.exe.vmoptions')

      try {
        const backup = await readFile(otherXmlPath + '.vpn-backup', 'utf-8')
        await writeFile(otherXmlPath, backup, 'utf-8')
      } catch { /* no backup */ }

      // Remove our VM options block (or restore backup if present)
      try {
        const backup = await readFile(vmoptsPath + '.vpn-backup', 'utf-8')
        await writeFile(vmoptsPath, backup, 'utf-8')
      } catch {
        try {
          const cur = await readFile(vmoptsPath, 'utf-8')
          const cleaned = cur.replace(/# VPN-Tunnel-Enforcer[\s\S]*?# \/VPN-Tunnel-Enforcer\n?/, '')
          await writeFile(vmoptsPath, cleaned, 'utf-8')
        } catch { /* */ }
      }
    }
    return true
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
