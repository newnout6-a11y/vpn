import { execFile } from 'child_process'
import { promisify } from 'util'

const execFileAsync = promisify(execFile)

function proxyUrl(proxyAddr: string, proxyType: 'socks5' | 'http'): string {
  const [host, port] = proxyAddr.split(':')
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

async function deleteUserEnvValue(name: string): Promise<void> {
  await execFileAsync('reg', ['delete', 'HKCU\\Environment', '/v', name, '/f'], {
    windowsHide: true,
    timeout: 10000
  }).catch(() => undefined)
}

export const env = {
  name: 'Environment Variables',

  async apply(proxyAddr: string, proxyType: 'socks5' | 'http' = 'socks5'): Promise<boolean> {
    const url = proxyUrl(proxyAddr, proxyType)
    try {
      // Set user-level environment variables (survives reboot)
      await execFileAsync('setx', ['HTTP_PROXY', url], { windowsHide: true, timeout: 10000 })
      await execFileAsync('setx', ['HTTPS_PROXY', url], { windowsHide: true, timeout: 10000 })
      await execFileAsync('setx', ['ALL_PROXY', url], { windowsHide: true, timeout: 10000 })
      await execFileAsync('setx', ['NO_PROXY', 'localhost,127.0.0.1,::1'], { windowsHide: true, timeout: 10000 })
      process.env.HTTP_PROXY = url
      process.env.HTTPS_PROXY = url
      process.env.ALL_PROXY = url
      process.env.NO_PROXY = 'localhost,127.0.0.1,::1'
      await broadcastEnvironmentChanged()
      return true
    } catch {
      return false
    }
  },

  async rollback(): Promise<boolean> {
    try {
      // Delete user-level environment variables
      await deleteUserEnvValue('HTTP_PROXY')
      await deleteUserEnvValue('HTTPS_PROXY')
      await deleteUserEnvValue('ALL_PROXY')
      await deleteUserEnvValue('NO_PROXY')
      delete process.env.HTTP_PROXY
      delete process.env.HTTPS_PROXY
      delete process.env.ALL_PROXY
      delete process.env.NO_PROXY
      await broadcastEnvironmentChanged()
      return true
    } catch {
      return false
    }
  },

  async isApplied(): Promise<boolean> {
    try {
      const { stdout } = await execFileAsync('reg', ['query', 'HKCU\\Environment', '/v', 'HTTP_PROXY'], {
        windowsHide: true,
        timeout: 10000,
        encoding: 'utf8'
      }) as { stdout: string; stderr: string }
      return stdout.includes('HTTP_PROXY')
    } catch {
      return false
    }
  }
}
