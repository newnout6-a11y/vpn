import { build } from 'esbuild'
import { existsSync, mkdtempSync, readFileSync } from 'fs'
import { tmpdir } from 'os'
import { dirname, join, resolve } from 'path'
import { createRequire } from 'module'
import { fileURLToPath } from 'url'

const require = createRequire(import.meta.url)
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const outDir = mkdtempSync(join(tmpdir(), 'vpnte-vpnprofiles-'))
const bundled = join(outDir, 'vpnProfiles.cjs')

await build({
  entryPoints: [join(root, 'src/main/vpnProfiles.ts')],
  bundle: true,
  platform: 'node',
  format: 'cjs',
  outfile: bundled,
  logLevel: 'silent'
})

const { parseVpnProfiles } = require(bundled)

function fail(message) {
  throw new Error(message)
}

function assert(condition, message) {
  if (!condition) fail(message)
}

function runCase(name, input, check) {
  const profiles = parseVpnProfiles(input)
  check(profiles)
  console.log(`ok ${name}: ${profiles.length} profile(s)`)
}

const vlessReality =
  'vless://00000000-0000-4000-8000-000000000000@example.com:443?security=reality&sni=www.example.com&fp=chrome&pbk=publicKeyExample&sid=1234&type=tcp&flow=xtls-rprx-vision#sample'
const trojanWs =
  'trojan://password@example.org:443?security=tls&sni=www.example.org&type=ws&host=cdn.example.org&path=%2Fws#trojan-ws'
const ssLegacy = `ss://${Buffer.from('aes-128-gcm:pass@example.net:8388').toString('base64')}#legacy-ss`
const ssSip002 = `ss://${Buffer.from('aes-256-gcm:pass').toString('base64')}@example.net:8388#sip002-ss`
const vmess = `vmess://${Buffer.from(JSON.stringify({
  v: '2',
  ps: 'vmess-ws',
  add: 'example.net',
  port: '443',
  id: '00000000-0000-4000-8000-000000000001',
  aid: '0',
  scy: 'auto',
  net: 'ws',
  type: 'none',
  host: 'cdn.example.net',
  path: '/ray',
  tls: 'tls',
  sni: 'www.example.net',
  fp: 'chrome'
})).toString('base64')}`

runCase('VLESS Reality URI', vlessReality, profiles => {
  assert(profiles.length === 1, 'VLESS URI should produce one profile')
  assert(profiles[0].protocol === 'vless', 'VLESS URI protocol mismatch')
  assert(profiles[0].outbound.tls?.reality?.enabled === true, 'VLESS Reality settings missing')
})

runCase('Trojan WebSocket URI', trojanWs, profiles => {
  assert(profiles.length === 1, 'Trojan URI should produce one profile')
  assert(profiles[0].protocol === 'trojan', 'Trojan URI protocol mismatch')
  assert(profiles[0].outbound.transport?.type === 'ws', 'Trojan WebSocket transport missing')
})

runCase('legacy base64 Shadowsocks URI', ssLegacy, profiles => {
  assert(profiles.length === 1, 'Legacy Shadowsocks URI should produce one profile')
  assert(profiles[0].protocol === 'shadowsocks', 'Legacy Shadowsocks protocol mismatch')
  assert(profiles[0].outbound.method === 'aes-128-gcm', 'Legacy Shadowsocks method mismatch')
})

runCase('SIP002 Shadowsocks URI', ssSip002, profiles => {
  assert(profiles.length === 1, 'SIP002 Shadowsocks URI should produce one profile')
  assert(profiles[0].protocol === 'shadowsocks', 'SIP002 Shadowsocks protocol mismatch')
  assert(profiles[0].outbound.method === 'aes-256-gcm', 'SIP002 Shadowsocks method mismatch')
})

runCase('VMess base64 URI', vmess, profiles => {
  assert(profiles.length === 1, 'VMess URI should produce one profile')
  assert(profiles[0].protocol === 'vmess', 'VMess protocol mismatch')
  assert(profiles[0].outbound.transport?.type === 'ws', 'VMess WebSocket transport missing')
})

runCase('base64 subscription lines', Buffer.from(`${vlessReality}\n${trojanWs}\n${ssLegacy}`).toString('base64'), profiles => {
  assert(profiles.length === 3, 'Base64 subscription should produce three profiles')
})

runCase('JSON wrapper with links array', JSON.stringify({ ok: true, links: [vlessReality, trojanWs] }), profiles => {
  assert(profiles.length === 2, 'JSON links wrapper should produce two profiles')
})

runCase('inline text containing VPN URI', `prefix ${vlessReality}, suffix`, profiles => {
  assert(profiles.length === 1, 'Inline URI extraction should produce one profile')
})

runCase('Clash YAML VLESS Reality', `
proxies:
  - name: clash-vless
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-4000-8000-000000000002
    network: tcp
    tls: true
    servername: www.example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: publicKeyExample
      short-id: 1234
`, profiles => {
  assert(profiles.length === 1, 'Clash VLESS Reality should produce one profile')
  assert(profiles[0].outbound.tls?.reality?.enabled === true, 'Clash Reality settings missing')
})

const appData = process.env.APPDATA || (process.env.USERPROFILE ? join(process.env.USERPROFILE, 'AppData', 'Roaming') : '')
const v2rayPrefs = appData ? join(appData, 'v2RayTun.net', 'v2RayTun', 'shared_preferences.json') : ''
if (v2rayPrefs && existsSync(v2rayPrefs)) {
  const prefs = JSON.parse(readFileSync(v2rayPrefs, 'utf8'))
  const configEntry = Object.entries(prefs).find(([key]) => key.startsWith('flutter.config_'))
  if (configEntry) {
    const config = JSON.parse(String(configEntry[1]))
    if (typeof config.xrayFullConfig === 'string' && config.xrayFullConfig.trim()) {
      runCase('local v2RayTun xrayFullConfig shape', config.xrayFullConfig, profiles => {
        assert(profiles.length > 0, 'Local xrayFullConfig should produce profiles')
      })
      runCase('local v2RayTun JSON wrapper shape', JSON.stringify({ xrayFullConfig: config.xrayFullConfig }), profiles => {
        assert(profiles.length > 0, 'Local xrayFullConfig wrapper should produce profiles')
      })
      runCase('local v2RayTun nested base64 wrapper shape', JSON.stringify({
        data: Buffer.from(config.xrayFullConfig).toString('base64')
      }), profiles => {
        assert(profiles.length > 0, 'Local nested base64 xrayFullConfig should produce profiles')
      })
    }
  }
}

console.log('vpn profile parser checks passed')
