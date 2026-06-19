import { execFile as execFileCb } from 'child_process'
import { createHash } from 'crypto'
import { hostname, userInfo } from 'os'
import { promisify } from 'util'
import { brotliDecompressSync, gunzipSync, inflateRawSync, inflateSync } from 'zlib'
import type { ClientDevice } from '../shared/ipc-types'
import { buildBootstrapRouteAttempts, type BootstrapRouteMode } from './bootstrapRoute'

const execFile = promisify(execFileCb)

export type VpnProtocol =
  | 'vless'
  | 'trojan'
  | 'shadowsocks'
  | 'vmess'
  | 'hysteria2'
  | 'naive'
  | 'anytls'
  | 'shadowtls'
  | 'tuic'
  | 'sing-box'

export interface VpnProfile {
  name: string
  protocol: VpnProtocol
  outbound: Record<string, any>
  clientDevice?: ClientDevice
  clientFingerprint?: string
}

export interface VpnProfileSummary {
  index: number
  name: string
  protocol: VpnProtocol
}

export interface VpnInputInspection {
  count: number
  protocols: Record<string, number>
  profiles: VpnProfileSummary[]
  fetched: boolean
  source: string
}

export interface SubscriptionFetchOptions {
  proxyAddr?: string
  proxyType?: 'socks5' | 'http'
  clientDevice?: ClientDevice
  bootstrapRouteMode?: BootstrapRouteMode
}

export type VpnProfileStealthPreset =
  | 'reality-utls'
  | 'naive-ech'
  | 'naive'
  | 'hysteria2-obfs'
  | 'tls-utls'
  | 'plain'

export interface VpnProfileCapabilitySummary {
  protocol: string
  stealthPreset: VpnProfileStealthPreset
  tlsConfigured: boolean
  echConfigured: boolean
  warnings: string[]
}

/**
 * Standard subscription metadata exposed by xray/sing-box panels
 * (Marzban, Marzneshin, 3X-UI, …) via response headers. We surface this so
 * the renderer can show "subscription expires in N days", "X / Y GB used",
 * and — most importantly — distinguish "the panel is gone but the keys may
 * still work" (post-trial scenario) from "the keys themselves were revoked".
 *
 * All fields are optional. A missing header just means the panel doesn't
 * publish that piece of info; we never fabricate values.
 */
export interface SubscriptionUserInfo {
  trafficUploadBytes?: number
  trafficDownloadBytes?: number
  /** upload + download, only set when at least one of the two is present. */
  trafficUsedBytes?: number
  trafficTotalBytes?: number
  /** Wall-clock ms timestamp (Date.now() compatible). Header gives unix seconds. */
  expiresAt?: number
  refreshIntervalSeconds?: number
  webPageUrl?: string
}

interface FetchAttempt {
  label: string
  args: string[]
}

interface SubscriptionHttpResponse {
  headers: Record<string, string>
  body: string
}

const SUPPORTED_OUTBOUND_TYPES = new Set([
  'vless',
  'trojan',
  'shadowsocks',
  'vmess',
  'hysteria2',
  'naive',
  'anytls',
  'shadowtls',
  'tuic'
])
const HAPP_VERSION = '3.22.1'
const SUBSCRIPTION_USER_AGENTS = ['sing-box/1.13.8', 'v2RayTun/1.0', 'v2rayN/7.0']
const DEVICE_FINGERPRINTS: Record<ClientDevice, string> = {
  pc: 'chrome',
  android: 'android',
  ios: 'ios',
  mac: 'safari'
}

const DEVICE_HEADER_PROFILES: Record<ClientDevice, {
  os: string
  osVersion: string
  model: string
}> = {
  pc: { os: 'Windows', osVersion: '11', model: 'Windows PC' },
  android: { os: 'Android', osVersion: '15', model: 'SM-A556B' },
  ios: { os: 'iOS', osVersion: '18.3', model: 'iPhone 15 Pro' },
  mac: { os: 'macOS', osVersion: '15.3', model: 'MacBookPro18,3' }
}

export function normalizeClientDevice(value: unknown): ClientDevice {
  return value === 'android' || value === 'ios' || value === 'mac' || value === 'pc' ? value : 'pc'
}

export function clientFingerprintForDevice(device: ClientDevice): string {
  return DEVICE_FINGERPRINTS[normalizeClientDevice(device)]
}

function buildMobileSubscriptionHwid(device: ClientDevice): string {
  let username = ''
  try {
    username = userInfo().username || ''
  } catch {
    username = process.env.USERNAME || process.env.USER || ''
  }
  const seed = [
    'happ-compatible-mobile-hwid',
    normalizeClientDevice(device),
    hostname(),
    username,
    process.env.USERDOMAIN || '',
    process.arch,
    process.platform
  ].join('|')
  return createHash('sha256').update(seed).digest('hex').slice(0, 16)
}

function buildHappSubscriptionHwid(device: ClientDevice): string {
  return buildMobileSubscriptionHwid(device)
}

export function applyClientDeviceToOutbound(outbound: Record<string, any>, device: ClientDevice): Record<string, any> {
  const result = JSON.parse(JSON.stringify(outbound || {}))
  const tls = result.tls && typeof result.tls === 'object' ? result.tls as Record<string, any> : null
  if (!tls || tls.enabled === false) return result
  tls.utls = {
    ...(tls.utls && typeof tls.utls === 'object' ? tls.utls : {}),
    enabled: true,
    fingerprint: clientFingerprintForDevice(device)
  }
  return result
}

export function applyClientDeviceToProfile(profile: VpnProfile, device: ClientDevice): VpnProfile {
  const clientDevice = normalizeClientDevice(device)
  const outbound = applyClientDeviceToOutbound(profile.outbound, clientDevice)
  return {
    ...profile,
    outbound,
    clientDevice,
    clientFingerprint: outbound.tls && typeof outbound.tls === 'object'
      ? clientFingerprintForDevice(clientDevice)
      : undefined
  }
}

export function getSubscriptionUserAgents(device: ClientDevice = 'pc'): string[] {
  const clientDevice = normalizeClientDevice(device)
  if (clientDevice === 'pc') {
    return [`Happ/${HAPP_VERSION}/Windows/${buildHappSubscriptionHwid('pc')}`, ...SUBSCRIPTION_USER_AGENTS]
  }
  if (clientDevice === 'android') {
    return [`Happ/${HAPP_VERSION}/Android/${buildHappSubscriptionHwid('android')}`, 'v2RayTun/1.0/android', ...SUBSCRIPTION_USER_AGENTS]
  }
  if (clientDevice === 'ios') {
    return [`Happ/${HAPP_VERSION}/iOS/${buildHappSubscriptionHwid('ios')}`, 'v2RayTun/1.0/ios', ...SUBSCRIPTION_USER_AGENTS]
  }
  if (clientDevice === 'mac') {
    return [`Happ/${HAPP_VERSION}/macOS/${buildHappSubscriptionHwid('mac')}`, 'sing-box/1.13.8', ...SUBSCRIPTION_USER_AGENTS]
  }
  return SUBSCRIPTION_USER_AGENTS
}
const SECRET_KEYS = new Set([
  'uuid',
  'password',
  'id',
  'address',
  'server',
  'server_port',
  'private_key',
  'public_key',
  'short_id',
  'client_secret',
  'token',
  'auth_str',
  'directvpninput',
  'vpninput',
  'subscription',
  'subscriptionurl',
  'up_mbps',
  'down_mbps'
])

export function redactSensitiveText(value: string): string {
  return value
    .replace(/\b(?:vless|trojan|ss|vmess|hysteria2|hy2|naive|anytls|shadowtls|tuic):\/\/\S+/gi, '<redacted-vpn-uri>')
    .replace(/\bhttps?:\/\/[^\s"'<>]{8,}/gi, '<redacted-url>')
    .replace(/\b(Could not resolve host|No such host is known|resolve host):\s*[^\s"'<>]+/gi, '$1: <redacted-host>')
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi, '<redacted-uuid>')
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

function decodeBase64Text(value: string): string | null {
  const compact = value.trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/')
  if (!compact || compact.length < 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) return null
  try {
    const padded = compact + '='.repeat((4 - compact.length % 4) % 4)
    const decoded = Buffer.from(padded, 'base64').toString('utf8')
    const trimmed = decoded.trim()
    if (!trimmed || trimmed.includes('\u0000')) return null
    return decoded
  } catch {
    return null
  }
}

function decodeBase64Loose(value: string): string | null {
  const decoded = decodeBase64Text(value)
  if (!decoded) return null
  const trimmed = decoded.trim()
  const looksLikeJsonConfig = /["'](?:outbounds|xrayFullConfig|rawConfig|proxies|dns|routing)["']\s*:/i.test(decoded)
  return decoded.includes('://') || trimmed.startsWith('{') || trimmed.startsWith('[') || looksLikeJsonConfig || /^\s*proxies\s*:/im.test(decoded) ? decoded : null
}

function decodeSubscriptionBody(value: Buffer): string {
  let body = value
  try {
    if (body.length >= 2 && body[0] === 0x1f && body[1] === 0x8b) {
      body = gunzipSync(body)
    } else if (body.length >= 2 && body[0] === 0x78) {
      body = inflateSync(body)
    }
  } catch {
    try {
      body = inflateRawSync(value)
    } catch {
      body = value
    }
  }

  const probe = body.subarray(0, Math.min(body.length, 80))
  const nulBytes = probe.filter(byte => byte === 0).length
  if (nulBytes > probe.length / 4) {
    return body.toString('utf16le')
  }

  const utf8 = body.toString('utf8')
  if (utf8.includes('\uFFFD') && body.length > 4) {
    try {
      const brotli = brotliDecompressSync(body).toString('utf8')
      if (brotli.trim()) return brotli
    } catch {
      // Not brotli or not valid compressed data; keep UTF-8 below.
    }
  }
  return utf8
}

function numberPort(raw: string | null | undefined): number {
  const port = Number(raw)
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`Некорректный порт VPN-сервера: ${raw || 'пусто'}`)
  }
  return port
}

function param(params: URLSearchParams, ...names: string[]): string | null {
  for (const name of names) {
    const value = params.get(name)
    if (value !== null && value !== '') return safeDecode(value)
  }
  return null
}

function boolParam(params: URLSearchParams, ...names: string[]): boolean {
  const raw = param(params, ...names)
  if (!raw) return false
  return /^(1|true|yes)$/i.test(raw)
}

function boolValue(value: unknown): boolean {
  if (typeof value === 'boolean') return value
  if (typeof value === 'number') return value !== 0
  if (typeof value !== 'string') return false
  return /^(1|true|yes|on)$/i.test(value.trim())
}

function stringValue(value: unknown): string | null {
  if (value === null || value === undefined) return null
  const text = String(value).trim()
  return text ? text : null
}

function stringListValue(value: unknown): string[] | null {
  if (Array.isArray(value)) {
    const items = value.map(item => stringValue(item)).filter((item): item is string => Boolean(item))
    return items.length ? items : null
  }
  const text = stringValue(value)
  if (!text) return null
  const trimmed = text.trim()
  const unwrapped = trimmed.startsWith('[') && trimmed.endsWith(']') ? trimmed.slice(1, -1) : trimmed
  const items = splitInlineYaml(unwrapped).map(item => stringValue(item)).filter((item): item is string => Boolean(item))
  return items.length ? items : null
}

function splitCsv(value: string | null): string[] | undefined {
  if (!value) return undefined
  const items = value.split(',').map(item => item.trim()).filter(Boolean)
  return items.length ? items : undefined
}

function positiveNumberParam(params: URLSearchParams, ...names: string[]): number | undefined {
  const raw = param(params, ...names)
  if (!raw) return undefined
  const value = Number(raw)
  return Number.isFinite(value) && value > 0 ? value : undefined
}

function firstPortFromRangeList(value: string | null): string | null {
  if (!value) return null
  const first = value.split(',').map(item => item.trim()).find(Boolean)
  if (!first) return null
  return first.split(/[-:]/)[0]?.trim() || null
}

function normalizeHysteria2ServerPorts(value: string | null): string | undefined {
  if (!value) return undefined
  const trimmed = value.trim()
  if (!trimmed || trimmed.includes(',')) return undefined
  const match = trimmed.match(/^(\d{1,5})\s*[-:]\s*(\d{1,5})$/)
  if (!match) return undefined
  const start = Number(match[1])
  const end = Number(match[2])
  if (!Number.isInteger(start) || !Number.isInteger(end) || start <= 0 || end <= 0 || start > 65535 || end > 65535 || end < start) {
    return undefined
  }
  return `${start}:${end}`
}

function hysteria2ServerPortsToUri(value: string): string {
  return value.replace(/^(\d{1,5}):(\d{1,5})$/, '$1-$2')
}

function buildEchFromParams(params: URLSearchParams): Record<string, any> | undefined {
  const config = splitCsv(param(params, 'echConfig', 'ech_config', 'ech-config'))
  const configPath = param(params, 'echConfigPath', 'ech_config_path', 'ech-config-path')
  const queryServerName = param(params, 'echQueryServerName', 'ech_query_server_name', 'ech-query-server-name')
  const enabled = boolParam(params, 'ech', 'echEnabled', 'ech_enabled', 'ech-enabled')
  if (!enabled && !config && !configPath && !queryServerName) return undefined

  const ech: Record<string, any> = { enabled: enabled || Boolean(config || configPath || queryServerName) }
  if (config) ech.config = config
  if (configPath) ech.config_path = configPath
  if (queryServerName) ech.query_server_name = queryServerName
  return ech
}

function buildEchFromObject(source: Record<string, any>): Record<string, any> | undefined {
  const raw =
    source.ech && typeof source.ech === 'object' ? source.ech :
    source.echSettings && typeof source.echSettings === 'object' ? source.echSettings :
    source['ech-settings'] && typeof source['ech-settings'] === 'object' ? source['ech-settings'] :
    source['ech-opts'] && typeof source['ech-opts'] === 'object' ? source['ech-opts'] :
    null
  const config = stringListValue(raw?.config) || stringListValue(source.echConfig) || stringListValue(source['ech-config'])
  const configPath =
    stringValue(raw?.config_path) ||
    stringValue(raw?.configPath) ||
    stringValue(source.echConfigPath) ||
    stringValue(source['ech-config-path'])
  const queryServerName =
    stringValue(raw?.query_server_name) ||
    stringValue(raw?.queryServerName) ||
    stringValue(source.echQueryServerName) ||
    stringValue(source['ech-query-server-name'])
  const explicitEnabled =
    raw && ('enabled' in raw) ? boolValue(raw.enabled) :
    'ech' in source ? boolValue(source.ech) :
    'ech-enabled' in source ? boolValue(source['ech-enabled']) :
    'echEnabled' in source ? boolValue(source.echEnabled) :
    false
  if (!explicitEnabled && !config && !configPath && !queryServerName) return undefined

  const ech: Record<string, any> = { enabled: explicitEnabled || Boolean(config || configPath || queryServerName) }
  if (config) ech.config = config
  if (configPath) ech.config_path = configPath
  if (queryServerName) ech.query_server_name = queryServerName
  return ech
}

function buildTls(params: URLSearchParams, host: string, defaultEnabled = false): Record<string, any> | undefined {
  const security = (param(params, 'security', 'tls') || '').toLowerCase()
  const enabled = defaultEnabled || security === 'tls' || security === 'reality'
  if (!enabled || security === 'none') return undefined

  const tls: Record<string, any> = { enabled: true }
  const serverName = param(params, 'sni', 'serverName', 'peer', 'host')
  tls.server_name = serverName || host

  const alpn = splitCsv(param(params, 'alpn'))
  if (alpn) tls.alpn = alpn
  if (boolParam(params, 'allowInsecure', 'insecure', 'skip-cert-verify')) tls.insecure = true
  const ech = buildEchFromParams(params)
  if (ech) tls.ech = ech

  const fp = param(params, 'fp', 'fingerprint')
  if (fp && fp.toLowerCase() !== 'none') {
    tls.utls = { enabled: true, fingerprint: fp }
  }

  if (security === 'reality') {
    const publicKey = param(params, 'pbk', 'publicKey', 'public_key')
    if (!publicKey) throw new Error('VLESS Reality ключ без pbk/publicKey')
    if (!tls.utls) tls.utls = { enabled: true, fingerprint: 'chrome' }
    tls.reality = {
      enabled: true,
      public_key: publicKey,
      short_id: param(params, 'sid', 'shortId', 'short_id') || ''
    }
  }

  // Anti-DPI default: ensure every TLS outbound carries a browser-like
  // fingerprint and ALPN. Without this, sing-box emits a Go-stdlib
  // ClientHello (TSPU known-bad pattern) and Russian university DPI
  // rate-limits the connection. Reality already forces utls on its own
  // path; we only fill in the gaps for plain TLS.
  if (tls.enabled !== false) {
    if (!tls.utls || typeof tls.utls !== 'object' || tls.utls.enabled === false) {
      tls.utls = { enabled: true, fingerprint: 'chrome' }
    } else if (!tls.utls.fingerprint) {
      tls.utls.fingerprint = 'chrome'
    }
    if (!Array.isArray(tls.alpn) || tls.alpn.length === 0) {
      tls.alpn = ['h2', 'http/1.1']
    }
  }

  return tls
}

function buildTransport(params: URLSearchParams): Record<string, any> | undefined {
  const type = (param(params, 'type', 'net') || 'tcp').toLowerCase()
  if (!type || type === 'tcp' || type === 'raw') return undefined

  if (type === 'ws' || type === 'websocket') {
    const headers: Record<string, string> = {}
    const host = param(params, 'host')
    if (host) headers.Host = host
    const transport: Record<string, any> = {
      type: 'ws',
      path: param(params, 'path') || '/'
    }
    if (Object.keys(headers).length) transport.headers = headers
    const earlyData = Number(param(params, 'ed', 'max_early_data') || 0)
    if (Number.isInteger(earlyData) && earlyData > 0) transport.max_early_data = earlyData
    const earlyHeader = param(params, 'eh', 'early_data_header_name')
    if (earlyHeader) transport.early_data_header_name = earlyHeader
    return transport
  }

  if (type === 'grpc') {
    return {
      type: 'grpc',
      service_name: param(params, 'serviceName', 'service_name') || ''
    }
  }

  if (type === 'httpupgrade' || type === 'http-upgrade') {
    const transport: Record<string, any> = {
      type: 'httpupgrade',
      host: param(params, 'host') || '',
      path: param(params, 'path') || '/'
    }
    return transport
  }

  if (type === 'http' || type === 'h2') {
    const host = param(params, 'host')
    return {
      type: 'http',
      host: host ? [host] : [],
      path: param(params, 'path') || '/'
    }
  }

  throw new Error(`Транспорт ${type} пока не поддерживается встроенным импортом`)
}

function finishOutbound(outbound: Record<string, any>): Record<string, any> {
  const result = JSON.parse(JSON.stringify(outbound))
  result.tag = 'proxy-out'
  delete result.detour
  delete result.domain_strategy
  delete result.domain_resolver
  // Anti-DPI default for the JSON-paste path: a user who pasted a full
  // sing-box outbound may not have included utls/alpn, so apply the same
  // browser-like defaults here. This is the last gate before the outbound
  // leaves the parser, so it covers parseLine, xray-format JSON, AND
  // Clash YAML (all of which call finishOutbound). Existing utls or alpn
  // values on the user's outbound are preserved.
  if (result.tls && typeof result.tls === 'object') {
    const tls = result.tls as Record<string, any>
    if (result.type === 'naive') {
      delete tls.insecure
    }
    if (tls.enabled !== false) {
      if (!tls.utls || typeof tls.utls !== 'object' || tls.utls.enabled === false) {
        tls.utls = { enabled: true, fingerprint: 'chrome' }
      } else if (!tls.utls.fingerprint) {
        tls.utls.fingerprint = 'chrome'
      }
      if (!Array.isArray(tls.alpn) || tls.alpn.length === 0) {
        tls.alpn = ['h2', 'http/1.1']
      }
    }
  }
  return result
}

function parseStandardUrl(line: string): URL {
  try {
    return new URL(line)
  } catch (err: any) {
    throw new Error(`Не удалось разобрать VPN-ссылку: ${err?.message || String(err)}`)
  }
}

function parseVless(line: string): VpnProfile {
  const url = parseStandardUrl(line)
  const params = url.searchParams
  const outbound: Record<string, any> = {
    type: 'vless',
    tag: 'proxy-out',
    server: url.hostname,
    server_port: numberPort(url.port),
    uuid: safeDecode(url.username)
  }
  const flow = param(params, 'flow')
  if (flow) outbound.flow = flow
  const tls = buildTls(params, url.hostname)
  if (tls) outbound.tls = tls
  const transport = buildTransport(params)
  if (transport) outbound.transport = transport
  const packetEncoding = param(params, 'packetEncoding', 'packet_encoding')
  if (packetEncoding) outbound.packet_encoding = packetEncoding
  return { name: safeDecode(url.hash.slice(1)) || 'VLESS', protocol: 'vless', outbound: finishOutbound(outbound) }
}

function parseTrojan(line: string): VpnProfile {
  const url = parseStandardUrl(line)
  const params = url.searchParams
  const outbound: Record<string, any> = {
    type: 'trojan',
    tag: 'proxy-out',
    server: url.hostname,
    server_port: numberPort(url.port),
    password: safeDecode(url.username)
  }
  const tls = buildTls(params, url.hostname, (param(params, 'security') || 'tls').toLowerCase() !== 'none')
  if (tls) outbound.tls = tls
  const transport = buildTransport(params)
  if (transport) outbound.transport = transport
  return { name: safeDecode(url.hash.slice(1)) || 'Trojan', protocol: 'trojan', outbound: finishOutbound(outbound) }
}

function splitHostPort(authority: string): { host: string; port: number } {
  if (authority.startsWith('[')) {
    const end = authority.indexOf(']')
    if (end > 0) return { host: authority.slice(1, end), port: numberPort(authority.slice(end + 2)) }
  }
  const idx = authority.lastIndexOf(':')
  if (idx <= 0) throw new Error('Не найден host:port в Shadowsocks ссылке')
  return { host: authority.slice(0, idx), port: numberPort(authority.slice(idx + 1)) }
}

function parseShadowsocks(line: string): VpnProfile {
  const withoutScheme = line.slice('ss://'.length)
  const [beforeHash, hash = ''] = withoutScheme.split('#', 2)
  const [main, query = ''] = beforeHash.split('?', 2)
  const params = new URLSearchParams(query)

  let userInfo = ''
  let authority = ''
  if (main.includes('@')) {
    const at = main.lastIndexOf('@')
    userInfo = main.slice(0, at)
    authority = main.slice(at + 1)
  } else {
    const decoded = decodeBase64Text(main)
    if (!decoded || !decoded.includes('@')) throw new Error('Не удалось декодировать Shadowsocks ссылку')
    const at = decoded.lastIndexOf('@')
    userInfo = decoded.slice(0, at)
    authority = decoded.slice(at + 1)
  }

  let credentials = userInfo.includes(':') ? userInfo : decodeBase64Text(userInfo) || userInfo
  credentials = safeDecode(credentials)
  const sep = credentials.indexOf(':')
  if (sep <= 0) throw new Error('Не найден method:password в Shadowsocks ссылке')
  const plugin = param(params, 'plugin')
  if (plugin) throw new Error('Shadowsocks SIP003 plugins пока не поддерживаются встроенным sing-box runtime')
  const { host, port } = splitHostPort(authority)
  return {
    name: safeDecode(hash) || 'Shadowsocks',
    protocol: 'shadowsocks',
    outbound: finishOutbound({
      type: 'shadowsocks',
      tag: 'proxy-out',
      server: host,
      server_port: port,
      method: credentials.slice(0, sep),
      password: credentials.slice(sep + 1)
    })
  }
}

function parseVmess(line: string): VpnProfile {
  const payload = line.slice('vmess://'.length)
  const decoded = decodeBase64Loose(payload)
  if (!decoded) throw new Error('Не удалось декодировать VMess ссылку')
  const raw = JSON.parse(decoded)
  const params = new URLSearchParams()
  if (raw.tls) params.set('security', raw.tls === 'tls' ? 'tls' : String(raw.tls))
  if (raw.sni) params.set('sni', raw.sni)
  if (raw.fp) params.set('fp', raw.fp)
  if (raw.alpn) params.set('alpn', Array.isArray(raw.alpn) ? raw.alpn.join(',') : String(raw.alpn))
  if (raw.net) params.set('type', raw.net)
  if (raw.host) params.set('host', raw.host)
  if (raw.path) params.set('path', raw.path)

  const outbound: Record<string, any> = {
    type: 'vmess',
    tag: 'proxy-out',
    server: String(raw.add || raw.server || ''),
    server_port: numberPort(String(raw.port || raw.server_port || '')),
    uuid: String(raw.id || raw.uuid || ''),
    security: String(raw.scy || raw.security || 'auto'),
    alter_id: Number(raw.aid || raw.alterId || 0)
  }
  const tls = buildTls(params, outbound.server)
  if (tls) outbound.tls = tls
  const transport = buildTransport(params)
  if (transport) outbound.transport = transport
  return { name: String(raw.ps || raw.name || 'VMess'), protocol: 'vmess', outbound: finishOutbound(outbound) }
}

function parseHysteria2(line: string): VpnProfile {
  const normalized = line.replace(/^hy2:\/\//i, 'hysteria2://')
  const url = parseStandardUrl(normalized)
  const params = url.searchParams
  const rawServerPorts = param(params, 'mport', 'server_ports', 'serverPorts')
  const serverPorts = normalizeHysteria2ServerPorts(rawServerPorts)
  const outbound: Record<string, any> = {
    type: 'hysteria2',
    tag: 'proxy-out',
    server: url.hostname,
    server_port: numberPort(url.port || firstPortFromRangeList(rawServerPorts)),
    password: safeDecode(url.username || param(params, 'password') || ''),
    tls: buildTls(params, url.hostname, true)
  }
  const obfsType = param(params, 'obfs')
  const obfsPassword = param(params, 'obfs-password', 'obfs_password')
  if (obfsType) outbound.obfs = { type: obfsType, password: obfsPassword || '' }
  if (serverPorts) outbound.server_ports = serverPorts
  const hopInterval = param(params, 'hop_interval', 'hopInterval', 'hop-interval')
  if (hopInterval) outbound.hop_interval = hopInterval
  const upMbps = positiveNumberParam(params, 'up_mbps', 'upMbps', 'upmbps')
  if (upMbps !== undefined) outbound.up_mbps = upMbps
  const downMbps = positiveNumberParam(params, 'down_mbps', 'downMbps', 'downmbps')
  if (downMbps !== undefined) outbound.down_mbps = downMbps
  return { name: safeDecode(url.hash.slice(1)) || 'Hysteria2', protocol: 'hysteria2', outbound: finishOutbound(outbound) }
}

function parseNaive(line: string): VpnProfile {
  const url = parseStandardUrl(line)
  const params = url.searchParams
  const outbound: Record<string, any> = {
    type: 'naive',
    tag: 'proxy-out',
    server: url.hostname,
    server_port: numberPort(url.port || '443'),
    username: safeDecode(url.username),
    password: safeDecode(url.password)
  }
  const tls = buildTls(params, url.hostname, true)
  if (tls) outbound.tls = tls
  return { name: safeDecode(url.hash.slice(1)) || 'Naive', protocol: 'naive', outbound: finishOutbound(outbound) }
}

function parseAnyTls(line: string): VpnProfile {
  const url = parseStandardUrl(line)
  const params = url.searchParams
  const outbound: Record<string, any> = {
    type: 'anytls',
    tag: 'proxy-out',
    server: url.hostname,
    server_port: numberPort(url.port || '443'),
    password: safeDecode(url.username || param(params, 'password') || '')
  }
  const tls = buildTls(params, url.hostname, true)
  if (tls) outbound.tls = tls
  return { name: safeDecode(url.hash.slice(1)) || 'AnyTLS', protocol: 'anytls', outbound: finishOutbound(outbound) }
}

function parseShadowTls(line: string): VpnProfile {
  const url = parseStandardUrl(line)
  const params = url.searchParams
  const outbound: Record<string, any> = {
    type: 'shadowtls',
    tag: 'proxy-out',
    server: url.hostname,
    server_port: numberPort(url.port || '443'),
    password: safeDecode(url.username || param(params, 'password') || ''),
    version: Number(param(params, 'version') || 3)
  }
  const tls = buildTls(params, url.hostname, true)
  if (tls) outbound.tls = tls
  return { name: safeDecode(url.hash.slice(1)) || 'ShadowTLS', protocol: 'shadowtls', outbound: finishOutbound(outbound) }
}

function parseTuic(line: string): VpnProfile {
  const url = parseStandardUrl(line)
  const params = url.searchParams
  const outbound: Record<string, any> = {
    type: 'tuic',
    tag: 'proxy-out',
    server: url.hostname,
    server_port: numberPort(url.port),
    uuid: safeDecode(url.username || param(params, 'uuid') || ''),
    password: safeDecode(url.password || param(params, 'password') || '')
  }
  const congestionControl = param(params, 'congestion_control', 'congestionControl', 'congestion')
  if (congestionControl) outbound.congestion_control = congestionControl
  const udpRelayMode = param(params, 'udp_relay_mode', 'udpRelayMode')
  if (udpRelayMode) outbound.udp_relay_mode = udpRelayMode
  const tls = buildTls(params, url.hostname, true)
  if (tls) outbound.tls = tls
  return { name: safeDecode(url.hash.slice(1)) || 'TUIC', protocol: 'tuic', outbound: finishOutbound(outbound) }
}

function xrayProtocol(value: unknown): VpnProtocol | null {
  const protocol = (stringValue(value) || '').toLowerCase()
  if (protocol === 'vless' || protocol === 'trojan' || protocol === 'vmess') return protocol
  if (protocol === 'shadowsocks' || protocol === 'ss') return 'shadowsocks'
  if (protocol === 'hysteria2' || protocol === 'hy2') return 'hysteria2'
  if (protocol === 'naive' || protocol === 'anytls' || protocol === 'shadowtls' || protocol === 'tuic') return protocol
  return null
}

function buildTlsFromXrayStream(stream: Record<string, any>, server: string): Record<string, any> | undefined {
  const security = (stringValue(stream.security) || '').toLowerCase()
  const tlsSettings = stream.tlsSettings && typeof stream.tlsSettings === 'object' ? stream.tlsSettings : {}
  const realitySettings = stream.realitySettings && typeof stream.realitySettings === 'object' ? stream.realitySettings : {}
  if (security !== 'tls' && security !== 'reality') return undefined

  const source = security === 'reality' ? realitySettings : tlsSettings
  const tls: Record<string, any> = {
    enabled: true,
    server_name: stringValue(source.serverName) || stringValue(source.server_name) || server
  }
  const alpn = stringListValue(source.alpn)
  if (alpn) tls.alpn = alpn
  if (boolValue(source.allowInsecure) || boolValue(source.insecure)) tls.insecure = true
  const ech = buildEchFromObject(source)
  if (ech) tls.ech = ech
  const fingerprint = stringValue(source.fingerprint) || stringValue(source.fp)
  if (fingerprint && fingerprint.toLowerCase() !== 'none') {
    tls.utls = { enabled: true, fingerprint }
  }

  if (security === 'reality') {
    const publicKey = stringValue(realitySettings.publicKey) || stringValue(realitySettings.public_key)
    if (!publicKey) throw new Error('Xray Reality outbound без publicKey')
    if (!tls.utls) tls.utls = { enabled: true, fingerprint: 'chrome' }
    tls.reality = {
      enabled: true,
      public_key: publicKey,
      short_id: stringValue(realitySettings.shortId) || stringValue(realitySettings.short_id) || ''
    }
  }

  // Anti-DPI default: ensure every TLS outbound carries a browser-like
  // fingerprint and ALPN. Without this, sing-box emits a Go-stdlib
  // ClientHello (TSPU known-bad pattern) and Russian university DPI
  // rate-limits the connection. Reality already forces utls on its own
  // path; we only fill in the gaps for plain TLS.
  if (tls.enabled !== false) {
    if (!tls.utls || typeof tls.utls !== 'object' || tls.utls.enabled === false) {
      tls.utls = { enabled: true, fingerprint: 'chrome' }
    } else if (!tls.utls.fingerprint) {
      tls.utls.fingerprint = 'chrome'
    }
    if (!Array.isArray(tls.alpn) || tls.alpn.length === 0) {
      tls.alpn = ['h2', 'http/1.1']
    }
  }

  return tls
}

function buildTransportFromXrayStream(stream: Record<string, any>): Record<string, any> | undefined {
  const network = (stringValue(stream.network) || 'tcp').toLowerCase()
  if (!network || network === 'tcp' || network === 'raw') return undefined

  if (network === 'ws' || network === 'websocket') {
    const ws = stream.wsSettings && typeof stream.wsSettings === 'object' ? stream.wsSettings : {}
    const transport: Record<string, any> = {
      type: 'ws',
      path: stringValue(ws.path) || '/'
    }
    if (ws.headers && typeof ws.headers === 'object' && Object.keys(ws.headers).length) {
      transport.headers = ws.headers
    }
    return transport
  }

  if (network === 'grpc') {
    const grpc = stream.grpcSettings && typeof stream.grpcSettings === 'object' ? stream.grpcSettings : {}
    return {
      type: 'grpc',
      service_name: stringValue(grpc.serviceName) || stringValue(grpc.service_name) || ''
    }
  }

  if (network === 'httpupgrade' || network === 'http-upgrade') {
    const http = stream.httpupgradeSettings && typeof stream.httpupgradeSettings === 'object' ? stream.httpupgradeSettings : {}
    return {
      type: 'httpupgrade',
      host: stringValue(http.host) || '',
      path: stringValue(http.path) || '/'
    }
  }

  if (network === 'http' || network === 'h2') {
    const http = stream.httpSettings && typeof stream.httpSettings === 'object' ? stream.httpSettings : {}
    const host = stringListValue(http.host)
    return {
      type: 'http',
      host: host || [],
      path: stringValue(http.path) || '/'
    }
  }

  return undefined
}

function xrayOutboundToProfiles(raw: Record<string, any>): VpnProfile[] {
  const protocol = xrayProtocol(raw.protocol)
  if (!protocol) return []
  const settings = raw.settings && typeof raw.settings === 'object' ? raw.settings : {}
  const stream = raw.streamSettings && typeof raw.streamSettings === 'object' ? raw.streamSettings : {}
  const tag = stringValue(raw.tag) || protocol.toUpperCase()
  const profiles: VpnProfile[] = []

  if (protocol === 'vless' || protocol === 'vmess') {
    const vnext = Array.isArray(settings.vnext) ? settings.vnext : []
    for (const node of vnext) {
      const server = stringValue(node?.address)
      if (!server) continue
      const port = numberPort(String(node?.port || ''))
      const users = Array.isArray(node?.users) && node.users.length ? node.users : [{}]
      for (let i = 0; i < users.length; i++) {
        const user = users[i] || {}
        const outbound: Record<string, any> = {
          type: protocol,
          tag: 'proxy-out',
          server,
          server_port: port,
          uuid: stringValue(user.id) || stringValue(user.uuid) || ''
        }
        if (protocol === 'vmess') {
          outbound.security = stringValue(user.security) || 'auto'
          outbound.alter_id = Number(user.alterId || user.alter_id || 0)
        }
        const flow = stringValue(user.flow)
        if (flow) outbound.flow = flow
        const tls = buildTlsFromXrayStream(stream, server)
        if (tls) outbound.tls = tls
        const transport = buildTransportFromXrayStream(stream)
        if (transport) outbound.transport = transport
        profiles.push({
          name: users.length > 1 ? `${tag} #${i + 1}` : tag,
          protocol,
          outbound: finishOutbound(outbound)
        })
      }
    }
    return profiles
  }

  const servers = Array.isArray(settings.servers) ? settings.servers : []
  for (const node of servers) {
    const server = stringValue(node?.address)
    if (!server) continue
    const port = numberPort(String(node?.port || ''))
    const outbound: Record<string, any> = {
      type: protocol,
      tag: 'proxy-out',
      server,
      server_port: port
    }
    if (protocol === 'trojan' || protocol === 'hysteria2' || protocol === 'naive' || protocol === 'anytls' || protocol === 'shadowtls') {
      outbound.password = stringValue(node.password) || ''
      if (protocol === 'naive') outbound.username = stringValue(node.username) || stringValue(node.user) || ''
      if (protocol === 'shadowtls') outbound.version = Number(node.version || 3)
      if (protocol === 'hysteria2') {
        const obfs = node.obfs && typeof node.obfs === 'object' ? node.obfs : null
        const obfsType = stringValue(obfs?.type) || stringValue(node.obfs)
        const obfsPassword =
          stringValue(obfs?.password) ||
          stringValue(node.obfs_password) ||
          stringValue(node['obfs-password'])
        if (obfsType) outbound.obfs = { type: obfsType, password: obfsPassword || '' }
        const serverPorts = normalizeHysteria2ServerPorts(
          stringValue(node.server_ports) || stringValue(node.serverPorts) || stringValue(node.mport)
        )
        if (serverPorts) outbound.server_ports = serverPorts
        const hopInterval = stringValue(node.hop_interval) || stringValue(node.hopInterval)
        if (hopInterval) outbound.hop_interval = hopInterval
        const upMbps = Number(node.up_mbps ?? node.upMbps ?? node.upmbps)
        if (Number.isFinite(upMbps) && upMbps > 0) outbound.up_mbps = upMbps
        const downMbps = Number(node.down_mbps ?? node.downMbps ?? node.downmbps)
        if (Number.isFinite(downMbps) && downMbps > 0) outbound.down_mbps = downMbps
      }
    } else if (protocol === 'tuic') {
      outbound.uuid = stringValue(node.uuid) || stringValue(node.id) || ''
      outbound.password = stringValue(node.password) || ''
      const congestionControl = stringValue(node.congestion_control) || stringValue(node.congestionControl)
      if (congestionControl) outbound.congestion_control = congestionControl
      const udpRelayMode = stringValue(node.udp_relay_mode) || stringValue(node.udpRelayMode)
      if (udpRelayMode) outbound.udp_relay_mode = udpRelayMode
    } else if (protocol === 'shadowsocks') {
      outbound.method = stringValue(node.method) || stringValue(node.cipher) || ''
      outbound.password = stringValue(node.password) || ''
    }
    const tls = buildTlsFromXrayStream(stream, server)
    if (tls) outbound.tls = tls
    const transport = buildTransportFromXrayStream(stream)
    if (transport) outbound.transport = transport
    profiles.push({ name: tag, protocol, outbound: finishOutbound(outbound) })
  }
  return profiles
}

function jsonOutboundCandidatesToProfiles(candidates: any[]): VpnProfile[] {
  const singBoxProfiles = candidates
    .filter((outbound: any) => outbound && SUPPORTED_OUTBOUND_TYPES.has(String(outbound.type)))
    .map((outbound: any) => ({
      name: String(outbound.tag || outbound.type || 'sing-box'),
      protocol: 'sing-box' as const,
      outbound: finishOutbound(outbound)
    }))
  if (singBoxProfiles.length) return singBoxProfiles

  return candidates.flatMap((outbound: any) => {
    try {
      return outbound && typeof outbound === 'object' ? xrayOutboundToProfiles(outbound) : []
    } catch {
      return []
    }
  })
}

function findJsonDocumentEnd(text: string, start: number): number | null {
  const opener = text[start]
  const expectedCloser = opener === '{' ? '}' : opener === '[' ? ']' : null
  if (!expectedCloser) return null

  const stack = [expectedCloser]
  let quote: string | null = null
  let escaped = false
  for (let i = start + 1; i < text.length; i++) {
    const ch = text[i]
    if (quote) {
      if (escaped) {
        escaped = false
      } else if (ch === '\\') {
        escaped = true
      } else if (ch === quote) {
        quote = null
      }
      continue
    }

    if (ch === '"' || ch === "'") {
      quote = ch
      continue
    }
    if (ch === '{') {
      stack.push('}')
    } else if (ch === '[') {
      stack.push(']')
    } else if (ch === '}' || ch === ']') {
      if (stack[stack.length - 1] !== ch) return null
      stack.pop()
      if (!stack.length) return i + 1
    }
  }
  return null
}

function jsonDocumentTexts(text: string): string[] {
  const trimmed = text.trim()
  const documents: string[] = []
  const seen = new Set<string>()
  const add = (candidate: string) => {
    const item = candidate.trim()
    if (!item || seen.has(item)) return
    seen.add(item)
    documents.push(item)
  }

  if (trimmed.startsWith('{') || trimmed.startsWith('[')) add(trimmed)

  // Some subscription endpoints prepend profile metadata lines before JSON.
  for (let i = 0; i < text.length && documents.length < 12; i++) {
    const ch = text[i]
    if (ch !== '{' && ch !== '[') continue
    const end = findJsonDocumentEnd(text, i)
    if (!end) continue
    add(text.slice(i, end))
    i = end - 1
  }
  return documents
}

function collectTextVariants(text: string, maxDepth = 3): string[] {
  const variants: string[] = []
  const seen = new Set<string>()
  const queue: Array<{ text: string; depth: number }> = [{ text, depth: 0 }]
  while (queue.length && variants.length < 12) {
    const current = queue.shift()!
    const normalized = current.text.trim()
    if (!normalized || seen.has(normalized)) continue
    seen.add(normalized)
    variants.push(current.text)
    if (current.depth >= maxDepth) continue
    const decoded = decodeBase64Loose(current.text)
    if (decoded && decoded.trim() && !seen.has(decoded.trim())) {
      queue.push({ text: decoded, depth: current.depth + 1 })
    }
  }
  return variants
}

function cleanExtractedUri(raw: string): string {
  let value = raw.trim()
  while (/[),.;\]}]+$/.test(value)) value = value.slice(0, -1)
  return value
}

function parseUriProfilesFromText(text: string): VpnProfile[] {
  const profiles: VpnProfile[] = []
  const seen = new Set<string>()
  const addCandidate = (candidate: string) => {
    const uri = cleanExtractedUri(candidate)
    if (!uri || seen.has(uri)) return
    seen.add(uri)
    try {
      const profile = parseLine(uri)
      if (profile) profiles.push(profile)
    } catch {
      // Ignore broken entries in a mixed subscription and keep parsing the rest.
    }
  }

  for (const line of text.replace(/\r/g, '\n').split('\n')) {
    const trimmed = line.trim()
    if (/^(vless|trojan|ss|vmess|hysteria2|hy2|naive|anytls|shadowtls|tuic):\/\//i.test(trimmed)) addCandidate(trimmed)
  }

  const uriPattern = /\b(?:vless|trojan|ss|vmess|hysteria2|hy2|naive|anytls|shadowtls|tuic):\/\/[^\s"'<>`\\]+/gi
  for (const match of text.matchAll(uriPattern)) addCandidate(match[0])
  return profiles
}

function parseJsonValueProfiles(value: any, seenTexts: Set<string>, depth = 0): VpnProfile[] {
  if (depth > 6 || value === null || value === undefined) return []

  if (typeof value === 'string') {
    const variants = collectTextVariants(value, 2)
    for (const decoded of variants) {
      for (const document of jsonDocumentTexts(decoded)) {
        if (seenTexts.has(document)) continue
        seenTexts.add(document)
        try {
          const profiles = parseJsonValueProfiles(JSON.parse(document), seenTexts, depth + 1)
          if (profiles.length) return profiles
        } catch {
          // Try the next embedded JSON document, if any.
        }
      }
    }

    for (const decoded of variants) {
      const clashProfiles = parseClashProfiles(decoded)
      if (clashProfiles.length) return clashProfiles
      const uriProfiles = parseUriProfilesFromText(decoded)
      if (uriProfiles.length) return uriProfiles
    }
    return []
  }

  if (Array.isArray(value)) {
    const directProfiles = jsonOutboundCandidatesToProfiles(value)
    if (directProfiles.length) return directProfiles

    const nestedProfiles: VpnProfile[] = []
    for (const item of value) {
      const profiles = parseJsonValueProfiles(item, seenTexts, depth + 1)
      if (profiles.length) nestedProfiles.push(...profiles)
    }
    return nestedProfiles
  }

  if (typeof value !== 'object') return []

  if (Array.isArray(value.outbounds)) {
    const profiles = jsonOutboundCandidatesToProfiles(value.outbounds)
    if (profiles.length) return profiles
  }

  const directProfile = jsonOutboundCandidatesToProfiles([value])
  if (directProfile.length) return directProfile

  // Some clients wrap the real Xray JSON into a subscription object/string.
  const preferredKeys = [
    'xrayFullConfig',
    'fullConfig',
    'full_config',
    'rawConfig',
    'raw_config',
    'config',
    'configs',
    'configuration',
    'profile',
    'profiles',
    'server',
    'servers',
    'node',
    'nodes',
    'data',
    'result',
    'subscription'
  ]

  const visitedKeys = new Set<string>()
  for (const key of preferredKeys) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) continue
    visitedKeys.add(key)
    const profiles = parseJsonValueProfiles(value[key], seenTexts, depth + 1)
    if (profiles.length) return profiles
  }

  for (const [key, child] of Object.entries(value)) {
    if (visitedKeys.has(key)) continue
    if (child === null || child === undefined) continue
    if (typeof child !== 'object' && typeof child !== 'string') continue
    const profiles = parseJsonValueProfiles(child, seenTexts, depth + 1)
    if (profiles.length) return profiles
  }

  return []
}

function parseJsonProfiles(text: string): VpnProfile[] {
  for (const document of jsonDocumentTexts(text)) {
    try {
      const profiles = parseJsonValueProfiles(JSON.parse(document), new Set([document]))
      if (profiles.length) return profiles
    } catch {
      // Keep looking; subscription metadata may contain unrelated braces.
    }
  }
  return []
}

function stripYamlComment(value: string): string {
  let quote: string | null = null
  for (let i = 0; i < value.length; i++) {
    const ch = value[i]
    if ((ch === '"' || ch === "'") && value[i - 1] !== '\\') {
      quote = quote === ch ? null : quote || ch
    }
    if (ch === '#' && !quote && (i === 0 || /\s/.test(value[i - 1]))) return value.slice(0, i).trim()
  }
  return value.trim()
}

function parseYamlScalar(value: string): any {
  const raw = stripYamlComment(value)
  if (!raw) return ''
  if (raw.startsWith('[') && raw.endsWith(']')) {
    return splitInlineYaml(raw.slice(1, -1)).map(item => parseYamlScalar(item))
  }
  if ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'"))) {
    return safeDecode(raw.slice(1, -1))
  }
  if (/^(true|false)$/i.test(raw)) return /^true$/i.test(raw)
  if (/^null$/i.test(raw)) return null
  if (/^-?\d+(\.\d+)?$/.test(raw)) return Number(raw)
  return safeDecode(raw)
}

function splitInlineYaml(value: string): string[] {
  const parts: string[] = []
  let quote: string | null = null
  let depth = 0
  let start = 0
  for (let i = 0; i < value.length; i++) {
    const ch = value[i]
    if ((ch === '"' || ch === "'") && value[i - 1] !== '\\') {
      quote = quote === ch ? null : quote || ch
    } else if (!quote && (ch === '{' || ch === '[')) {
      depth++
    } else if (!quote && (ch === '}' || ch === ']')) {
      depth = Math.max(0, depth - 1)
    } else if (!quote && depth === 0 && ch === ',') {
      parts.push(value.slice(start, i).trim())
      start = i + 1
    }
  }
  parts.push(value.slice(start).trim())
  return parts.filter(Boolean)
}

function findYamlKeySeparator(value: string): number {
  let quote: string | null = null
  for (let i = 0; i < value.length; i++) {
    const ch = value[i]
    if ((ch === '"' || ch === "'") && value[i - 1] !== '\\') {
      quote = quote === ch ? null : quote || ch
    } else if (ch === ':' && !quote) {
      return i
    }
  }
  return -1
}

function parseInlineYamlMap(value: string): Record<string, any> {
  const trimmed = value.trim().replace(/^\{/, '').replace(/\}$/, '')
  const result: Record<string, any> = {}
  for (const part of splitInlineYaml(trimmed)) {
    const idx = findYamlKeySeparator(part)
    if (idx <= 0) continue
    const key = part.slice(0, idx).trim()
    result[key] = parseYamlScalar(part.slice(idx + 1))
  }
  return result
}

function parseYamlObject(lines: string[]): Record<string, any> {
  const first = lines.find(line => line.trim())
  if (first?.trim().startsWith('{')) return parseInlineYamlMap(first.trim())

  const root: Record<string, any> = {}
  const stack: Array<{ indent: number; obj: Record<string, any> }> = [{ indent: -1, obj: root }]

  for (const rawLine of lines) {
    if (!rawLine.trim() || rawLine.trim().startsWith('#')) continue
    const indent = rawLine.match(/^\s*/)?.[0].length ?? 0
    const trimmed = rawLine.trim()
    const idx = findYamlKeySeparator(trimmed)
    if (idx <= 0) continue

    while (stack.length > 1 && indent <= stack[stack.length - 1].indent) stack.pop()
    const parent = stack[stack.length - 1].obj
    const key = trimmed.slice(0, idx).trim()
    const value = trimmed.slice(idx + 1).trim()
    if (!value) {
      const child: Record<string, any> = {}
      parent[key] = child
      stack.push({ indent, obj: child })
    } else if (value.startsWith('{') && value.endsWith('}')) {
      parent[key] = parseInlineYamlMap(value)
    } else {
      parent[key] = parseYamlScalar(value)
    }
  }

  return root
}

function collectClashProxyBlocks(text: string): string[][] {
  const lines = text.replace(/\r/g, '\n').split('\n')
  const blocks: string[][] = []
  let inProxies = false
  let current: string[] | null = null

  for (const line of lines) {
    if (!inProxies) {
      if (/^\s*proxies\s*:\s*(?:#.*)?$/i.test(line)) inProxies = true
      continue
    }

    if (/^\S[^:]*:\s*/.test(line)) break
    const item = line.match(/^(\s*)-\s*(.*)$/)
    if (item && item[1].length <= 2) {
      if (current?.length) blocks.push(current)
      const rest = item[2].trim()
      current = rest ? [`${item[1]}  ${rest}`] : []
      continue
    }
    if (current) current.push(line)
  }

  if (current?.length) blocks.push(current)
  return blocks
}

function buildTlsFromClash(raw: Record<string, any>, server: string): Record<string, any> | undefined {
  const realityOpts = raw['reality-opts'] && typeof raw['reality-opts'] === 'object' ? raw['reality-opts'] : null
  const serverName = stringValue(raw.servername) || stringValue(raw.sni) || stringValue(raw.host)
  const tlsEnabled = boolValue(raw.tls) || Boolean(serverName) || Boolean(realityOpts)
  if (!tlsEnabled) return undefined

  const tls: Record<string, any> = { enabled: true, server_name: serverName || server }
  if (boolValue(raw['skip-cert-verify']) || boolValue(raw.insecure)) tls.insecure = true
  const fp = stringValue(raw['client-fingerprint']) || stringValue(raw.fingerprint)
  if (fp && fp.toLowerCase() !== 'none') tls.utls = { enabled: true, fingerprint: fp }
  const alpn = stringListValue(raw.alpn)
  if (alpn) tls.alpn = alpn
  const ech = buildEchFromObject(raw)
  if (ech) tls.ech = ech

  if (realityOpts) {
    const publicKey = stringValue(realityOpts['public-key']) || stringValue(realityOpts.public_key) || stringValue(raw['reality-public-key'])
    if (publicKey) {
      if (!tls.utls) tls.utls = { enabled: true, fingerprint: 'chrome' }
      tls.reality = {
        enabled: true,
        public_key: publicKey,
        short_id: stringValue(realityOpts['short-id']) || stringValue(realityOpts.short_id) || ''
      }
    }
  }

  // Anti-DPI default: ensure every TLS outbound carries a browser-like
  // fingerprint and ALPN. Without this, sing-box emits a Go-stdlib
  // ClientHello (TSPU known-bad pattern) and Russian university DPI
  // rate-limits the connection. Reality already forces utls on its own
  // path; we only fill in the gaps for plain TLS.
  if (tls.enabled !== false) {
    if (!tls.utls || typeof tls.utls !== 'object' || tls.utls.enabled === false) {
      tls.utls = { enabled: true, fingerprint: 'chrome' }
    } else if (!tls.utls.fingerprint) {
      tls.utls.fingerprint = 'chrome'
    }
    if (!Array.isArray(tls.alpn) || tls.alpn.length === 0) {
      tls.alpn = ['h2', 'http/1.1']
    }
  }

  return tls
}

function buildTransportFromClash(raw: Record<string, any>): Record<string, any> | undefined {
  const network = (stringValue(raw.network) || stringValue(raw.net) || 'tcp').toLowerCase()
  if (!network || network === 'tcp') return undefined

  if (network === 'ws' || network === 'websocket') {
    const ws = raw['ws-opts'] && typeof raw['ws-opts'] === 'object' ? raw['ws-opts'] : {}
    const headers = ws.headers && typeof ws.headers === 'object' ? ws.headers : {}
    const transport: Record<string, any> = {
      type: 'ws',
      path: stringValue(ws.path) || stringValue(raw.path) || '/'
    }
    if (Object.keys(headers).length) transport.headers = headers
    return transport
  }

  if (network === 'grpc') {
    const grpc = raw['grpc-opts'] && typeof raw['grpc-opts'] === 'object' ? raw['grpc-opts'] : {}
    return {
      type: 'grpc',
      service_name: stringValue(grpc['grpc-service-name']) || stringValue(grpc.serviceName) || stringValue(raw['grpc-service-name']) || ''
    }
  }

  if (network === 'httpupgrade' || network === 'http-upgrade') {
    const http = raw['http-opts'] && typeof raw['http-opts'] === 'object' ? raw['http-opts'] : {}
    return {
      type: 'httpupgrade',
      host: stringValue(http.host) || stringValue(raw.host) || '',
      path: stringValue(http.path) || stringValue(raw.path) || '/'
    }
  }

  if (network === 'h2' || network === 'http') {
    const http = raw['http-opts'] && typeof raw['http-opts'] === 'object' ? raw['http-opts'] : {}
    const host = stringValue(http.host) || stringValue(raw.host)
    return {
      type: 'http',
      host: host ? [host] : [],
      path: stringValue(http.path) || stringValue(raw.path) || '/'
    }
  }

  return undefined
}

function clashProxyToProfile(raw: Record<string, any>): VpnProfile | null {
  const rawType = (stringValue(raw.type) || '').toLowerCase()
  const type = rawType === 'ss' ? 'shadowsocks' : rawType === 'hy2' ? 'hysteria2' : rawType
  if (!SUPPORTED_OUTBOUND_TYPES.has(type)) return null
  const server = stringValue(raw.server)
  const port = numberPort(String(raw.port || raw.server_port || ''))
  if (!server) return null

  const outbound: Record<string, any> = {
    type,
    tag: 'proxy-out',
    server,
    server_port: port
  }

  if (type === 'vless' || type === 'vmess') {
    outbound.uuid = stringValue(raw.uuid) || stringValue(raw.id) || ''
    if (type === 'vmess') {
      outbound.security = stringValue(raw.cipher) || stringValue(raw.security) || 'auto'
      outbound.alter_id = Number(raw.alterId || raw.alter_id || 0)
    }
    const flow = stringValue(raw.flow)
    if (flow) outbound.flow = flow
  } else if (type === 'trojan' || type === 'hysteria2' || type === 'naive' || type === 'anytls' || type === 'shadowtls') {
    outbound.password = stringValue(raw.password) || ''
    if (type === 'naive') outbound.username = stringValue(raw.username) || stringValue(raw.user) || ''
    if (type === 'shadowtls') outbound.version = Number(raw.version || 3)
    if (type === 'hysteria2') {
      const obfs = raw.obfs && typeof raw.obfs === 'object' ? raw.obfs : null
      const obfsType = stringValue(obfs?.type) || stringValue(raw.obfs)
      const obfsPassword =
        stringValue(obfs?.password) ||
        stringValue(raw['obfs-password']) ||
        stringValue(raw.obfs_password)
      if (obfsType) outbound.obfs = { type: obfsType, password: obfsPassword || '' }
      const serverPorts = normalizeHysteria2ServerPorts(
        stringValue(raw.server_ports) || stringValue(raw['server-ports']) || stringValue(raw.mport)
      )
      if (serverPorts) outbound.server_ports = serverPorts
      const hopInterval = stringValue(raw.hop_interval) || stringValue(raw['hop-interval'])
      if (hopInterval) outbound.hop_interval = hopInterval
      const upMbps = Number(raw.up_mbps ?? raw['up-mbps'] ?? raw.upmbps)
      if (Number.isFinite(upMbps) && upMbps > 0) outbound.up_mbps = upMbps
      const downMbps = Number(raw.down_mbps ?? raw['down-mbps'] ?? raw.downmbps)
      if (Number.isFinite(downMbps) && downMbps > 0) outbound.down_mbps = downMbps
    }
  } else if (type === 'tuic') {
    outbound.uuid = stringValue(raw.uuid) || stringValue(raw.id) || ''
    outbound.password = stringValue(raw.password) || ''
    const congestionControl = stringValue(raw.congestion_control) || stringValue(raw['congestion-control'])
    if (congestionControl) outbound.congestion_control = congestionControl
    const udpRelayMode = stringValue(raw.udp_relay_mode) || stringValue(raw['udp-relay-mode'])
    if (udpRelayMode) outbound.udp_relay_mode = udpRelayMode
  } else if (type === 'shadowsocks') {
    outbound.method = stringValue(raw.cipher) || stringValue(raw.method) || ''
    outbound.password = stringValue(raw.password) || ''
  }

  const tls = buildTlsFromClash(raw, server)
  if (tls) outbound.tls = tls
  const transport = buildTransportFromClash(raw)
  if (transport) outbound.transport = transport

  return {
    name: stringValue(raw.name) || type.toUpperCase(),
    protocol: type as VpnProtocol,
    outbound: finishOutbound(outbound)
  }
}

function parseClashProfiles(text: string): VpnProfile[] {
  if (!/^\s*proxies\s*:/im.test(text)) return []
  const profiles: VpnProfile[] = []
  for (const block of collectClashProxyBlocks(text)) {
    try {
      const profile = clashProxyToProfile(parseYamlObject(block))
      if (profile) profiles.push(profile)
    } catch {
      // Keep parsing other proxies if one YAML entry is unsupported/broken.
    }
  }
  return profiles
}

function parseLine(line: string): VpnProfile | null {
  const trimmed = line.trim()
  if (!trimmed || trimmed.startsWith('#')) return null
  const scheme = trimmed.match(/^([a-z0-9+.-]+):\/\//i)?.[1]?.toLowerCase()
  if (!scheme) return null
  if (scheme === 'vless') return parseVless(trimmed)
  if (scheme === 'trojan') return parseTrojan(trimmed)
  if (scheme === 'ss') return parseShadowsocks(trimmed)
  if (scheme === 'vmess') return parseVmess(trimmed)
  if (scheme === 'hysteria2' || scheme === 'hy2') return parseHysteria2(trimmed)
  if (scheme === 'naive') return parseNaive(trimmed)
  if (scheme === 'anytls') return parseAnyTls(trimmed)
  if (scheme === 'shadowtls') return parseShadowTls(trimmed)
  if (scheme === 'tuic') return parseTuic(trimmed)
  return null
}

export function parseVpnProfiles(text: string): VpnProfile[] {
  const inputs = collectTextVariants(text)

  for (const input of inputs) {
    try {
      const jsonProfiles = parseJsonProfiles(input)
      if (jsonProfiles.length) return jsonProfiles
    } catch {
      // Fall through; subscriptions often contain non-JSON text.
    }

    const clashProfiles = parseClashProfiles(input)
    if (clashProfiles.length) return clashProfiles
  }

  for (const input of inputs) {
    const uriProfiles = parseUriProfilesFromText(input)
    if (uriProfiles.length) return uriProfiles
  }
  return []
}

export function buildSubscriptionHwid(device: ClientDevice = 'pc'): string {
  const override = (process.env.VPNTE_SUBSCRIPTION_HWID || '').trim()
  if (override) return override
  const clientDevice = normalizeClientDevice(device)
  if (clientDevice === 'pc' || clientDevice === 'android' || clientDevice === 'ios' || clientDevice === 'mac') {
    return buildHappSubscriptionHwid(clientDevice)
  }

  let username = ''
  try {
    username = userInfo().username || ''
  } catch {
    username = process.env.USERNAME || process.env.USER || ''
  }
  const seed = [
    'vpn-tunnel-enforcer',
    clientDevice,
    hostname(),
    username,
    process.env.USERDOMAIN || '',
    process.arch,
    process.platform
  ].join('|')
  return `vpnte-${createHash('sha256').update(seed).digest('hex').slice(0, 32)}`
}

function subscriptionCommonCurlArgs(device: ClientDevice = 'pc'): string[] {
  // X-HWID is what every modern Marzban/Marzneshin-style panel uses to bind a
  // subscription to a specific device. Sosa Connect (sub.sosa.ink) and similar
  // panels return an EMPTY 200 OK when the header is missing — that's the
  // root cause of the long-standing "пустой ответ" failure.
  //
  // Earlier the header was removed under the (wrong) assumption that it was
  // causing the empty response. The actual behaviour is the opposite: most
  // panels require it. We always send a stable, hashed HWID derived from the
  // host so the panel can recognise this device on subsequent updates.
  //
  // For panels that explicitly reject unknown HWIDs (rare), buildFetchAttempts
  // will additionally fall back to no-header attempts.
  const clientDevice = normalizeClientDevice(device)
  const hwid = buildSubscriptionHwid(clientDevice)
  const args = ['-H', `x-hwid: ${hwid}`]
  const profile = DEVICE_HEADER_PROFILES[clientDevice]
  args.push(
    '-H', `x-device-os: ${profile.os}`,
    '-H', `x-ver-os: ${profile.osVersion}`,
    '-H', `x-device-model: ${profile.model}`
  )
  return args
}

// Same fetch args but without X-HWID, used as a secondary attempt for panels
// that would reject unknown device identifiers. Most won't need this branch.
function subscriptionFallbackCurlArgs(): string[] {
  return []
}

function buildFetchAttempts(options: SubscriptionFetchOptions = {}): FetchAttempt[] {
  const clientDevice = normalizeClientDevice(options.clientDevice)
  const headerSets: Array<{ args: string[]; suffix: string }> = [
    { args: subscriptionCommonCurlArgs(clientDevice), suffix: '' },
    { args: subscriptionFallbackCurlArgs(), suffix: ' [no-hwid]' }
  ]
  const bootstrapAttempts = buildBootstrapRouteAttempts({
    mode: options.bootstrapRouteMode,
    proxyAddr: options.proxyAddr,
    proxyType: options.proxyType
  })

  const attempts: FetchAttempt[] = []
  // Try with HWID first (Marzban/Sosa-style panels require it). Only if every
  // HWID-bearing attempt produces an empty body do we fall back to bare attempts.
  for (const headerSet of headerSets) {
    for (const ua of getSubscriptionUserAgents(clientDevice)) {
      for (const route of bootstrapAttempts) {
        attempts.push({
          label: `${route.label} (${ua})${headerSet.suffix}`,
          args: [...route.curlArgs, '--compressed', '-A', ua, ...headerSet.args]
        })
      }
    }
  }
  return attempts
}

async function resolveHostWithDoh(host: string): Promise<string[]> {
  const resolvers = [
    {
      label: 'Cloudflare DoH',
      resolve: 'cloudflare-dns.com:443:1.1.1.1',
      url: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`,
      headers: ['-H', 'accept: application/dns-json']
    },
    {
      label: 'Google DoH',
      resolve: 'dns.google:443:8.8.8.8',
      url: `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`,
      headers: []
    }
  ]
  const ips: string[] = []
  const seen = new Set<string>()
  for (const resolver of resolvers) {
    try {
      const { stdout } = await execFile('curl.exe', [
        '-L',
        '-sS',
        '--fail',
        '--noproxy',
        '*',
        '--max-time',
        '12',
        '--connect-timeout',
        '6',
        '--resolve',
        resolver.resolve,
        ...resolver.headers,
        resolver.url
      ], {
        windowsHide: true,
        timeout: 15000,
        encoding: 'buffer',
        maxBuffer: 1024 * 1024
      })
      const parsed = JSON.parse(decodeSubscriptionBody(stdout as Buffer))
      const answers = Array.isArray(parsed.Answer) ? parsed.Answer : []
      for (const answer of answers) {
        const ip = stringValue(answer?.data)
        if (!ip || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip) || seen.has(ip)) continue
        seen.add(ip)
        ips.push(ip)
      }
      if (ips.length) return ips
    } catch {
      // Keep trying other DNS-over-HTTPS resolvers.
    }
  }
  return ips
}

async function buildDnsBypassAttempts(url: string, options: SubscriptionFetchOptions = {}): Promise<FetchAttempt[]> {
  if (options.bootstrapRouteMode === 'localProxy') return []
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return []
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return []
  const host = parsed.hostname
  if (!host || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host === 'localhost') return []

  const ips = (await resolveHostWithDoh(host)).slice(0, 3)
  if (!ips.length) return []
  const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80')
  const clientDevice = normalizeClientDevice(options.clientDevice)
  const headerSets: Array<{ args: string[]; suffix: string }> = [
    { args: subscriptionCommonCurlArgs(clientDevice), suffix: '' },
    { args: subscriptionFallbackCurlArgs(), suffix: ' [no-hwid]' }
  ]
  const attempts: FetchAttempt[] = []
  for (const headerSet of headerSets) {
    for (const ua of getSubscriptionUserAgents(clientDevice)) {
      for (const ip of ips) {
        attempts.push({
          label: `напрямую через DoH ${ip} (${ua})${headerSet.suffix}`,
          args: ['--noproxy', '*', '--compressed', '-A', ua, ...headerSet.args, '--resolve', `${host}:${port}:${ip}`]
        })
      }
    }
  }
  return attempts
}

function curlErrorMessage(err: any): string {
  const stderr = typeof err?.stderr === 'string' ? err.stderr.trim() : Buffer.isBuffer(err?.stderr) ? err.stderr.toString('utf8').trim() : ''
  const stdout = typeof err?.stdout === 'string' ? err.stdout.trim() : Buffer.isBuffer(err?.stdout) ? decodeSubscriptionBody(err.stdout).trim() : ''
  const message = stderr || stdout || err?.message || String(err)
  return redactSensitiveText(message).replace(/\s+/g, ' ').slice(0, 500)
}

function describeSubscriptionBody(text: string): string {
  const trimmed = text.trim()
  if (!trimmed) return 'пустой ответ'
  const parts = [`${Buffer.byteLength(text, 'utf8')} байт`]
  const first = trimmed[0]
  if (first === '<') {
    parts.push('похоже на HTML')
  } else if (first === '{' || first === '[' || /["'](?:outbounds|xrayFullConfig|config|proxies)["']\s*:/i.test(trimmed)) {
    parts.push('похоже на JSON')
    for (const document of jsonDocumentTexts(trimmed).slice(0, 1)) {
      try {
        const parsed = JSON.parse(document)
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
          const keys = Object.keys(parsed).slice(0, 8).join(',')
          if (keys) parts.push(`keys=${keys}`)
          if (Array.isArray(parsed.outbounds)) parts.push(`outbounds=${parsed.outbounds.length}`)
        } else if (Array.isArray(parsed)) {
          parts.push(`array=${parsed.length}`)
        }
      } catch {
        parts.push('JSON не разобран')
      }
    }
  } else if (/^[A-Za-z0-9+/=_-]{64,}$/.test(trimmed.replace(/\s+/g, ''))) {
    parts.push('похоже на base64')
  } else if (trimmed.includes('://')) {
    parts.push('есть URI-схемы')
  } else {
    parts.push(`начало=${JSON.stringify(trimmed.slice(0, 12))}`)
  }
  return parts.join(', ')
}

function summarizeSubscriptionErrors(errors: string[]): string {
  const primary = errors.slice(0, 6)
  const dnsBypass = errors
    .filter(error => /DoH|DNS-over-HTTPS/i.test(error) && !primary.includes(error))
    .slice(-4)
  const shown = [...primary, ...dnsBypass]
  const hidden = Math.max(0, errors.length - shown.length)
  if (hidden > 0) shown.push(`еще ${hidden} попыток не сработали`)
  return shown.join(' | ')
}

// ─── Subscription header parsing ────────────────────────────────────────────
//
// curl.exe with `-D -` dumps response headers to stdout BEFORE the body, with
// a `\r\n\r\n` terminator. With `-L` (follow redirects) it emits one header
// block per hop. We always want the LAST hop — that's the panel's actual
// response — so we scan from the end for the last terminator and treat
// everything after it as the body.
//
// Windows curl always uses CRLF; we don't bother with bare-LF fallbacks.

function lastIndexOfHeaderTerminator(buf: Buffer): number {
  // Search backwards for `\r\n\r\n` (CRLF CRLF). We only care about the last
  // occurrence: with -L, every redirect hop writes its own header block.
  for (let i = buf.length - 4; i >= 0; i--) {
    if (buf[i] === 0x0d && buf[i + 1] === 0x0a && buf[i + 2] === 0x0d && buf[i + 3] === 0x0a) {
      return i
    }
  }
  return -1
}

function parseHttpHeaders(text: string): Record<string, string> {
  // The text contains potentially MULTIPLE header blocks separated by blank
  // lines (one per redirect hop). We want the last block — that's the final
  // response. Split on blank-line boundaries first, then parse the last
  // non-empty group.
  const lines = text.replace(/\r/g, '').split('\n')
  const blocks: string[][] = []
  let current: string[] = []
  for (const line of lines) {
    if (!line.trim()) {
      if (current.length) {
        blocks.push(current)
        current = []
      }
      continue
    }
    current.push(line)
  }
  if (current.length) blocks.push(current)
  if (!blocks.length) return {}
  const lastBlock = blocks[blocks.length - 1]

  const headers: Record<string, string> = {}
  // Skip the status line (e.g. `HTTP/1.1 200 OK`) — it has no `:` separator
  // we care about. Be defensive: some non-conforming servers omit it.
  const startIdx = /^HTTP\/[0-9.]+\s/i.test(lastBlock[0]) ? 1 : 0
  for (let i = startIdx; i < lastBlock.length; i++) {
    const line = lastBlock[i]
    const sep = line.indexOf(':')
    if (sep <= 0) continue
    const key = line.slice(0, sep).trim().toLowerCase()
    const value = line.slice(sep + 1).trim()
    if (!key) continue
    // Last writer wins — RFC says repeated headers can be combined with
    // commas, but for the fields we care about (subscription-userinfo,
    // profile-update-interval, profile-web-page-url) panels always emit a
    // single value.
    headers[key] = value
  }
  return headers
}

function parseHttpStatusCode(text: string): number | null {
  const firstLine = text.replace(/\r/g, '').split('\n').find(Boolean)
  const match = firstLine?.match(/^HTTP\/[0-9.]+\s+(\d{3})\b/i)
  if (!match) return null
  const code = Number(match[1])
  return Number.isInteger(code) ? code : null
}

export function normalizeSubscriptionRedirectLocation(location: string, baseUrl: string): string | null {
  let value = location.trim()
  if (!value) return null
  value = value.replace(/^<(.+)>$/, '$1').replace(/^["'](.+)["']$/, '$1').trim()
  value = value.replace(/^url\s*[:=]\s*/i, '').trim()

  const decoded = safeDecode(value).trim().replace(/^url\s*[:=]\s*/i, '').trim()
  if (/^(?:https?|happ|mantaray):\/\//i.test(decoded)) value = decoded

  if (/^\/\//.test(value)) {
    try {
      return `${new URL(baseUrl).protocol}${value}`
    } catch {
      return value
    }
  }

  if (/^https?:\/\//i.test(value) || /^happ:\/\//i.test(value) || /^mantaray:\/\//i.test(value)) return value

  try {
    return new URL(value, baseUrl).toString()
  } catch {
    return value
  }
}

async function fetchSubscriptionHttpResponse(url: string, attempt: FetchAttempt): Promise<SubscriptionHttpResponse> {
  let currentUrl = url
  const visited = new Set<string>()

  for (let hop = 0; hop < 6; hop++) {
    if (visited.has(currentUrl)) throw new Error('redirect loop while fetching subscription')
    visited.add(currentUrl)

    const { stdout } = await execFile('curl.exe', [
      '-sS',
      '--fail',
      // We follow redirects ourselves because some panels redirect to
      // happ://add/... or malformed "URL: https://..." targets that make
      // curl -L abort before we can inspect Location.
      '-D',
      '-',
      '--max-time',
      '25',
      ...attempt.args,
      currentUrl
    ], {
      windowsHide: true,
      timeout: 30000,
      encoding: 'buffer',
      maxBuffer: 1024 * 1024 * 16
    })

    const raw = stdout as Buffer
    const splitIdx = lastIndexOfHeaderTerminator(raw)
    const headerBytes = splitIdx >= 0 ? raw.subarray(0, splitIdx) : Buffer.alloc(0)
    const bodyBytes = splitIdx >= 0 ? raw.subarray(splitIdx + 4) : raw
    const headerText = headerBytes.toString('utf8')
    const headers = parseHttpHeaders(headerText)
    const statusCode = parseHttpStatusCode(headerText)

    if (statusCode !== null && statusCode >= 300 && statusCode < 400 && headers.location) {
      const next = normalizeSubscriptionRedirectLocation(headers.location, currentUrl)
      if (!next) throw new Error('redirect without a usable Location header')

      const unwrapped = unwrapClientDeepLink(next)
      const effectiveNext = unwrapped ?? next
      if (/^https?:\/\//i.test(effectiveNext)) {
        currentUrl = effectiveNext
        continue
      }
      if (/^(?:vless|trojan|ss|vmess|hysteria2|hy2|naive|anytls|shadowtls|tuic):\/\//i.test(effectiveNext)) {
        return { headers, body: effectiveNext }
      }

      const body = decodeSubscriptionBody(bodyBytes)
      if (body.trim()) return { headers, body }
      throw new Error(`unsupported subscription redirect target: ${redactSensitiveText(effectiveNext).slice(0, 120)}`)
    }

    return { headers, body: decodeSubscriptionBody(bodyBytes) }
  }

  throw new Error('too many redirects while fetching subscription')
}

function parseSubscriptionUserInfo(headers: Record<string, string>): SubscriptionUserInfo | undefined {
  const result: SubscriptionUserInfo = {}
  let touched = false

  const rawUserInfo = headers['subscription-userinfo']
  if (rawUserInfo) {
    // Format: `upload=12345; download=67890; total=1000000000; expire=1735689600`
    // Whitespace around `;` and `=` is tolerated by every panel we've seen.
    let upload: number | undefined
    let download: number | undefined
    for (const part of rawUserInfo.split(';')) {
      const eq = part.indexOf('=')
      if (eq <= 0) continue
      const key = part.slice(0, eq).trim().toLowerCase()
      const valueText = part.slice(eq + 1).trim()
      if (!valueText) continue
      const value = Number(valueText)
      if (!Number.isFinite(value) || value < 0) continue
      if (key === 'upload') upload = value
      else if (key === 'download') download = value
      else if (key === 'total') { result.trafficTotalBytes = value; touched = true }
      else if (key === 'expire') {
        // Header gives unix seconds. Multiply to ms for Date.now() compat.
        // Treat 0 as "no expiry set" (some panels emit `expire=0`).
        if (value > 0) { result.expiresAt = value * 1000; touched = true }
      }
    }
    if (upload !== undefined) { result.trafficUploadBytes = upload; touched = true }
    if (download !== undefined) { result.trafficDownloadBytes = download; touched = true }
    if (upload !== undefined || download !== undefined) {
      result.trafficUsedBytes = (upload ?? 0) + (download ?? 0)
      touched = true
    }
  }

  const refreshRaw = headers['profile-update-interval']
  if (refreshRaw) {
    const refresh = Number(refreshRaw.trim())
    if (Number.isFinite(refresh) && refresh > 0 && Number.isInteger(refresh)) {
      result.refreshIntervalSeconds = refresh
      touched = true
    }
  }

  const webPage = headers['profile-web-page-url']
  if (webPage) {
    const trimmed = webPage.trim()
    // Drop anything that isn't an http(s) URL. Some panels accidentally emit
    // garbage here (relative paths, `null`, …) and we don't want the renderer
    // to render an unsafe link.
    if (/^https?:\/\//i.test(trimmed)) {
      result.webPageUrl = trimmed
      touched = true
    }
  }

  return touched ? result : undefined
}

async function fetchAndParseSubscription(url: string, options?: SubscriptionFetchOptions): Promise<{ profiles: VpnProfile[]; source: string; userInfo?: SubscriptionUserInfo }> {
  const errors: string[] = []
  const runAttempts = async (attempts: FetchAttempt[]) => {
    for (const attempt of attempts) {
      try {
        const response = await fetchSubscriptionHttpResponse(url, attempt)
        const userInfo = parseSubscriptionUserInfo(response.headers)
        const body = response.body
        const profiles = parseVpnProfiles(body)
        if (profiles.length) return { profiles, source: attempt.label, userInfo }
        errors.push(`${attempt.label}: скачано (${describeSubscriptionBody(body)}), но VLESS/Trojan/SS/VMess/Hysteria2 не найдены`)
      } catch (err: any) {
        errors.push(`${attempt.label}: ${curlErrorMessage(err)}`)
      }
    }
    return null
  }

  const directResult = await runAttempts(buildFetchAttempts(options))
  if (directResult) return directResult

  const dnsBypassAttempts = await buildDnsBypassAttempts(url, options)
  if (dnsBypassAttempts.length) {
    const dnsBypassResult = await runAttempts(dnsBypassAttempts)
    if (dnsBypassResult) return dnsBypassResult
  } else if (/^https?:\/\//i.test(url)) {
    errors.push('DNS-over-HTTPS fallback: не удалось получить A-записи для домена подписки')
  }

  throw new Error(`Не удалось скачать или распознать subscription. ${summarizeSubscriptionErrors(errors)}`)
}
/**
 * Unwraps a Happ deep-link to extract a usable subscription URL or VPN-link.
 *
 * Happ uses several `happ://` schemes (see Happ-docs/dev-docs):
 *   - `happ://add/<payload>` — community shorthand used by VPN providers
 *     (Sosa, Marzban, etc.). Payload is the subscription URL, either
 *     URL-encoded or base64-encoded. We try both and return the unwrapped URL.
 *   - `happ://routing/add/{base64}` and `happ://routing/onadd/{base64}` —
 *     routing profile (NOT a server subscription). Reject with a clear error
 *     so we don't silently produce 0 profiles.
 *   - `happ://crypt3/...`, `happ://crypt4/...`, `happ://crypt5/...` —
 *     RSA-encrypted subscriptions. The keys live inside the Happ app and we
 *     can't decrypt them here. Reject with a clear error.
 *
 * Returns the unwrapped string (a regular URL or VPN URI) or `null` if the
 * input isn't a `happ://` link.
 */
function unwrapHappAddLink(input: string): string | null {
  const match = input.match(/^happ:\/\/([^/]+)(?:\/(.*))?$/i)
  if (!match) return null
  const host = match[1].toLowerCase()
  const rest = match[2] ?? ''

  if (host === 'crypt3' || host === 'crypt4' || host === 'crypt5' || host === 'crypto') {
    throw new Error(
      'Это зашифрованная подписка Happ (' + host + '). VPNTE не умеет её расшифровать — ' +
      'попросите у вашего провайдера обычный subscription URL (https://…) или vless://-ссылку.'
    )
  }

  if (host === 'routing') {
    throw new Error(
      'Это правило маршрутизации Happ (happ://routing/…), а не VPN-подписка. ' +
      'Вставьте ссылку на подписку или ключ протокола (vless://, trojan://, ss://, vmess://, hysteria2://, naive://, anytls://, shadowtls://, tuic://).'
    )
  }

  if (host === 'add') {
    // Payload might be URL-encoded (https%3A%2F%2F…), bare URL after the slash,
    // base64 of a URL, base64 of a base64-list of vless://… links — try each.
    const candidates: string[] = []
    const trySafeDecode = (value: string) => {
      const decoded = safeDecode(value).trim()
      if (decoded) candidates.push(decoded)
    }
    trySafeDecode(rest)
    // Some senders include the scheme in the path: happ://add/https://example/sub
    if (/^https?:\/\//i.test(rest)) candidates.push(rest)
    const base64 = decodeBase64Text(rest)
    if (base64) candidates.push(base64.trim())

    for (const candidate of candidates) {
      if (/^https?:\/\//i.test(candidate)) return candidate
      if (/^(?:vless|trojan|ss|vmess|hysteria2|hy2|naive|anytls|shadowtls|tuic):\/\//i.test(candidate)) return candidate
      // Could be a base64 blob with multiple vless:// lines — let parseVpnProfiles handle it.
      if (/(?:vless|trojan|ss|vmess|hysteria2|hy2|naive|anytls|shadowtls|tuic):\/\//i.test(candidate)) return candidate
    }

    throw new Error(
      'Не удалось разобрать ссылку happ://add/… — внутри ожидается subscription URL или ' +
      'vless://-ссылка, но содержимое не похоже ни на то, ни на другое.'
    )
  }

  // Unknown happ:// host — bail out loudly instead of silently producing 0 profiles.
  throw new Error(
    'Неизвестная схема happ://' + host + '/. Вставьте обычную ссылку подписки (https://…) ' +
    'или ключ протокола (vless://, trojan://, ss://, vmess://, hysteria2://, naive://, anytls://, shadowtls://, tuic://).'
  )
}

function unwrapMantarayLink(input: string): string | null {
  const match = input.match(/^mantaray:\/\/([^/]+)(?:\/(.*))?$/i)
  if (!match) return null
  const host = match[1].toLowerCase()
  const rest = match[2] ?? ''

  if (host === 'crypt' || host === 'crypto' || host === 'crypt3' || host === 'crypt4' || host === 'crypt5') {
    throw new Error(
      'Это зашифрованная подписка MantaRay (mantaray://' + host + '/...). VPNTE не может расшифровать ее без ключей приложения MantaRay. ' +
      'Попросите у провайдера обычный subscription URL (https://...) или прямую ссылку ключа (vless://, trojan://, ss://, vmess://, hysteria2://, naive://, anytls://, shadowtls://, tuic://).'
    )
  }

  if (host === 'add' || host === 'import' || host === 'sub' || host === 'subscription') {
    const candidates: string[] = []
    const decoded = safeDecode(rest).trim()
    if (decoded) candidates.push(decoded)
    if (/^https?:\/\//i.test(rest)) candidates.push(rest)
    const base64 = decodeBase64Text(rest)
    if (base64) candidates.push(base64.trim())

    for (const candidate of candidates) {
      if (/^https?:\/\//i.test(candidate)) return candidate
      if (/^(?:vless|trojan|ss|vmess|hysteria2|hy2|naive|anytls|shadowtls|tuic):\/\//i.test(candidate)) return candidate
      if (/(?:vless|trojan|ss|vmess|hysteria2|hy2|naive|anytls|shadowtls|tuic):\/\//i.test(candidate)) return candidate
    }

    throw new Error(
      'Не удалось разобрать ссылку mantaray://' + host + '/... — внутри ожидается обычный subscription URL или ключ протокола.'
    )
  }

  throw new Error(
    'Неизвестная схема mantaray://' + host + '/. Вставьте обычный subscription URL (https://...) или ключ протокола.'
  )
}

function unwrapClientDeepLink(input: string): string | null {
  return unwrapHappAddLink(input) ?? unwrapMantarayLink(input)
}

export async function resolveVpnProfiles(input: string, options?: SubscriptionFetchOptions): Promise<{ profiles: VpnProfile[]; source: string; fetched: boolean; userInfo?: SubscriptionUserInfo }> {
  const trimmed = input.trim()
  if (!trimmed) throw new Error('Вставьте VPN-ссылку, subscription URL или sing-box outbound JSON')

  // Auto-unwrap `happ://add/<encoded-url>` etc. before hitting the regular pipeline.
  // This is the format VPN providers (Sosa, Marzban, …) put into their share buttons.
  const unwrapped = unwrapClientDeepLink(trimmed)
  const effective = unwrapped ?? trimmed

  if (/^https?:\/\//i.test(effective)) {
    const result = await fetchAndParseSubscription(effective, options)
    return { ...result, fetched: true }
  }

  const profiles = parseVpnProfiles(effective)
  return { profiles, source: unwrapped ? 'распакованная ссылка happ://' : 'вставленный текст', fetched: false, userInfo: undefined }
}

export async function resolveVpnProfile(input: string, selectedIndex = 0, options?: SubscriptionFetchOptions): Promise<VpnProfile> {
  const { profiles } = await resolveVpnProfiles(input, options)
  if (!profiles.length) {
    throw new Error('В подписке/ключе не найдено поддерживаемых профилей (VLESS, Trojan, Shadowsocks, VMess, Hysteria2, Naive, AnyTLS, ShadowTLS, TUIC или sing-box outbound JSON)')
  }
  return profiles[Math.min(Math.max(0, selectedIndex), profiles.length - 1)]
}

export async function inspectVpnInput(input: string, options?: SubscriptionFetchOptions): Promise<VpnInputInspection> {
  if (!input.trim()) {
    return { count: 0, protocols: {}, profiles: [], fetched: false, source: 'пусто' }
  }
  const resolved = await resolveVpnProfiles(input, options)
  const profiles = resolved.profiles
  const protocols: Record<string, number> = {}
  for (const profile of profiles) {
    protocols[profile.protocol] = (protocols[profile.protocol] || 0) + 1
  }
  return {
    count: profiles.length,
    protocols,
    profiles: profiles.map((profile, index) => ({ index, name: profile.name, protocol: profile.protocol })),
    fetched: resolved.fetched,
    source: resolved.source
  }
}

export function redactSensitiveConfig(value: unknown): unknown {
  if (typeof value === 'string') {
    return redactSensitiveText(value)
  }
  if (Array.isArray(value)) return value.map(item => redactSensitiveConfig(item))
  if (value && typeof value === 'object') {
    const result: Record<string, unknown> = {}
    for (const [key, raw] of Object.entries(value as Record<string, unknown>)) {
      const lower = key.toLowerCase()
      if (SECRET_KEYS.has(lower) || /uuid|password|token|secret|private[_-]?key|public[_-]?key|short[_-]?id|^id$/i.test(key)) {
        result[key] = '<redacted>'
      } else {
        result[key] = redactSensitiveConfig(raw)
      }
    }
    return result
  }
  return value
}

export function redactSettingsForDiagnostics<T extends Record<string, any>>(settings: T): T {
  return {
    ...settings,
    directVpnInput: settings.directVpnInput ? '<redacted>' : '',
    directVpnCachedInput: settings.directVpnCachedInput ? '<redacted>' : '',
    directVpnCachedProfiles: Array.isArray(settings.directVpnCachedProfiles)
      ? settings.directVpnCachedProfiles.map((profile: any, index: number) => ({
          index,
          name: profile?.name,
          protocol: profile?.protocol,
          outbound: '<redacted>'
        }))
      : []
  }
}


// ─── Outbound → URI export ──────────────────────────────────────────────────
//
// Inverse of parseVless / parseTrojan / parseVmess / parseShadowsocks /
// parseHysteria2. Lets the user export a saved server profile back to a
// shareable single-line key (vless://…, trojan://…, ss://…, vmess://…,
// hysteria2://…) so they can paste it into Happ, v2RayN, sing-box CLI, or
// hand it off to another device.
//
// Notes:
//   - We round-trip outbounds that came from URI imports lossless-ly; the
//     output URL is functionally equivalent to whatever the user originally
//     pasted (modulo URL-encoding nits in fragments/comments).
//   - Hysteria2 output is best-effort: not every implementation accepts the
//     exact same query-string flavour, so we stick to the params Happ and
//     v2RayN both understand.
//   - The function intentionally does not redact secrets — the caller is
//     responsible for showing it only to the local user (clipboard is fine,
//     diagnostic exports are not).

function appendTransportParams(params: URLSearchParams, transport: Record<string, any> | undefined): void {
  if (!transport || typeof transport !== 'object') return
  const type = String(transport.type || '').toLowerCase()
  if (!type || type === 'tcp' || type === 'raw') return
  if (type === 'ws') {
    params.set('type', 'ws')
    if (typeof transport.path === 'string' && transport.path) params.set('path', transport.path)
    const headerHost = transport.headers && typeof transport.headers === 'object' ? transport.headers.Host || transport.headers.host : null
    if (headerHost) params.set('host', String(headerHost))
    if (Number.isInteger(transport.max_early_data) && transport.max_early_data > 0) params.set('ed', String(transport.max_early_data))
    if (typeof transport.early_data_header_name === 'string' && transport.early_data_header_name) {
      params.set('eh', transport.early_data_header_name)
    }
  } else if (type === 'grpc') {
    params.set('type', 'grpc')
    if (typeof transport.service_name === 'string' && transport.service_name) params.set('serviceName', transport.service_name)
  } else if (type === 'httpupgrade') {
    params.set('type', 'httpupgrade')
    if (typeof transport.host === 'string' && transport.host) params.set('host', transport.host)
    if (typeof transport.path === 'string' && transport.path) params.set('path', transport.path)
  } else if (type === 'http') {
    params.set('type', 'http')
    if (Array.isArray(transport.host) && transport.host.length) params.set('host', String(transport.host[0]))
    if (typeof transport.path === 'string' && transport.path) params.set('path', transport.path)
  } else {
    params.set('type', type)
  }
}

function appendTlsParams(params: URLSearchParams, tls: Record<string, any> | undefined, host: string): boolean {
  if (!tls || tls.enabled === false) return false
  const isReality = tls.reality && typeof tls.reality === 'object' && tls.reality.enabled !== false
  params.set('security', isReality ? 'reality' : 'tls')
  const sni = String(tls.server_name || '').trim()
  if (sni && sni !== host) params.set('sni', sni)
  if (Array.isArray(tls.alpn) && tls.alpn.length) params.set('alpn', tls.alpn.join(','))
  if (tls.insecure === true) params.set('allowInsecure', '1')
  const fp = tls.utls && typeof tls.utls === 'object' && typeof tls.utls.fingerprint === 'string'
    ? tls.utls.fingerprint
    : null
  if (fp) params.set('fp', fp)
  if (isReality) {
    if (typeof tls.reality.public_key === 'string' && tls.reality.public_key) params.set('pbk', tls.reality.public_key)
    if (typeof tls.reality.short_id === 'string' && tls.reality.short_id) params.set('sid', tls.reality.short_id)
  }
  const ech = tls.ech && typeof tls.ech === 'object' && tls.ech.enabled !== false ? tls.ech : null
  if (ech) {
    params.set('ech', '1')
    if (Array.isArray(ech.config) && ech.config.length) params.set('echConfig', ech.config.join(','))
    if (typeof ech.config_path === 'string' && ech.config_path) params.set('echConfigPath', ech.config_path)
    if (typeof ech.query_server_name === 'string' && ech.query_server_name) {
      params.set('echQueryServerName', ech.query_server_name)
    }
  }
  return true
}

export function describeVpnProfileCapabilities(
  profileOrOutbound: { protocol?: string; outbound?: Record<string, any> } | Record<string, any>
): VpnProfileCapabilitySummary {
  const maybeProfile = profileOrOutbound as { protocol?: string; outbound?: Record<string, any> }
  const outbound = maybeProfile.outbound && typeof maybeProfile.outbound === 'object'
    ? maybeProfile.outbound
    : profileOrOutbound as Record<string, any>
  const protocol = String(maybeProfile.protocol || outbound.type || 'unknown').toLowerCase()
  const tls = outbound.tls && typeof outbound.tls === 'object' && outbound.tls.enabled !== false
    ? outbound.tls as Record<string, any>
    : null
  const ech = tls?.ech && typeof tls.ech === 'object' && tls.ech.enabled !== false
    ? tls.ech as Record<string, any>
    : null
  const echHasConfig =
    !!ech &&
    ((Array.isArray(ech.config) && ech.config.length > 0) ||
      Boolean(ech.config_path) ||
      Boolean(ech.query_server_name))
  const warnings: string[] = []

  if (tls?.insecure === true) warnings.push('TLS certificate verification is disabled')
  if (protocol === 'naive' && tls?.insecure === true) warnings.push('Naive in sing-box does not support tls.insecure')
  if (ech && !echHasConfig) warnings.push('ECH is enabled but no config, config_path, or query_server_name is set')
  if (protocol === 'hysteria2') {
    const obfsType = outbound.obfs && typeof outbound.obfs === 'object'
      ? String(outbound.obfs.type || '').toLowerCase()
      : ''
    if (!obfsType) warnings.push('Hysteria2 obfs is not configured')
    if (obfsType === 'gecko') warnings.push('Hysteria2 gecko obfs requires sing-box 1.14+')
    if (outbound.network === 'tcp') warnings.push('Hysteria2 uses QUIC/UDP; tcp-only routing can block it')
  }

  let stealthPreset: VpnProfileStealthPreset = 'plain'
  if (tls?.reality && typeof tls.reality === 'object' && tls.reality.enabled !== false) {
    stealthPreset = 'reality-utls'
  } else if (protocol === 'naive' && echHasConfig) {
    stealthPreset = 'naive-ech'
  } else if (protocol === 'naive') {
    stealthPreset = 'naive'
  } else if (protocol === 'hysteria2' && outbound.obfs && typeof outbound.obfs === 'object') {
    stealthPreset = 'hysteria2-obfs'
  } else if (tls?.utls && typeof tls.utls === 'object' && tls.utls.enabled !== false) {
    stealthPreset = 'tls-utls'
  }

  return {
    protocol,
    stealthPreset,
    tlsConfigured: Boolean(tls),
    echConfigured: echHasConfig,
    warnings
  }
}

function buildHostPort(server: string, port: unknown): string {
  const portStr = Number.isFinite(Number(port)) ? String(Number(port)) : String(port ?? '')
  if (server.includes(':') && !server.startsWith('[')) {
    return `[${server}]${portStr ? `:${portStr}` : ''}`
  }
  return portStr ? `${server}:${portStr}` : server
}

function nameToFragment(name: string | undefined): string {
  if (!name) return ''
  return '#' + encodeURIComponent(name).replace(/%20/g, '%20')
}

function vlessToUri(name: string, outbound: Record<string, any>): string {
  const params = new URLSearchParams()
  params.set('encryption', 'none')
  appendTlsParams(params, outbound.tls, String(outbound.server || ''))
  appendTransportParams(params, outbound.transport)
  if (typeof outbound.flow === 'string' && outbound.flow) params.set('flow', outbound.flow)
  if (typeof outbound.packet_encoding === 'string' && outbound.packet_encoding) {
    params.set('packetEncoding', outbound.packet_encoding)
  }
  const uuid = encodeURIComponent(String(outbound.uuid || ''))
  const authority = buildHostPort(String(outbound.server || ''), outbound.server_port)
  return `vless://${uuid}@${authority}?${params.toString()}${nameToFragment(name)}`
}

function trojanToUri(name: string, outbound: Record<string, any>): string {
  const params = new URLSearchParams()
  appendTlsParams(params, outbound.tls, String(outbound.server || ''))
  appendTransportParams(params, outbound.transport)
  const password = encodeURIComponent(String(outbound.password || ''))
  const authority = buildHostPort(String(outbound.server || ''), outbound.server_port)
  return `trojan://${password}@${authority}?${params.toString()}${nameToFragment(name)}`
}

function shadowsocksToUri(name: string, outbound: Record<string, any>): string {
  const method = String(outbound.method || '')
  const password = String(outbound.password || '')
  const userinfo = Buffer.from(`${method}:${password}`, 'utf8').toString('base64').replace(/=+$/, '')
  const authority = buildHostPort(String(outbound.server || ''), outbound.server_port)
  return `ss://${userinfo}@${authority}${nameToFragment(name)}`
}

function vmessToUri(name: string, outbound: Record<string, any>): string {
  // VMess shares one canonical JSON-base64 schema (the v2rayN flavour).
  const tls = outbound.tls && typeof outbound.tls === 'object' && outbound.tls.enabled !== false ? outbound.tls : null
  const transport = outbound.transport && typeof outbound.transport === 'object' ? outbound.transport : null
  const transportType = transport ? String(transport.type || '').toLowerCase() : ''
  const payload: Record<string, any> = {
    v: '2',
    ps: name || 'VMess',
    add: String(outbound.server || ''),
    port: Number(outbound.server_port || 0),
    id: String(outbound.uuid || ''),
    aid: Number(outbound.alter_id ?? 0),
    scy: String(outbound.security || 'auto'),
    net: transportType === 'ws' ? 'ws'
       : transportType === 'grpc' ? 'grpc'
       : transportType === 'http' ? 'http'
       : 'tcp',
    type: 'none',
    tls: tls ? 'tls' : ''
  }
  if (tls) {
    if (typeof tls.server_name === 'string' && tls.server_name) payload.sni = tls.server_name
    if (Array.isArray(tls.alpn) && tls.alpn.length) payload.alpn = tls.alpn.join(',')
    if (tls.utls && typeof tls.utls === 'object' && typeof tls.utls.fingerprint === 'string') {
      payload.fp = tls.utls.fingerprint
    }
  }
  if (transport) {
    if (transportType === 'ws') {
      if (typeof transport.path === 'string') payload.path = transport.path
      const headerHost = transport.headers && typeof transport.headers === 'object' ? transport.headers.Host || transport.headers.host : null
      if (headerHost) payload.host = String(headerHost)
    } else if (transportType === 'grpc') {
      if (typeof transport.service_name === 'string') payload.path = transport.service_name
    } else if (transportType === 'http') {
      if (Array.isArray(transport.host) && transport.host.length) payload.host = String(transport.host[0])
      if (typeof transport.path === 'string') payload.path = transport.path
    }
  }
  const json = JSON.stringify(payload)
  const b64 = Buffer.from(json, 'utf8').toString('base64')
  return `vmess://${b64}`
}

function hysteria2ToUri(name: string, outbound: Record<string, any>): string {
  const params = new URLSearchParams()
  if (outbound.tls && typeof outbound.tls === 'object') {
    if (typeof outbound.tls.server_name === 'string' && outbound.tls.server_name) {
      params.set('sni', outbound.tls.server_name)
    }
    if (outbound.tls.insecure === true) params.set('insecure', '1')
  }
  if (outbound.obfs && typeof outbound.obfs === 'object') {
    if (typeof outbound.obfs.type === 'string' && outbound.obfs.type) params.set('obfs', outbound.obfs.type)
    if (typeof outbound.obfs.password === 'string' && outbound.obfs.password) params.set('obfs-password', outbound.obfs.password)
  }
  if (typeof outbound.server_ports === 'string' && outbound.server_ports) {
    params.set('mport', hysteria2ServerPortsToUri(outbound.server_ports))
  }
  if (typeof outbound.hop_interval === 'string' && outbound.hop_interval) params.set('hop_interval', outbound.hop_interval)
  if (Number.isFinite(Number(outbound.up_mbps)) && Number(outbound.up_mbps) > 0) {
    params.set('upmbps', String(Number(outbound.up_mbps)))
  }
  if (Number.isFinite(Number(outbound.down_mbps)) && Number(outbound.down_mbps) > 0) {
    params.set('downmbps', String(Number(outbound.down_mbps)))
  }
  const password = encodeURIComponent(String(outbound.password || ''))
  const authority = buildHostPort(String(outbound.server || ''), outbound.server_port)
  const query = params.toString()
  return `hysteria2://${password}@${authority}${query ? `?${query}` : ''}${nameToFragment(name)}`
}

function naiveToUri(name: string, outbound: Record<string, any>): string {
  const params = new URLSearchParams()
  appendTlsParams(params, outbound.tls, String(outbound.server || ''))
  const username = encodeURIComponent(String(outbound.username || ''))
  const password = encodeURIComponent(String(outbound.password || ''))
  const authority = buildHostPort(String(outbound.server || ''), outbound.server_port)
  return `naive://${username}:${password}@${authority}?${params.toString()}${nameToFragment(name)}`
}

function anyTlsToUri(name: string, outbound: Record<string, any>): string {
  const params = new URLSearchParams()
  appendTlsParams(params, outbound.tls, String(outbound.server || ''))
  const password = encodeURIComponent(String(outbound.password || ''))
  const authority = buildHostPort(String(outbound.server || ''), outbound.server_port)
  return `anytls://${password}@${authority}?${params.toString()}${nameToFragment(name)}`
}

function shadowTlsToUri(name: string, outbound: Record<string, any>): string {
  const params = new URLSearchParams()
  appendTlsParams(params, outbound.tls, String(outbound.server || ''))
  if (outbound.version) params.set('version', String(outbound.version))
  const password = encodeURIComponent(String(outbound.password || ''))
  const authority = buildHostPort(String(outbound.server || ''), outbound.server_port)
  return `shadowtls://${password}@${authority}?${params.toString()}${nameToFragment(name)}`
}

function tuicToUri(name: string, outbound: Record<string, any>): string {
  const params = new URLSearchParams()
  appendTlsParams(params, outbound.tls, String(outbound.server || ''))
  if (typeof outbound.congestion_control === 'string' && outbound.congestion_control) {
    params.set('congestion_control', outbound.congestion_control)
  }
  if (typeof outbound.udp_relay_mode === 'string' && outbound.udp_relay_mode) {
    params.set('udp_relay_mode', outbound.udp_relay_mode)
  }
  const uuid = encodeURIComponent(String(outbound.uuid || ''))
  const password = encodeURIComponent(String(outbound.password || ''))
  const authority = buildHostPort(String(outbound.server || ''), outbound.server_port)
  return `tuic://${uuid}:${password}@${authority}?${params.toString()}${nameToFragment(name)}`
}

/**
 * Renders a single sing-box outbound back to its scheme URI.
 *
 * Returns null when the outbound type is genuinely not exportable (e.g.
 * raw "sing-box outbound JSON" profiles imported as-is — those don't map
 * to any single-line scheme).
 */
export function exportOutboundToUri(profile: { name: string; protocol: string; outbound: Record<string, any> }): string | null {
  const out = profile.outbound
  if (!out || typeof out !== 'object') return null
  const type = String(out.type || profile.protocol || '').toLowerCase()
  switch (type) {
    case 'vless':       return vlessToUri(profile.name, out)
    case 'trojan':      return trojanToUri(profile.name, out)
    case 'shadowsocks': return shadowsocksToUri(profile.name, out)
    case 'vmess':       return vmessToUri(profile.name, out)
    case 'hysteria2':   return hysteria2ToUri(profile.name, out)
    case 'naive':       return naiveToUri(profile.name, out)
    case 'anytls':      return anyTlsToUri(profile.name, out)
    case 'shadowtls':   return shadowTlsToUri(profile.name, out)
    case 'tuic':        return tuicToUri(profile.name, out)
    default:            return null
  }
}
