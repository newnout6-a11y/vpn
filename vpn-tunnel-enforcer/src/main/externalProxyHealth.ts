import axios, { type AxiosRequestConfig } from 'axios'

export const EXTERNAL_PROXY_IP_CHECK_URL = 'https://api.ipify.org?format=json'
export const EXTERNAL_PROXY_IP_CHECK_FALLBACK_URL = 'https://api.myip.com'
export const EXTERNAL_PROXY_HTTPS_CHECK_URL = 'https://www.cloudflare.com/cdn-cgi/trace'

export interface ExternalProxyProbeResult {
  egressIp: string
  latencyMs: number
}

export interface ExternalProxyProbeOptions {
  timeoutMs?: number
  ipCheckUrl?: string
  httpsCheckUrl?: string
}

const DEFAULT_PROBE_TIMEOUT_MS = 10_000

function proxyConfig(proxyUrl: string): { protocol: 'http'; host: string; port: number } {
  const proxy = new URL(proxyUrl)
  const port = Number(proxy.port || 80)
  if (proxy.protocol !== 'http:' || !proxy.hostname || !Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`Invalid external proxy URL: ${proxyUrl}`)
  }
  return { protocol: 'http', host: proxy.hostname, port }
}

function acceptedStatus(status: number): boolean {
  return status >= 200 && status < 400
}

function egressIpFrom(data: unknown): string {
  let value = data
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value)
    } catch {
      return ''
    }
  }
  return value && typeof value === 'object' && typeof (value as { ip?: unknown }).ip === 'string'
    ? (value as { ip: string }).ip.trim()
    : ''
}

async function requestEgressIp(
  urls: string[],
  requestConfig: AxiosRequestConfig
): Promise<string> {
  let lastError: unknown = null
  for (const url of urls) {
    try {
      const response = await axios.get(url, requestConfig)
      const egressIp = egressIpFrom(response.data)
      if (egressIp) return egressIp
      lastError = new Error(`External IP check returned no IP address: ${url}`)
    } catch (error) {
      lastError = error
    }
  }
  throw lastError ?? new Error('External IP check returned no IP address')
}

export async function probeExternalProxy(
  proxyUrl: string,
  options: ExternalProxyProbeOptions = {}
): Promise<ExternalProxyProbeResult> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS
  const proxy = proxyConfig(proxyUrl)
  const requestConfig = {
    proxy,
    timeout: timeoutMs,
    maxRedirects: 0,
    responseType: 'text' as const,
    validateStatus: acceptedStatus
  }
  const startedAt = Date.now()
  const [egressIp] = await Promise.all([
    requestEgressIp(
      options.ipCheckUrl
        ? [options.ipCheckUrl]
        : [EXTERNAL_PROXY_IP_CHECK_URL, EXTERNAL_PROXY_IP_CHECK_FALLBACK_URL],
      requestConfig
    ),
    axios.get(options.httpsCheckUrl ?? EXTERNAL_PROXY_HTTPS_CHECK_URL, requestConfig)
  ])

  return { egressIp, latencyMs: Date.now() - startedAt }
}

export function externalProxyHealthErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const code = error.code ? `${error.code}: ` : ''
    return `${code}${error.message}`
  }
  return error instanceof Error ? error.message : String(error)
}

export function isRecoverableExternalProxyTransportError(error: unknown): boolean {
  const message = externalProxyHealthErrorMessage(error)
  return /(timeout|timed out|eof|socket hang up|econnreset|econnrefused|ehostunreach|enetunreach)/i.test(message)
}
