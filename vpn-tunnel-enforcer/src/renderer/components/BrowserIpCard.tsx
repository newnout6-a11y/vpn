import { useState, useRef, useEffect } from 'react'
import { Loader2, RadioTower, RefreshCw, ShieldAlert } from 'lucide-react'
import { cn } from '../design-system/utils'
import '../styles/swiss.css'
import { useAppStore, type BrowserIpCheck } from '../store'
import { Address4, Address6 } from 'ip-address'
import { usePageActive } from '../hooks/usePageActive'

export interface WebRtcCandidate {
  type: string
  address: string
  protocol: string
}

const IPV4_URLS = [
  'https://api.ipify.org?format=json',
  'https://api.myip.com'
]
export const BROWSER_CHECK_DEADLINE_MS = 5000

export function unwrapIpv4Mapped(ip: string): string {
  const trimmed = ip.trim().toLowerCase()
  try {
    if (Address4.isValid(trimmed)) return new Address4(trimmed).correctForm()
    if (Address6.isValid(trimmed)) {
      const address = new Address6(trimmed)
      const groups = address.canonicalForm().split(':')
      if (groups.slice(0, 5).every(g => g === '0000') && groups[5] === 'ffff') {
        return address.to4().correctForm()
      }
      return address.correctForm()
    }
  } catch {}
  return trimmed
}

export function isPrivateIp(rawIp: string): boolean {
  const ip = unwrapIpv4Mapped(rawIp)
  if (!Address4.isValid(ip) && !Address6.isValid(ip)) return false
  return (
    ip.startsWith('10.') ||
    ip.startsWith('127.') ||
    ip.startsWith('169.254.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    ip === '::1' ||
    ip === '::' ||
    /^fe[89ab][0-9a-f]:/i.test(ip) ||
    /^fc|^fd/i.test(ip)
  )
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean).map(unwrapIpv4Mapped))]
}

function worse(a: BrowserIpCheck['summary'], b: BrowserIpCheck['summary']): BrowserIpCheck['summary'] {
  const weight = { ok: 0, info: 1, warn: 2, fail: 3 }
  return weight[b] > weight[a] ? b : a
}

async function fetchWithTimeout(url: string, timeoutMs = 8000, signal?: AbortSignal): Promise<any | null> {
  const controller = new AbortController()
  const abort = () => controller.abort()
  signal?.addEventListener('abort', abort, { once: true })
  if (signal?.aborted) controller.abort()
  const timeout = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const response = await fetch(url, {
      cache: 'no-store',
      signal: controller.signal
    })
    if (!response.ok) return null
    return await response.json()
  } finally {
    signal?.removeEventListener('abort', abort)
    clearTimeout(timeout)
  }
}

export async function fetchBrowserIpv4(signal?: AbortSignal): Promise<string | null> {
  const controller = new AbortController()
  const abort = () => controller.abort()
  signal?.addEventListener('abort', abort, { once: true })
  if (signal?.aborted) controller.abort()
  const reads = IPV4_URLS.map(async url => {
    const data = await fetchWithTimeout(url, BROWSER_CHECK_DEADLINE_MS, controller.signal)
    const ip = data?.ip || data?.query
    if (typeof ip !== 'string' || !Address4.isValid(ip)) throw new Error('Browser IPv4 unavailable')
    return ip
  })
  try {
    return await Promise.any(reads).catch(() => null)
  } finally {
    controller.abort()
    await Promise.allSettled(reads)
    signal?.removeEventListener('abort', abort)
  }
}

async function fetchBrowserIpv6(signal?: AbortSignal): Promise<string | null> {
  try {
    const data = await fetchWithTimeout('https://api6.ipify.org?format=json', BROWSER_CHECK_DEADLINE_MS, signal)
    const ip = data?.ip
    return typeof ip === 'string' && Address6.isValid(ip) ? new Address6(ip).correctForm() : null
  } catch {
    return null
  }
}

function readNodeIp(signal: AbortSignal): Promise<string | null> {
  return new Promise(resolve => {
    const finish = (ip: string | null) => {
      signal.removeEventListener('abort', abort)
      resolve(ip)
    }
    const abort = () => finish(null)
    if (signal.aborted) { resolve(null); return }
    signal.addEventListener('abort', abort, { once: true })
    // Observe the bounded main read without substituting a cached IP on failure.
    window.electronAPI.getPublicIp().then(result => finish(result.ip), () => finish(null))
  })
}

function parseCandidate(raw: string): WebRtcCandidate | null {
  const parts = raw.trim().split(/\s+/)
  const typIndex = parts.indexOf('typ')
  const address = parts[4]
  if (!address) return null
  return {
    type: typIndex >= 0 ? parts[typIndex + 1] || 'unknown' : 'unknown',
    address,
    protocol: parts[2] || 'unknown'
  }
}

function collectWebRtcCandidates(timeoutMs = 4500, signal?: AbortSignal): Promise<{ candidates: WebRtcCandidate[]; error: string | null }> {
  return new Promise((resolve) => {
    if (signal?.aborted) { resolve({ candidates: [], error: 'Cancelled' }); return }
    if (typeof RTCPeerConnection === 'undefined') {
      resolve({ candidates: [], error: 'WebRTC недоступен в этом окружении' })
      return
    }

    const candidates: WebRtcCandidate[] = []
    const pc = new RTCPeerConnection({
      iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
    })
    let done = false
    const finish = (error: string | null = null) => {
      if (done) return
      done = true
      clearTimeout(timer)
      signal?.removeEventListener('abort', abort)
      try {
        pc.close()
      } catch {
      }
      resolve({ candidates, error })
    }

    const abort = () => finish('Cancelled')
    const timer = setTimeout(() => finish('Истекло время ожидания WebRTC'), timeoutMs)
    signal?.addEventListener('abort', abort, { once: true })
    pc.onicecandidate = (event) => {
      if (!event.candidate) {
        clearTimeout(timer)
        finish(null)
        return
      }
      const parsed = parseCandidate(event.candidate.candidate)
      if (parsed) candidates.push(parsed)
    }

    try {
      pc.createDataChannel('vpnte-check')
      pc.createOffer()
        .then(offer => pc.setLocalDescription(offer))
        .catch(err => {
          clearTimeout(timer)
          finish(err?.message || String(err))
        })
    } catch (err: any) {
      clearTimeout(timer)
      finish(err?.message || String(err))
    }
  })
}

export function summarize(args: {
  browserIpv4: string | null
  browserIpv6: string | null
  nodeIp: string | null
  webRtcCandidates: WebRtcCandidate[]
  webRtcError: string | null
  tunRunning: boolean
}): BrowserIpCheck {
  const details: string[] = []
  let summary: BrowserIpCheck['summary'] = 'ok'
  const browserMatchesNode = args.browserIpv4 && args.nodeIp ? unwrapIpv4Mapped(args.browserIpv4) === unwrapIpv4Mapped(args.nodeIp) : null

  if (!args.browserIpv4) {
    summary = worse(summary, 'info')
    details.push('Публичный IPv4 браузера не проверен: сервисы недоступны или истекло время ожидания.')
  } else if (!args.nodeIp) {
    summary = worse(summary, 'info')
    details.push('IPv4 main-процесса не проверен; сравнение с браузером недоступно.')
  } else if (browserMatchesNode === false) {
    summary = worse(summary, args.tunRunning ? 'fail' : 'warn')
    details.push(`Браузер видит ${args.browserIpv4}, а main-процесс видит ${args.nodeIp}. Это может означать обход системного маршрута браузером.`)
  } else {
    details.push('Browser fetch и main-процесс видят один и тот же IPv4.')
  }

  if (args.browserIpv6) {
    summary = worse(summary, 'warn')
    details.push(`Браузер получил публичный IPv6: ${args.browserIpv6}. Если это провайдерский IPv6, сайты могут видеть не VPN.`)
  } else {
    summary = worse(summary, 'info')
    details.push('Публичный IPv6 браузера не проверен: отсутствие ответа не подтверждает отсутствие IPv6-утечки.')
  }

  const webRtcAddresses = args.webRtcCandidates.map(c => c.address)
  const webRtcMdnsCount = webRtcAddresses.filter(x => /\.local$/i.test(x)).length
  const webRtcLocalIps = unique(webRtcAddresses.filter(x => !/\.local$/i.test(x) && isPrivateIp(x)))
  const webRtcPublicIps = unique(webRtcAddresses.filter(x => !/\.local$/i.test(x) && !isPrivateIp(x) && (Address4.isValid(x) || Address6.isValid(x))))
  const expectedPublicIps = unique([args.browserIpv4, args.browserIpv6, args.nodeIp].filter((ip): ip is string => Boolean(ip)))
  const unexpectedWebRtcPublicIps = webRtcPublicIps.filter(ip => !expectedPublicIps.includes(ip))

  if (args.webRtcError) {
    summary = worse(summary, 'info')
    details.push(`WebRTC проверка не завершилась: ${args.webRtcError}`)
  }
  if (unexpectedWebRtcPublicIps.length > 0) {
    summary = worse(summary, 'warn')
    details.push(`WebRTC показал другие публичные адреса: ${unexpectedWebRtcPublicIps.join(', ')}.`)
  } else if (webRtcPublicIps.length > 0) {
    details.push(`WebRTC показал только текущий публичный VPN IP: ${webRtcPublicIps.join(', ')}.`)
  }
  if (webRtcLocalIps.length > 0) {
    summary = worse(summary, 'warn')
    details.push(`WebRTC показал локальные адреса: ${webRtcLocalIps.join(', ')}.`)
  } else if (webRtcMdnsCount > 0) {
    details.push('WebRTC скрывает локальные адреса через mDNS — это нормально.')
  } else if (webRtcPublicIps.length === 0 && !args.webRtcError) {
    details.push('WebRTC не выдал IP-кандидатов или заблокирован браузером.')
  }

  return {
    ranAt: Date.now(),
    summary,
    browserIpv4: args.browserIpv4,
    browserIpv6: args.browserIpv6,
    nodeIp: args.nodeIp,
    browserMatchesNode,
    webRtcPublicIps,
    webRtcLocalIps,
    webRtcMdnsCount,
    webRtcError: args.webRtcError,
    details
  }
}

export function BrowserIpCard() {
  const active = usePageActive()
  const check = useAppStore(s => s.browserIpCheck)
  const setCheck = useAppStore(s => s.setBrowserIpCheck)
  const tunRunning = useAppStore(s => s.tunRunning)
  const publicIp = useAppStore(s => s.publicIp)
  const networkContext = useAppStore(s => `${s.mode}:${s.tunStartedAt}:${s.connectionBusy}:${s.serverSwitchingName}:${s.vpnIp}`)
  const addLog = useAppStore(s => s.addLog)
  const [running, setRunning] = useState(false)
  const [hardening, setHardening] = useState(false)
  const [rollingBack, setRollingBack] = useState(false)
  const [hardeningMessage, setHardeningMessage] = useState<string | null>(null)
  const checkIdRef = useRef(0)
  const abortRef = useRef<AbortController | null>(null)
  useEffect(() => {
    setRunning(false)
    return () => {
      ++checkIdRef.current
      abortRef.current?.abort()
    }
  }, [tunRunning, publicIp, networkContext, active])

  const runCheck = async (silent = false) => {
    if (!active) return
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    const currentCheckId = ++checkIdRef.current
    const deadline = setTimeout(() => controller.abort(), BROWSER_CHECK_DEADLINE_MS)
    setRunning(true)
    if (!silent) addLog('info', 'Проверяем, какой IP видят сайты в браузере…')
    try {
      const [nodeIp, browserIpv4, browserIpv6, webRtc] = await Promise.all([
        readNodeIp(controller.signal),
        fetchBrowserIpv4(controller.signal),
        fetchBrowserIpv6(controller.signal),
        collectWebRtcCandidates(4500, controller.signal)
      ])
      if (checkIdRef.current !== currentCheckId) {
        return
      }
      const result = summarize({
        browserIpv4,
        browserIpv6,
        nodeIp,
        webRtcCandidates: webRtc.candidates,
        webRtcError: webRtc.error,
        tunRunning
      })
      setCheck(result)
      if (!silent) {
        const message =
          result.summary === 'ok'
            ? `Сайты видят VPN IP: ${result.browserIpv4 ?? 'неизвестно'}`
            : result.summary === 'fail'
              ? 'Браузер видит другой IP или IP не проверился.'
              : result.summary === 'info' ? 'Проверка браузера завершилась не полностью; отсутствие утечки не подтверждено.'
              : 'Есть предупреждения по браузеру/WebRTC/IPv6.'
        addLog(result.summary === 'fail' ? 'error' : result.summary === 'warn' ? 'warn' : 'info', `Проверка браузера: ${message}`)
      }
    } catch (err: any) {
      if (checkIdRef.current !== currentCheckId) {
        return
      }
      const failed: BrowserIpCheck = {
        ranAt: Date.now(),
        summary: 'fail',
        browserIpv4: null,
        browserIpv6: null,
        nodeIp: null,
        browserMatchesNode: null,
        webRtcPublicIps: [],
        webRtcLocalIps: [],
        webRtcMdnsCount: 0,
        webRtcError: err?.message || String(err),
        details: [`Проверка браузера упала: ${err?.message || String(err)}`]
      }
      setCheck(failed)
      if (!silent) addLog('error', failed.details[0])
    } finally {
      clearTimeout(deadline)
      controller.abort()
      if (checkIdRef.current === currentCheckId) {
        setRunning(false)
      }
    }
  }

  const rollbackHardening = async () => {
    setRollingBack(true)
    setHardeningMessage(null)
    addLog('warn', 'Откатываем защиту браузеров от WebRTC/IP leak из backup.')
    try {
      const result = await window.electronAPI.rollbackBrowserLeakProtection()
      setHardeningMessage(result.message || 'Настройки откатаны. Перезапустите браузеры.')
      addLog(result.success ? 'info' : 'error', result.message || 'Настройки защиты браузеров откатаны.')
    } catch (err: any) {
      const message = `Не удалось откатить защиту браузеров: ${err?.message || err}`
      setHardeningMessage(message)
      addLog('error', message)
    } finally {
      setRollingBack(false)
    }
  }

  const applyHardening = async () => {
    setHardening(true)
    setHardeningMessage(null)
    addLog('warn', 'Применяем защиту браузеров от WebRTC/IP leak. После этого нужно полностью перезапустить браузеры.')
    try {
      const result = await window.electronAPI.applyBrowserLeakProtection()
      setHardeningMessage(result.message || 'Настройки применены. Перезапустите браузеры.')
      addLog(result.success ? 'info' : 'error', result.message || 'Настройки защиты браузеров применены.')
    } catch (err: any) {
      const message = `Не удалось применить защиту браузеров: ${err?.message || err}`
      setHardeningMessage(message)
      addLog('error', message)
    } finally {
      setHardening(false)
    }
  }

  const status = check?.summary ?? 'unknown'
  const browserProtectionAttention = status === 'warn' || status === 'fail'
  const webRtcUnexpectedPublicIps = check?.webRtcPublicIps.filter(ip =>
    ![check.browserIpv4, check.browserIpv6, check.nodeIp].filter(Boolean).map(x => unwrapIpv4Mapped(x!)).includes(unwrapIpv4Mapped(ip))
  ) ?? []
  const webRtcHasLocalLeak = Boolean(check?.webRtcLocalIps.length)
  const title =
    status === 'ok'
      ? 'Сайты видят тот же IP'
      : status === 'fail'
        ? 'Браузерный IP под вопросом'
        : status === 'warn'
          ? 'Есть browser-предупреждения'
          : status === 'info'
            ? 'Проверка браузера не завершена'
            : 'Браузер ещё не проверялся'

  return (
    // «Пломба» panel: same check and hardening actions as before, Swiss layout
    <section className="swiss-panel">
      <header className="swiss-panel-head" data-perch="browser" data-perch-y="bottom" data-perch-scale="0.32" data-perch-fit="gap">
        <span className="swiss-label swiss-label-ink">Что видят сайты</span>
        <button type="button" className="swiss-fact-action" onClick={() => runCheck(false)} disabled={running}>
          {running && <Loader2 className="mr-1 inline h-3 w-3 animate-spin" />}
          Проверить браузер
        </button>
      </header>

      <div className="swiss-panel-pad">
        <p className={cn('swiss-browser-title', 'is-' + status)}>{title}</p>
        <div className="swiss-metrics">
          <Metric label="Browser IPv4" value={check?.browserIpv4 ?? '—'} status={check?.browserMatchesNode === true ? 'ok' : check?.browserMatchesNode === false ? tunRunning ? 'fail' : 'warn' : 'info'} />
          <Metric label="Main/Node IPv4" value={check?.nodeIp ?? '—'} status="info" />
          <Metric label="Browser IPv6" value={check?.browserIpv6 ?? (check ? 'IPv6 не проверен' : '—')} status={check?.browserIpv6 ? 'warn' : 'info'} />
          <Metric
            label="WebRTC"
            value={
              check
                ? check.webRtcPublicIps.length > 0
                  ? check.webRtcPublicIps.join(', ')
                  : check.webRtcLocalIps.length > 0
                    ? check.webRtcLocalIps.join(', ')
                    : check.webRtcMdnsCount > 0
                      ? 'mDNS скрытие активно'
                      : check.webRtcError || 'IP не выдан'
                : '—'
            }
            status={webRtcUnexpectedPublicIps.length || webRtcHasLocalLeak ? 'warn' : !check || check.webRtcError ? 'info' : 'ok'}
            icon={<RadioTower className="h-3 w-3" />}
          />
        </div>
        {check && (
          <div className="swiss-browser-details">
            {check.details.map((detail, index) => (
              <p key={index} className={cn('swiss-browser-detail', index === 0 && 'is-' + check.summary)}>
                {detail}
              </p>
            ))}
            <p className="swiss-mono swiss-browser-time">Проверено: {new Date(check.ranAt).toLocaleTimeString('ru-RU')}</p>
          </div>
        )}
      </div>

      <div className={cn('swiss-browser-guard', browserProtectionAttention && 'is-attention')}>
        <p className="swiss-browser-guard-title">
          {browserProtectionAttention ? 'Если внешний Яндекс/Chrome всё ещё показывает реальный IP — это WebRTC leak самого браузера.' : 'Защита внешних браузеров от WebRTC leak'}
        </p>
        <p className="swiss-browser-guard-body">Нажмите защиту, закройте все окна браузера и откройте его заново. Backup сохраняется для отката.</p>
        <div className="swiss-browser-guard-actions">
          <button type="button" className="swiss-btn" onClick={applyHardening} disabled={hardening || rollingBack}>
            {hardening ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldAlert className="h-4 w-4" />}
            Защитить браузеры от WebRTC
          </button>
          <button type="button" className="swiss-btn is-ghost" onClick={rollbackHardening} disabled={hardening || rollingBack}>
            {rollingBack ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            Откатить
          </button>
        </div>
        {hardeningMessage && <p className="swiss-browser-guard-body">{hardeningMessage}</p>}
      </div>
    </section>
  )
}
function Metric({ label, value, status, icon }: { label: string; value: string; status: BrowserIpCheck['summary']; icon?: JSX.Element }) {
  return (
    <div className="swiss-metric">
      <span className="swiss-label swiss-metric-label">
        {icon}
        {label}
      </span>
      <span className={cn('swiss-mono swiss-metric-value', 'is-' + status)}>{value}</span>
    </div>
  )
}
