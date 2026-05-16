import { useState } from 'react'
import { CheckCircle2, Eye, Globe2, Loader2, RadioTower, RefreshCw, ShieldAlert, TriangleAlert } from 'lucide-react'
import { useAppStore, type BrowserIpCheck } from '../store'

interface WebRtcCandidate {
  type: string
  address: string
  protocol: string
}

const IPV4_URLS = [
  'https://api.ipify.org?format=json',
  'https://api.myip.com',
  'https://ipinfo.io/json'
]

function isPrivateIp(ip: string): boolean {
  return (
    ip.startsWith('10.') ||
    ip.startsWith('127.') ||
    ip.startsWith('169.254.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    ip === '::1' ||
    /^fe80:/i.test(ip) ||
    /^fc|^fd/i.test(ip)
  )
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))]
}

function worse(a: BrowserIpCheck['summary'], b: BrowserIpCheck['summary']): BrowserIpCheck['summary'] {
  const weight = { ok: 0, info: 1, warn: 2, fail: 3 }
  return weight[b] > weight[a] ? b : a
}

async function fetchWithTimeout(url: string, timeoutMs = 8000): Promise<any | null> {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const response = await fetch(url, {
      cache: 'no-store',
      signal: controller.signal
    })
    if (!response.ok) return null
    return await response.json()
  } finally {
    clearTimeout(timeout)
  }
}

async function fetchBrowserIpv4(): Promise<string | null> {
  for (const url of IPV4_URLS) {
    try {
      const data = await fetchWithTimeout(url)
      const ip = data?.ip || data?.query
      if (typeof ip === 'string' && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip
    } catch {
    }
  }
  return null
}

async function fetchBrowserIpv6(): Promise<string | null> {
  try {
    const data = await fetchWithTimeout('https://api6.ipify.org?format=json', 6000)
    const ip = data?.ip
    return typeof ip === 'string' && ip.includes(':') ? ip : null
  } catch {
    return null
  }
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

function collectWebRtcCandidates(timeoutMs = 4500): Promise<{ candidates: WebRtcCandidate[]; error: string | null }> {
  return new Promise((resolve) => {
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
      try {
        pc.close()
      } catch {
      }
      resolve({ candidates, error })
    }

    const timer = setTimeout(() => finish(null), timeoutMs)
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

function summarize(args: {
  browserIpv4: string | null
  browserIpv6: string | null
  nodeIp: string | null
  webRtcCandidates: WebRtcCandidate[]
  webRtcError: string | null
  tunRunning: boolean
}): BrowserIpCheck {
  const details: string[] = []
  let summary: BrowserIpCheck['summary'] = 'ok'
  const browserMatchesNode = args.browserIpv4 && args.nodeIp ? args.browserIpv4 === args.nodeIp : null

  if (!args.browserIpv4) {
    summary = worse(summary, 'fail')
    details.push('Браузерный fetch не смог получить публичный IPv4.')
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
    details.push('Отдельный публичный IPv6 из браузера не получен.')
  }

  const webRtcAddresses = args.webRtcCandidates.map(c => c.address)
  const webRtcMdnsCount = webRtcAddresses.filter(x => /\.local$/i.test(x)).length
  const webRtcLocalIps = unique(webRtcAddresses.filter(x => !/\.local$/i.test(x) && isPrivateIp(x)))
  const webRtcPublicIps = unique(webRtcAddresses.filter(x => !/\.local$/i.test(x) && !isPrivateIp(x) && /[.:]/.test(x)))
  const expectedPublicIps = unique([args.browserIpv4, args.browserIpv6, args.nodeIp].filter((ip): ip is string => Boolean(ip)))
  const unexpectedWebRtcPublicIps = webRtcPublicIps.filter(ip => !expectedPublicIps.includes(ip))

  if (args.webRtcError) {
    summary = worse(summary, 'info')
    details.push(`WebRTC проверка не завершилась: ${args.webRtcError}`)
  } else if (unexpectedWebRtcPublicIps.length > 0) {
    summary = worse(summary, 'warn')
    details.push(`WebRTC показал другие публичные адреса: ${unexpectedWebRtcPublicIps.join(', ')}.`)
  } else if (webRtcPublicIps.length > 0) {
    details.push(`WebRTC показал только текущий публичный VPN IP: ${webRtcPublicIps.join(', ')}.`)
  } else if (webRtcLocalIps.length > 0) {
    summary = worse(summary, 'warn')
    details.push(`WebRTC показал локальные адреса: ${webRtcLocalIps.join(', ')}.`)
  } else if (webRtcMdnsCount > 0) {
    details.push('WebRTC скрывает локальные адреса через mDNS — это нормально.')
  } else {
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

function statusClass(status: BrowserIpCheck['summary'] | 'unknown'): string {
  if (status === 'ok') return 'text-success'
  if (status === 'warn') return 'text-warning'
  if (status === 'fail') return 'text-danger'
  return 'text-gray-400'
}

function statusIcon(status: BrowserIpCheck['summary'] | 'unknown') {
  if (status === 'ok') return <CheckCircle2 className="w-4 h-4 text-success" />
  if (status === 'fail') return <ShieldAlert className="w-4 h-4 text-danger" />
  if (status === 'warn') return <TriangleAlert className="w-4 h-4 text-warning" />
  return <Eye className="w-4 h-4 text-gray-400" />
}

export function BrowserIpCard() {
  const check = useAppStore(s => s.browserIpCheck)
  const setCheck = useAppStore(s => s.setBrowserIpCheck)
  const tunRunning = useAppStore(s => s.tunRunning)
  const publicIp = useAppStore(s => s.publicIp)
  const addLog = useAppStore(s => s.addLog)
  const [running, setRunning] = useState(false)
  const [hardening, setHardening] = useState(false)
  const [rollingBack, setRollingBack] = useState(false)
  const [hardeningMessage, setHardeningMessage] = useState<string | null>(null)

  const runCheck = async (silent = false) => {
    setRunning(true)
    if (!silent) addLog('info', 'Проверяем, какой IP видят сайты в браузере…')
    try {
      const [nodeIpInfo, browserIpv4, browserIpv6, webRtc] = await Promise.all([
        window.electronAPI.getPublicIp().catch(() => ({ ip: publicIp, isLeak: false, vpnIp: null })),
        fetchBrowserIpv4(),
        fetchBrowserIpv6(),
        collectWebRtcCandidates()
      ])
      const result = summarize({
        browserIpv4,
        browserIpv6,
        nodeIp: nodeIpInfo.ip ?? publicIp,
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
              : 'Есть предупреждения по браузеру/WebRTC/IPv6.'
        addLog(result.summary === 'fail' ? 'error' : result.summary === 'warn' ? 'warn' : 'info', `Проверка браузера: ${message}`)
      }
    } catch (err: any) {
      const failed: BrowserIpCheck = {
        ranAt: Date.now(),
        summary: 'fail',
        browserIpv4: null,
        browserIpv6: null,
        nodeIp: publicIp,
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
      setRunning(false)
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
    ip !== check.browserIpv4 && ip !== check.browserIpv6 && ip !== check.nodeIp
  ) ?? []
  const webRtcHasLocalLeak = Boolean(check?.webRtcLocalIps.length)
  const title =
    status === 'ok'
      ? 'Сайты видят тот же IP'
      : status === 'fail'
        ? 'Браузерный IP под вопросом'
        : status === 'warn'
          ? 'Есть browser-предупреждения'
          : 'Браузер ещё не проверялся'

  return (
    <div className="card space-y-4">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-gray-300 uppercase tracking-wider flex items-center gap-2">
            <Globe2 className="w-4 h-4 text-accent" />
            Что видят сайты
          </h3>
          <p className={`text-sm mt-1 ${statusClass(status)}`}>{title}</p>
        </div>
        <button onClick={() => runCheck(false)} disabled={running} className="btn-secondary flex items-center gap-2 text-sm disabled:opacity-50">
          {running ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
          Проверить браузер
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        <Metric label="Browser IPv4" value={check?.browserIpv4 ?? '—'} status={check?.browserIpv4 ? check.browserMatchesNode === false ? 'fail' : 'ok' : 'info'} />
        <Metric label="Main/Node IPv4" value={check?.nodeIp ?? publicIp ?? '—'} status="info" />
        <Metric label="Browser IPv6" value={check?.browserIpv6 ?? 'IPv6 не доступен'} status={check?.browserIpv6 ? 'warn' : 'ok'} />
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
          status={webRtcUnexpectedPublicIps.length || webRtcHasLocalLeak ? 'warn' : check?.webRtcError ? 'info' : 'ok'}
          icon={<RadioTower className="w-3.5 h-3.5" />}
        />
      </div>

      {check && (
        <div className="space-y-1.5">
          {check.details.map((detail, index) => (
            <div key={index} className="flex items-start gap-2 text-xs text-gray-500">
              {statusIcon(index === 0 ? check.summary : 'info')}
              <span className="break-words">{detail}</span>
            </div>
          ))}
          <p className="text-[10px] text-gray-600 pt-1">Проверено: {new Date(check.ranAt).toLocaleTimeString('ru-RU')}</p>
        </div>
      )}

      <div className={`${browserProtectionAttention ? 'bg-warning/10 border-warning/30' : 'bg-surface/60 border-surface-lighter/40'} border rounded-lg p-3 space-y-2`}>
        <div className="flex items-start gap-2">
          <ShieldAlert className={`w-4 h-4 ${browserProtectionAttention ? 'text-warning' : 'text-accent'} flex-shrink-0 mt-0.5`} />
          <div className={`text-xs ${browserProtectionAttention ? 'text-warning/90' : 'text-gray-400'}`}>
            <p className="font-semibold">{browserProtectionAttention ? 'Если внешний Яндекс/Chrome всё ещё показывает реальный IP — это WebRTC leak самого браузера.' : 'Защита внешних браузеров от WebRTC leak'}</p>
            <p className={`${browserProtectionAttention ? 'text-warning/75' : 'text-gray-500'} mt-1`}>Нажмите защиту, закройте все окна браузера и откройте его заново. Backup сохраняется для отката.</p>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <button onClick={applyHardening} disabled={hardening || rollingBack} className="btn-secondary flex items-center gap-2 text-sm disabled:opacity-50">
            {hardening ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldAlert className="w-4 h-4" />}
            Защитить браузеры от WebRTC
          </button>
          <button onClick={rollbackHardening} disabled={hardening || rollingBack} className="btn-secondary flex items-center gap-2 text-sm disabled:opacity-50">
            {rollingBack ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
            Откатить
          </button>
        </div>
        {hardeningMessage && <p className="text-xs text-gray-400">{hardeningMessage}</p>}
      </div>
    </div>
  )
}

function Metric({ label, value, status, icon }: { label: string; value: string; status: BrowserIpCheck['summary']; icon?: JSX.Element }) {
  return (
    <div className="bg-surface/60 border border-surface-lighter/40 rounded-lg px-3 py-2">
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs text-gray-500 flex items-center gap-1.5">
          {icon}
          {label}
        </span>
        <span className={`text-xs font-mono text-right break-all ${statusClass(status)}`}>{value}</span>
      </div>
    </div>
  )
}
