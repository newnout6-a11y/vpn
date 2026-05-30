import { useState, useEffect, useCallback } from 'react'
import {
  Search,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Loader2,
  Trash2,
  Globe,
  Lock,
  Wifi,
  Server as ServerIcon,
  Network,
  ShieldCheck,
  ShieldOff,
  Info
} from 'lucide-react'
import { MacCard, MacInput, MacButton } from '../design-system'
import { useAppStore } from '../store'

/**
 * URL Availability page.
 *
 * The user pastes any link and gets a side-by-side comparison:
 *
 *   ┌─────────────────────────┬─────────────────────────┐
 *   │ Через VPN               │ Без VPN                 │
 *   │ ✅ Открывается           │ ❌ Заблокирован         │
 *   │ TLS · 145 ms · DE       │ TCP timeout             │
 *   │ (детальная разбивка)    │ (latency-only)          │
 *   └─────────────────────────┴─────────────────────────┘
 *
 * Verdict + recommendation card below. History sidebar on the right.
 *
 * When VPN is OFF only the direct path is measured — the second card
 * shows a hint "Включите защиту, чтобы сравнить".
 */

// ─── Types mirror src/main/urlAvailability.ts (loose to avoid coupling) ──────

interface PathReport {
  available: boolean
  totalMs: number | null
  errorStage: string | null
  errorMessage: string | null
  dns: { resolved: boolean; ips: string[]; ms: number | null; poisoned: boolean } | null
  tcp: { connected: boolean; ms: number | null } | null
  tls: { handshakeOk: boolean; ms: number | null; cipher: string | null; protocol: string | null } | null
  http: { status: number | null; ms: number | null; server: string | null } | null
  asn: { country: string; org: string } | null
  geoBlocked?: boolean
  source: 'native' | 'clash-direct-out'
}

interface UrlResult {
  id: string
  url: string
  testedAt: number
  tunnelActive: boolean
  tunnel: PathReport | null
  direct: PathReport | null
  verdict: 'works-both' | 'works-only-with-vpn' | 'works-only-without-vpn' | 'blocked-everywhere' | 'unknown'
  recommendation: string
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatAge(ms: number): string {
  const sec = Math.floor((Date.now() - ms) / 1000)
  if (sec < 60) return `${sec} с назад`
  const min = Math.floor(sec / 60)
  if (min < 60) return `${min} мин назад`
  const hr = Math.floor(min / 60)
  if (hr < 24) return `${hr} ч назад`
  const days = Math.floor(hr / 24)
  return `${days} д назад`
}

function verdictTone(v: UrlResult['verdict']) {
  switch (v) {
    case 'works-both':
      return { color: 'text-[var(--color-success)]', icon: CheckCircle2, label: 'Доступен и так и так' }
    case 'works-only-with-vpn':
      return { color: 'text-[var(--color-accent)]', icon: ShieldCheck, label: 'Нужен VPN' }
    case 'works-only-without-vpn':
      return { color: 'text-[var(--color-warning)]', icon: ShieldOff, label: 'Только без VPN' }
    case 'blocked-everywhere':
      return { color: 'text-[var(--color-danger)]', icon: XCircle, label: 'Не отвечает' }
    default:
      return { color: 'text-[var(--color-text-secondary)]', icon: AlertTriangle, label: 'Неопределённо' }
  }
}

// ─── Path detail card ────────────────────────────────────────────────────────

function PathDetailCard({ title, report, missingMessage }: {
  title: string
  report: PathReport | null
  missingMessage?: string
}) {
  if (!report) {
    return (
      <MacCard className="!p-4 h-full">
        <h4 className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider mb-3">
          {title}
        </h4>
        <p className="text-sm text-[var(--color-text-muted)]">
          {missingMessage ?? 'Нет данных.'}
        </p>
      </MacCard>
    )
  }
  const ok = report.available
  const Icon = ok ? CheckCircle2 : XCircle
  const color = ok ? 'text-[var(--color-success)]' : 'text-[var(--color-danger)]'

  return (
    <MacCard className="!p-4 h-full flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <h4 className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider">
          {title}
        </h4>
        <span className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider">
          {report.source === 'clash-direct-out' ? 'оценка' : 'полный замер'}
        </span>
      </div>
      <div className="flex items-center gap-2">
        <Icon className={`w-5 h-5 ${color}`} />
        <span className={`text-base font-semibold ${color}`}>
          {ok ? 'Открывается' : (report.geoBlocked ? 'Гео-блок' : 'Не открывается')}
        </span>
        {report.totalMs != null && (
          <span className="ml-auto text-xs text-[var(--color-text-secondary)] tabular-nums">
            {report.totalMs} ms
          </span>
        )}
      </div>
      {report.geoBlocked && (
        <p className="text-xs text-[var(--color-warning)] bg-[var(--color-warning)]/10 rounded-[var(--radius-sm)] p-2">
          Сеть пропускает, но сам сайт закрыт для этого региона.
        </p>
      )}
      {report.errorMessage && (
        <p className="text-xs text-[var(--color-danger)] bg-[var(--color-danger)]/10 rounded-[var(--radius-sm)] p-2">
          {report.errorMessage}
        </p>
      )}
      <div className="space-y-1.5 mt-1">
        {report.dns && (
          <DetailRow
            icon={<Globe size={12} />}
            label="DNS"
            value={
              report.dns.resolved
                ? (report.dns.poisoned
                  ? <span className="text-[var(--color-warning)]">подозрительно: {report.dns.ips[0]}</span>
                  : `${report.dns.ips[0]}${report.dns.ips.length > 1 ? ` (+${report.dns.ips.length - 1})` : ''}`)
                : <span className="text-[var(--color-danger)]">не разрешился</span>
            }
            ms={report.dns.ms}
          />
        )}
        {report.tcp && (
          <DetailRow
            icon={<Network size={12} />}
            label="TCP"
            value={report.tcp.connected
              ? <span className="text-[var(--color-success)]">соединение открыто</span>
              : <span className="text-[var(--color-danger)]">не открылось</span>}
            ms={report.tcp.ms}
          />
        )}
        {report.tls && (
          <DetailRow
            icon={<Lock size={12} />}
            label="TLS"
            value={report.tls.handshakeOk
              ? <span className="text-[var(--color-success)]">{report.tls.protocol || 'OK'}{report.tls.cipher ? ` · ${report.tls.cipher}` : ''}</span>
              : <span className="text-[var(--color-danger)]">handshake не прошёл</span>}
            ms={report.tls.ms}
          />
        )}
        {report.http && (
          <DetailRow
            icon={<Wifi size={12} />}
            label="HTTP"
            value={report.http.status != null
              ? <span className={report.http.status < 400 ? 'text-[var(--color-success)]' : 'text-[var(--color-warning)]'}>{report.http.status}{report.http.server ? ` · ${report.http.server}` : ''}</span>
              : <span className="text-[var(--color-danger)]">нет ответа</span>}
            ms={report.http.ms}
          />
        )}
        {report.asn && (
          <DetailRow
            icon={<ServerIcon size={12} />}
            label="Где"
            value={`${report.asn.country} · ${report.asn.org}`}
          />
        )}
      </div>
    </MacCard>
  )
}

function DetailRow({ icon, label, value, ms }: {
  icon: React.ReactNode
  label: string
  value: React.ReactNode
  ms?: number | null
}) {
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="text-[var(--color-text-muted)] flex-shrink-0">{icon}</span>
      <span className="text-[var(--color-text-secondary)] w-10 flex-shrink-0">{label}</span>
      <span className="flex-1 truncate text-[var(--color-text)]">{value}</span>
      {ms != null && <span className="text-[var(--color-text-muted)] tabular-nums">{ms} ms</span>}
    </div>
  )
}

// ─── Main page ───────────────────────────────────────────────────────────────

export function Availability() {
  const tunRunning = useAppStore((s) => s.tunRunning)
  const addLog = useAppStore((s) => s.addLog)

  const [input, setInput] = useState('')
  const [checking, setChecking] = useState(false)
  const [error, setError] = useState('')
  const [latest, setLatest] = useState<UrlResult | null>(null)
  const [history, setHistory] = useState<UrlResult[]>([])

  // Routing self-test state.
  const [routingTesting, setRoutingTesting] = useState(false)
  const [routing, setRouting] = useState<{
    vpnIp: string | null
    directIp: string | null
    splitWorks: boolean
    smartRu: { enabled: boolean; ruHostIp: string | null; ruGoesDirect: boolean | null }
    verdict: 'ok' | 'partial' | 'leak' | 'tunnel-off' | 'inconclusive'
    message: string
  } | null>(null)

  const loadHistory = useCallback(async () => {
    try {
      const list = await window.electronAPI.urlAvailabilityHistory()
      setHistory(list || [])
    } catch (err) {
      console.error('failed to load url-availability history', err)
    }
  }, [])

  useEffect(() => {
    loadHistory()
  }, [loadHistory])

  const handleCheck = async () => {
    setError('')
    if (!input.trim()) {
      setError('Введите ссылку, например youtube.com или https://www.instagram.com')
      return
    }
    setChecking(true)
    try {
      const result: UrlResult = await window.electronAPI.urlAvailabilityCheck(input.trim())
      setLatest(result)
      addLog('info', `Проверка ${result.url}: ${verdictTone(result.verdict).label}`)
      loadHistory()
    } catch (err: any) {
      setError(err?.message ?? String(err))
    } finally {
      setChecking(false)
    }
  }

  const handleClearHistory = async () => {
    try {
      await window.electronAPI.urlAvailabilityClearHistory()
      setHistory([])
    } catch (err) {
      console.error('failed to clear history', err)
    }
  }

  const handleRoutingTest = async () => {
    setRoutingTesting(true)
    try {
      const r = await window.electronAPI.runRoutingSelfTest()
      setRouting(r)
      addLog('info', `Проверка маршрутизации: ${r.verdict}`)
    } catch (err: any) {
      addLog('error', `Ошибка проверки маршрутизации: ${err?.message ?? err}`)
    } finally {
      setRoutingTesting(false)
    }
  }

  const verdictInfo = latest ? verdictTone(latest.verdict) : null
  const VerdictIcon = verdictInfo?.icon ?? Info

  return (
    <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_320px] xl:gap-6 items-start">
      <div className="space-y-6 max-w-3xl xl:max-w-none">
        {/* Read-only what-this-does banner */}
        <MacCard className="!p-3">
          <div className="flex gap-3">
            <Search className="w-4 h-4 text-[var(--color-accent)] flex-shrink-0 mt-0.5" />
            <div className="text-xs text-[var(--color-text-secondary)] space-y-1">
              <p className="text-[var(--color-text)] font-medium">Что делает эта страница</p>
              <p>
                <span className="text-[var(--color-text-secondary)]">Сейчас:</span>{' '}
                вы не знаете, заблокирован ли конкретный сайт у вас, или
                просто лагает соединение. Помогает ли VPN — тоже неясно
                без перезапуска защиты.
              </p>
              <p>
                <span className="text-[var(--color-text-secondary)]">Станет:</span>{' '}
                вставляете ссылку, приложение одновременно проверяет её
                «через защиту» и «как было бы без защиты», и говорит, что
                реально работает и нужен ли вам VPN для этого конкретного
                сайта.
              </p>
            </div>
          </div>
        </MacCard>

        {/* Input + Check */}
        <MacCard>
          <h2 className="text-sm font-semibold text-[var(--color-text)] uppercase tracking-wider mb-3 flex items-center gap-2">
            <Search className="w-4 h-4 text-[var(--color-accent)]" />
            Проверить ссылку
          </h2>
          <div className="flex flex-col sm:flex-row gap-2">
            <MacInput
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleCheck() }}
              placeholder="https://youtube.com или просто youtube.com"
              className="flex-1"
              disabled={checking}
            />
            <MacButton
              onClick={handleCheck}
              disabled={checking || !input.trim()}
              variant="primary"
            >
              {checking ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <Search className="w-4 h-4 mr-2" />}
              {checking ? 'Проверяем…' : 'Проверить'}
            </MacButton>
          </div>
          {error && (
            <p className="mt-2 text-xs text-[var(--color-danger)]">{error}</p>
          )}
          {!tunRunning && (
            <p className="mt-2 text-xs text-[var(--color-text-muted)]">
              Защита выключена. Проверим только «как сейчас, без VPN». Чтобы сравнить
              с защитой — включите её на главной и повторите.
            </p>
          )}
        </MacCard>

        {/* Routing self-test — proves the VPN/direct split is real. */}
        <MacCard>
          <div className="flex items-center justify-between gap-3 mb-2">
            <h2 className="text-sm font-semibold text-[var(--color-text)] uppercase tracking-wider flex items-center gap-2">
              <Network className="w-4 h-4 text-[var(--color-accent)]" />
              Проверка маршрутизации
            </h2>
            <MacButton
              onClick={handleRoutingTest}
              disabled={routingTesting || !tunRunning}
              variant="secondary"
            >
              {routingTesting ? <Loader2 className="w-4 h-4 mr-2 animate-spin" /> : <ShieldCheck className="w-4 h-4 mr-2" />}
              {routingTesting ? 'Проверяем…' : 'Проверить'}
            </MacButton>
          </div>
          <p className="text-xs text-[var(--color-text-secondary)]">
            Сравнивает, какой IP виден через VPN и какой — напрямую. Если адреса
            разные — туннель реально разделяет трафик. При включённом «умном
            режиме РФ» дополнительно проверяет, что РФ-сайты идут с вашим
            настоящим адресом.
          </p>
          {!tunRunning && (
            <p className="mt-2 text-xs text-[var(--color-text-muted)]">
              Включите защиту, чтобы проверить маршрутизацию.
            </p>
          )}
          {routing && (
            <div
              className="mt-3 rounded-[var(--radius-sm)] border-l-4 p-3"
              style={{
                borderLeftColor:
                  routing.verdict === 'ok' ? 'var(--color-success)' :
                  routing.verdict === 'partial' ? 'var(--color-warning)' :
                  routing.verdict === 'leak' ? 'var(--color-danger)' :
                  'var(--color-text-secondary)',
                background: 'var(--color-bg)'
              }}
            >
              <p className="text-sm text-[var(--color-text)]">{routing.message}</p>
              <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
                <div className="flex items-center gap-1.5">
                  <ShieldCheck className="w-3 h-3 text-[var(--color-accent)]" />
                  <span className="text-[var(--color-text-secondary)]">Через VPN:</span>
                  <span className="font-mono text-[var(--color-text)]">{routing.vpnIp ?? '—'}</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <ShieldOff className="w-3 h-3 text-[var(--color-warning)]" />
                  <span className="text-[var(--color-text-secondary)]">Напрямую:</span>
                  <span className="font-mono text-[var(--color-text)]">{routing.directIp ?? '—'}</span>
                </div>
              </div>
            </div>
          )}
        </MacCard>

        {/* Result */}
        {latest && (
          <>
            <MacCard
              className={`!p-4 border-l-4`}
              style={{
                borderLeftColor:
                  latest.verdict === 'works-both' ? 'var(--color-success)' :
                  latest.verdict === 'works-only-with-vpn' ? 'var(--color-accent)' :
                  latest.verdict === 'works-only-without-vpn' ? 'var(--color-warning)' :
                  latest.verdict === 'blocked-everywhere' ? 'var(--color-danger)' :
                  'var(--color-text-secondary)'
              }}
            >
              <div className="flex items-start gap-3">
                <VerdictIcon className={`w-6 h-6 flex-shrink-0 ${verdictInfo?.color ?? ''}`} />
                <div className="flex-1">
                  <p className="text-[10px] uppercase tracking-wider text-[var(--color-text-muted)]">
                    Результат для {latest.url}
                  </p>
                  <p className={`text-lg font-semibold ${verdictInfo?.color ?? ''}`}>
                    {verdictInfo?.label}
                  </p>
                  <p className="text-sm text-[var(--color-text-secondary)] mt-1">
                    {latest.recommendation}
                  </p>
                </div>
              </div>
            </MacCard>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <PathDetailCard
                title="Через защиту (VPN)"
                report={latest.tunnel}
                missingMessage={latest.tunnelActive ? undefined : 'Защита была выключена во время проверки.'}
              />
              <PathDetailCard
                title="Без защиты (напрямую)"
                report={latest.direct}
                missingMessage="Нет данных для прямого пути."
              />
            </div>
          </>
        )}
      </div>

      {/* History sidebar */}
      <aside className="hidden xl:block sticky top-6 self-start max-h-[calc(100vh-3rem)] overflow-y-auto pr-1">
        <MacCard className="!p-3">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider">
              Последние проверки
            </h3>
            {history.length > 0 && (
              <button
                type="button"
                onClick={handleClearHistory}
                className="text-[var(--color-text-muted)] hover:text-[var(--color-danger)] p-1 rounded-[4px] transition-colors"
                title="Очистить историю"
                aria-label="Очистить историю"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
          {history.length === 0 ? (
            <p className="text-xs text-[var(--color-text-muted)]">Истории пока нет.</p>
          ) : (
            <ul className="space-y-1.5">
              {history.slice(0, 20).map(item => {
                const info = verdictTone(item.verdict)
                const Icon = info.icon
                return (
                  <li key={item.id}>
                    <button
                      type="button"
                      onClick={() => setLatest(item)}
                      className="w-full flex items-start gap-2 px-2 py-1.5 rounded-[var(--radius-sm)] hover:bg-[var(--color-border)]/40 text-left transition-colors"
                    >
                      <Icon className={`w-3.5 h-3.5 flex-shrink-0 mt-0.5 ${info.color}`} />
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium text-[var(--color-text)] truncate">{item.url}</p>
                        <p className="text-[10px] text-[var(--color-text-muted)]">
                          {formatAge(item.testedAt)} · {info.label.toLowerCase()}
                        </p>
                      </div>
                    </button>
                  </li>
                )
              })}
            </ul>
          )}
        </MacCard>
      </aside>
    </div>
  )
}
