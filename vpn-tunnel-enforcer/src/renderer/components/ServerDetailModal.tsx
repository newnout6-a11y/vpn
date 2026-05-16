import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { motion } from 'framer-motion'
import {
  Globe,
  Wifi,
  Server as ServerIcon,
  MapPin,
  Network,
  Shield,
  Clock,
  Activity,
  Lock,
  Building2,
  AlertCircle
} from 'lucide-react'
import { MacModal, MacButton, MacCard, MacBadge } from '../design-system'
import { detectCountry } from './countryGlyph'
import type { ServerProfile } from '../../shared/ipc-types'

interface IpInfo {
  ip: string
  country?: string
  city?: string
  region?: string
  org?: string
  loc?: string  // "lat,lon"
  timezone?: string
}

// Mirrors ServerProbeResult from src/main/serverProbe.ts. Kept loose-typed
// (any-bridged through preload) so that updating the main-process shape
// doesn't break the type chain — we just defensively check fields.
interface AsnInfo {
  asn: string
  org: string
  network: string
  country: string
}
interface LatencyStats {
  min: number
  avg: number
  max: number
  jitter: number
  loss: number
  samples: number[]
}
interface PortScanResult {
  port: number
  open: boolean
  service?: string
}
interface TlsCertInfo {
  subject: string
  issuer: string
  validFrom: string
  validTo: string
  fingerprint: string
  sans: string[]
  protocol: string
  cipher: string
}
interface ServerProbeResult {
  host: string
  resolvedIps: string[]
  reverseDns: string | null
  asn: AsnInfo | null
  latency: LatencyStats | null
  openPorts: PortScanResult[]
  tlsCert: TlsCertInfo | null
  httpBanner: string | null
}

/**
 * Either a full ServerProfile from the proxy list, or a cached Direct VPN
 * profile (which is an outbound config without server/port at this level).
 */
type AnyProfile =
  | ServerProfile
  | { name: string; protocol: string; server?: string; port?: number; country?: string }

interface ServerDetailModalProps {
  open: boolean
  profile: AnyProfile | null
  onClose: () => void
}

/**
 * Modal that shows detailed metadata about a VPN server profile.
 *
 * Combines two data sources:
 *   1. ipapi.co (best-effort) for country / city / provider / map preview.
 *   2. window.electronAPI.serverProbe — main-process active probing of the
 *      host: DNS resolution, reverse DNS, ASN, TCP latency, common-port
 *      scan, TLS cert inspection, HTTP banner. Anything that can't be
 *      reached is just hidden — we never show error spinners forever.
 */
export function ServerDetailModal({ open, profile, onClose }: ServerDetailModalProps) {
  const { t } = useTranslation()
  const [ipInfo, setIpInfo] = useState<IpInfo | null>(null)
  const [loading, setLoading] = useState(false)
  const [probe, setProbe] = useState<ServerProbeResult | null>(null)
  const [probing, setProbing] = useState(false)
  const [probeError, setProbeError] = useState(false)

  useEffect(() => {
    if (!open || !profile) return
    setIpInfo(null)
    setProbe(null)
    setProbeError(false)

    const host = (profile as any).server
    const port = (profile as any).port as number | undefined
    if (!host) {
      setLoading(false)
      setProbing(false)
      return
    }

    setLoading(true)
    setProbing(true)
    let cancelled = false

    // Geo info (existing behaviour).
    fetch(`https://ipapi.co/${host}/json/`, { method: 'GET' })
      .then(r => (r.ok ? r.json() : null))
      .then(data => {
        if (cancelled) return
        if (data && !data.error) {
          setIpInfo({
            ip: data.ip || host,
            country: data.country_name,
            city: data.city,
            region: data.region,
            org: data.org,
            loc:
              data.latitude && data.longitude
                ? `${data.latitude},${data.longitude}`
                : undefined,
            timezone: data.timezone
          })
        }
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    // Active probe via main process (DNS/latency/ports/TLS).
    window.electronAPI.serverProbe(host, port)
      .then((result: ServerProbeResult | null) => {
        if (cancelled) return
        if (result) setProbe(result)
        else setProbeError(true)
      })
      .catch(() => {
        if (!cancelled) setProbeError(true)
      })
      .finally(() => {
        if (!cancelled) setProbing(false)
      })

    return () => {
      cancelled = true
    }
  }, [open, profile])

  if (!profile) return null

  const host = (profile as any).server as string | undefined
  const port = (profile as any).port as number | undefined
  const ping = (profile as any).ping as number | null | undefined
  // Name-based country recognition is used as the universal fallback. ASN
  // lookups are rate-limited (free ipapi.co tier) and reverse DNS rarely
  // returns geo info — but the profile name almost always names the country.
  const recognised = detectCountry(profile.name)
  const lat = ipInfo?.loc?.split(',')[0]
  const lon = ipInfo?.loc?.split(',')[1]
  const mapUrl =
    lat && lon
      ? `https://www.openstreetmap.org/export/embed.html?bbox=${parseFloat(lon) - 2},${parseFloat(lat) - 2},${parseFloat(lon) + 2},${parseFloat(lat) + 2}&marker=${lat},${lon}`
      : null

  // Stagger the diagnostic cards on entrance — feels less janky when a few
  // network probes finish at slightly different times.
  const cardMotion = (delay: number) => ({
    initial: { opacity: 0, y: 6 },
    animate: { opacity: 1, y: 0 },
    transition: { duration: 0.25, delay, ease: 'easeOut' as const }
  })

  return (
    <MacModal open={open} onClose={onClose} title={`${recognised?.flag ?? '🌐'}  ${profile.name}`} size="lg">
      <div className="space-y-4">
        {/* Protocol & Host */}
        <div className="grid grid-cols-2 gap-3">
          <DetailField
            icon={<Shield size={14} />}
            label={t('serverDetail.protocol')}
            value={profile.protocol.toUpperCase()}
          />
          <DetailField
            icon={<Network size={14} />}
            label={t('serverDetail.host')}
            value={host || '—'}
          />
          <DetailField
            icon={<ServerIcon size={14} />}
            label={t('serverDetail.port')}
            value={port ? String(port) : '—'}
          />
          <DetailField
            icon={<Wifi size={14} />}
            label={t('serverDetail.ping')}
            value={ping != null ? `${ping} ms` : '—'}
          />
        </div>

        {/* Geo info. We render the card whenever we know *anything* about
            the location — either ipapi returned data, or the profile name
            itself encodes a country. Without this fallback, free-tier rate
            limiting on ipapi makes the whole section disappear. */}
        {loading && (
          <p className="text-xs text-[var(--color-text-secondary)]">
            {t('serverDetail.loading')}
          </p>
        )}
        {(ipInfo || recognised) && (
          <MacCard className="!p-3">
            <h4 className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider mb-2">
              {t('serverDetail.location')}
            </h4>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <DetailField
                icon={<MapPin size={12} />}
                label={t('serverDetail.country')}
                value={ipInfo?.country || recognised?.label || '—'}
              />
              <DetailField
                icon={<MapPin size={12} />}
                label={t('serverDetail.city')}
                value={ipInfo?.city || '—'}
              />
              <DetailField
                icon={<Globe size={12} />}
                label={t('serverDetail.org')}
                value={ipInfo?.org || '—'}
              />
              <DetailField
                icon={<Clock size={12} />}
                label={t('serverDetail.timezone')}
                value={ipInfo?.timezone || '—'}
              />
            </div>
          </MacCard>
        )}

        {/* Map */}
        {mapUrl && (
          <div className="rounded-[var(--radius-md)] overflow-hidden border border-[var(--color-border)]">
            <iframe
              src={mapUrl}
              width="100%"
              height="220"
              style={{ border: 0 }}
              title="map"
              loading="lazy"
            />
          </div>
        )}

        {/* Active diagnostics from main process */}
        {host && probing && !probe && (
          <p className="text-xs text-[var(--color-text-secondary)] flex items-center gap-1.5">
            <Activity size={12} className="animate-pulse" />
            {t('serverDetail.probing')}
          </p>
        )}
        {host && probeError && !probe && (
          <p className="text-xs text-[var(--color-text-secondary)] flex items-center gap-1.5">
            <AlertCircle size={12} />
            {t('serverDetail.probeError')}
          </p>
        )}

        {probe && (
          <>
            {/* Network: resolved IPs, rDNS, HTTP server */}
            {(probe.resolvedIps.length > 0 || probe.reverseDns || probe.httpBanner) && (
              <motion.div {...cardMotion(0.0)}>
                <MacCard className="!p-3">
                  <h4 className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <Network size={12} />
                    {t('serverDetail.network')}
                  </h4>
                  <div className="space-y-2">
                    {probe.resolvedIps.length > 0 && (
                      <div>
                        <div className="text-xs text-[var(--color-text-secondary)] mb-1">
                          {t('serverDetail.resolvedIps')}
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {probe.resolvedIps.map(ip => (
                            <MacBadge key={ip} variant="neutral" className="font-mono">
                              {ip}
                            </MacBadge>
                          ))}
                        </div>
                      </div>
                    )}
                    {probe.reverseDns && (
                      <DetailField
                        icon={<Globe size={12} />}
                        label={t('serverDetail.reverseDns')}
                        value={probe.reverseDns}
                      />
                    )}
                    {probe.httpBanner && (
                      <DetailField
                        icon={<ServerIcon size={12} />}
                        label={t('serverDetail.httpServer')}
                        value={probe.httpBanner}
                      />
                    )}
                  </div>
                </MacCard>
              </motion.div>
            )}

            {/* ASN / Org */}
            {probe.asn && (
              <motion.div {...cardMotion(0.05)}>
                <MacCard className="!p-3">
                  <h4 className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <Building2 size={12} />
                    {t('serverDetail.asn')}
                  </h4>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <DetailField
                      icon={<Building2 size={12} />}
                      label={t('serverDetail.asn')}
                      value={probe.asn.asn || '—'}
                    />
                    <DetailField
                      icon={<Globe size={12} />}
                      label={t('serverDetail.org')}
                      value={probe.asn.org || '—'}
                    />
                    {probe.asn.network && (
                      <DetailField
                        icon={<Network size={12} />}
                        label={t('serverDetail.network_')}
                        value={probe.asn.network}
                      />
                    )}
                    {probe.asn.country && (
                      <DetailField
                        icon={<MapPin size={12} />}
                        label={t('serverDetail.country')}
                        value={probe.asn.country}
                      />
                    )}
                  </div>
                </MacCard>
              </motion.div>
            )}

            {/* Latency */}
            {probe.latency && (
              <motion.div {...cardMotion(0.1)}>
                <MacCard className="!p-3">
                  <h4 className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <Activity size={12} />
                    {t('serverDetail.latency')}
                  </h4>
                  <div className="grid grid-cols-3 gap-2 text-xs mb-3">
                    <LatencyStat label={t('serverDetail.latencyMin')} value={`${probe.latency.min} ms`} />
                    <LatencyStat label={t('serverDetail.latencyAvg')} value={`${probe.latency.avg} ms`} highlight />
                    <LatencyStat label={t('serverDetail.latencyMax')} value={`${probe.latency.max} ms`} />
                    <LatencyStat label={t('serverDetail.jitter')} value={`${probe.latency.jitter} ms`} />
                    <LatencyStat
                      label={t('serverDetail.loss')}
                      value={`${Math.round(probe.latency.loss * 100)}%`}
                      tone={probe.latency.loss > 0.2 ? 'danger' : probe.latency.loss > 0 ? 'warning' : 'success'}
                    />
                  </div>
                  {probe.latency.samples.length > 0 && (
                    <LatencySparkline samples={probe.latency.samples} />
                  )}
                </MacCard>
              </motion.div>
            )}

            {/* Open ports */}
            <motion.div {...cardMotion(0.15)}>
              <MacCard className="!p-3">
                <h4 className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <ServerIcon size={12} />
                  {t('serverDetail.openPorts')}
                </h4>
                {probe.openPorts.length === 0 ? (
                  <p className="text-xs text-[var(--color-text-secondary)]">
                    {t('serverDetail.noOpenPorts')}
                  </p>
                ) : (
                  <div className="flex flex-wrap gap-1.5">
                    {probe.openPorts.map(p => (
                      <MacBadge key={p.port} variant="success">
                        <span className="font-mono">{p.port}</span>
                        {p.service && (
                          <span className="opacity-70 ml-1">— {p.service}</span>
                        )}
                      </MacBadge>
                    ))}
                  </div>
                )}
              </MacCard>
            </motion.div>

            {/* TLS Certificate */}
            {probe.tlsCert && (
              <motion.div {...cardMotion(0.2)}>
                <MacCard className="!p-3">
                  <h4 className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <Lock size={12} />
                    {t('serverDetail.tlsCert')}
                  </h4>
                  <div className="space-y-2 text-xs">
                    {probe.tlsCert.subject && (
                      <DetailField
                        icon={<Lock size={12} />}
                        label={t('serverDetail.subject')}
                        value={probe.tlsCert.subject}
                      />
                    )}
                    {probe.tlsCert.issuer && (
                      <DetailField
                        icon={<Building2 size={12} />}
                        label={t('serverDetail.issuer')}
                        value={probe.tlsCert.issuer}
                      />
                    )}
                    <div className="grid grid-cols-2 gap-2">
                      {probe.tlsCert.validFrom && (
                        <DetailField
                          icon={<Clock size={12} />}
                          label={t('serverDetail.validFrom')}
                          value={probe.tlsCert.validFrom}
                        />
                      )}
                      {probe.tlsCert.validTo && (
                        <DetailField
                          icon={<Clock size={12} />}
                          label={t('serverDetail.validTo')}
                          value={probe.tlsCert.validTo}
                        />
                      )}
                      {probe.tlsCert.protocol && (
                        <DetailField
                          icon={<Shield size={12} />}
                          label={t('serverDetail.protocol_')}
                          value={probe.tlsCert.protocol}
                        />
                      )}
                      {probe.tlsCert.cipher && (
                        <DetailField
                          icon={<Lock size={12} />}
                          label={t('serverDetail.cipher')}
                          value={probe.tlsCert.cipher}
                        />
                      )}
                    </div>
                    {probe.tlsCert.sans.length > 0 && (
                      <div>
                        <div className="text-xs text-[var(--color-text-secondary)] mb-1">
                          {t('serverDetail.sans')}
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {probe.tlsCert.sans.slice(0, 12).map(san => (
                            <MacBadge key={san} variant="neutral" className="font-mono">
                              {san}
                            </MacBadge>
                          ))}
                          {probe.tlsCert.sans.length > 12 && (
                            <span className="text-xs text-[var(--color-text-secondary)] self-center">
                              +{probe.tlsCert.sans.length - 12}
                            </span>
                          )}
                        </div>
                      </div>
                    )}
                    {probe.tlsCert.fingerprint && (
                      <div>
                        <div className="text-xs text-[var(--color-text-secondary)] mb-1">
                          {t('serverDetail.fingerprint')}
                        </div>
                        <p className="text-[10px] font-mono break-all text-[var(--color-text)]">
                          {probe.tlsCert.fingerprint}
                        </p>
                      </div>
                    )}
                  </div>
                </MacCard>
              </motion.div>
            )}
          </>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <MacButton variant="ghost" onClick={onClose}>
            {t('common.close')}
          </MacButton>
        </div>
      </div>
    </MacModal>
  )
}

function DetailField({
  icon,
  label,
  value
}: {
  icon: React.ReactNode
  label: string
  value: string
}) {
  return (
    <div>
      <div className="flex items-center gap-1.5 text-[var(--color-text-secondary)] mb-0.5">
        {icon}
        <span className="text-xs">{label}</span>
      </div>
      <p className="text-sm font-medium text-[var(--color-text)] truncate">{value}</p>
    </div>
  )
}

function LatencyStat({
  label,
  value,
  highlight,
  tone
}: {
  label: string
  value: string
  highlight?: boolean
  tone?: 'success' | 'warning' | 'danger'
}) {
  const toneClass =
    tone === 'danger'
      ? 'text-[var(--color-danger)]'
      : tone === 'warning'
        ? 'text-[var(--color-warning)]'
        : tone === 'success'
          ? 'text-[var(--color-success)]'
          : highlight
            ? 'text-[var(--color-accent)]'
            : 'text-[var(--color-text)]'
  return (
    <div className="text-center">
      <div className="text-[10px] uppercase tracking-wider text-[var(--color-text-secondary)] mb-0.5">
        {label}
      </div>
      <div className={`text-sm font-semibold ${toneClass}`}>{value}</div>
    </div>
  )
}

/**
 * Tiny inline bar chart of latency samples — gives a "feel" for the
 * jitter without needing a charting library.
 */
function LatencySparkline({ samples }: { samples: number[] }) {
  if (samples.length === 0) return null
  const max = Math.max(...samples, 1)
  return (
    <div className="flex items-end gap-1 h-10">
      {samples.map((sample, i) => {
        const heightPct = Math.max(8, (sample / max) * 100)
        return (
          <motion.div
            key={i}
            initial={{ height: 0 }}
            animate={{ height: `${heightPct}%` }}
            transition={{ duration: 0.3, delay: i * 0.04 }}
            className="flex-1 bg-[var(--color-accent)]/60 rounded-sm"
            title={`${sample} ms`}
          />
        )
      })}
    </div>
  )
}
