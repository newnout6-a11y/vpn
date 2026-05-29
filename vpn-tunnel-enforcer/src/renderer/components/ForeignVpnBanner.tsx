import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import { AlertTriangle } from 'lucide-react'
import { useForeignVpn, foreignVpnFriendlyName } from './useForeignVpn'

/**
 * Warning banner shown when another VPN/TUN adapter (Happ, WireGuard, …) is
 * active while OUR tunnel is OFF. Tells the user that per-server pings can't
 * be trusted until the other VPN is fully closed, because its tun adapter
 * intercepts our latency probes and answers them locally (collapsing every
 * server to a fake ~1-46 ms).
 *
 * Rendered inline above the profile selector / server list. Self-contained:
 * polls via useForeignVpn and renders nothing when no foreign VPN is present.
 */
export function ForeignVpnBanner() {
  const { t } = useTranslation()
  const foreign = useForeignVpn()
  const name = foreignVpnFriendlyName(foreign)

  return (
    <AnimatePresence initial={false}>
      {foreign && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          exit={{ opacity: 0, height: 0 }}
          transition={{ duration: 0.2 }}
          className="overflow-hidden"
        >
          <div className="flex items-start gap-2.5 rounded-[var(--radius-sm)] border border-[var(--color-warning)]/40 bg-[var(--color-warning)]/10 px-3 py-2.5 text-[var(--color-text)]">
            <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0 text-[var(--color-warning)]" />
            <div className="min-w-0 text-xs leading-relaxed">
              <p className="font-medium">
                {t('foreignVpn.title', 'Обнаружен другой VPN')}
                {name ? `: ${name}` : ''}
              </p>
              <p className="text-[var(--color-text-secondary)] mt-0.5">
                {t(
                  'foreignVpn.body',
                  'Пока он запущен, пинг ненадёжен — его адаптер перехватывает проверки и отвечает за все серверы (отсюда одинаковые ~1–40 мс). Полностью закройте другой VPN (выход из трея), чтобы увидеть реальные задержки.'
                )}
              </p>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
