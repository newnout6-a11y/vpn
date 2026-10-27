import { useTranslation } from 'react-i18next'
import { motion, AnimatePresence } from 'framer-motion'
import '../styles/swiss.css'
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
          {/* «Пломба» notice strip: orange bar, mono title, one or two lines of body */}
          <div className="c-swiss swiss-notice" role="note">
            <span className="swiss-label swiss-notice-tag">
              {t('foreignVpn.title', 'Обнаружен другой VPN')}
              {name ? ': ' + name : ''}
            </span>
            <p className="swiss-notice-body">
              {t(
                'foreignVpn.body',
                'Пока он запущен, пинг ненадёжен — его адаптер перехватывает проверки и отвечает за все серверы (отсюда одинаковые ~1–40 мс). Полностью закройте другой VPN (выход из трея), чтобы увидеть реальные задержки.'
              )}
            </p>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
