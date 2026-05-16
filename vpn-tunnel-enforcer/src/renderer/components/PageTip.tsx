import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Info, X } from 'lucide-react'

interface PageTipProps {
  tipKey: string // localStorage key to remember dismissal
  children: React.ReactNode
}

export function PageTip({ tipKey, children }: PageTipProps) {
  const storageKey = `tip-dismissed-${tipKey}`
  const [dismissed, setDismissed] = useState(() => localStorage.getItem(storageKey) === '1')

  if (dismissed) return null

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -10 }}
        transition={{ duration: 0.3, ease: 'easeOut' }}
        className="flex items-start gap-3 p-4 rounded-[var(--radius-md)] bg-[var(--color-accent)]/5 border border-[var(--color-accent)]/20 mb-6"
      >
        <Info className="w-5 h-5 text-[var(--color-accent)] shrink-0 mt-0.5" />
        <p className="text-sm text-[var(--color-text)] flex-1">{children}</p>
        <button
          onClick={() => { localStorage.setItem(storageKey, '1'); setDismissed(true) }}
          className="p-1 rounded-[var(--radius-sm)] text-[var(--color-text-secondary)] hover:text-[var(--color-text)] hover:bg-[var(--color-border)]/50 transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </motion.div>
    </AnimatePresence>
  )
}
