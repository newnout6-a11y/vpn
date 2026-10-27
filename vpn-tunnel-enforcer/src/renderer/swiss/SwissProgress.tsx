import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from '../design-system/utils'
import type { ConnectionOperation } from '../../shared/operation'

const CELLS = 10

/**
 * Ten-cell ruler under the slab. The main process reports an operation's start
 * and deadline but not individual steps, so cells fill by elapsed time against
 * the deadline (indeterminate stripes when there is no deadline). The hint says so.
 */
export function SwissProgress({ operation, busy }: { operation: ConnectionOperation | null; busy: boolean }) {
  const { t } = useTranslation()
  const [tick, setTick] = useState(() => Date.now())
  useEffect(() => {
    if (!busy) return
    const id = window.setInterval(() => setTick(Date.now()), 250)
    return () => window.clearInterval(id)
  }, [busy])

  const span = busy && operation && operation.deadline ? operation.deadline - operation.startedAt : null
  const fill = span && operation ? Math.min(1, Math.max(0, (tick - operation.startedAt) / span)) : 0
  const lit = Math.round(fill * CELLS)
  const indeterminate = busy && !span

  return (
    <div className={cn('swiss-progress', indeterminate && 'is-indeterminate')} title={busy ? t('swiss.progressHint') : undefined} aria-hidden="true">
      {Array.from({ length: CELLS }, (_, i) => (
        <span key={i} className={cn('swiss-progress-cell', busy && i < lit && 'is-done')}>
          <span className="swiss-mono">{String(i + 1).padStart(2, '0')}</span>
        </span>
      ))}
    </div>
  )
}
