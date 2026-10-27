import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from '../design-system/utils'
import { useAppStore, type LogEntry } from '../store'

const pad = (n: number) => String(n).padStart(2, '0')
const clock = (ts: number) => {
  const d = new Date(ts)
  return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds())
}
const keyOf = (e: LogEntry) => e.timestamp + ':' + e.message

/** «Пломба» journal panel: the latest entries of the app's real log. */
export function SwissJournal() {
  const { t } = useTranslation()
  const logs = useAppStore(s => s.logs)
  // Entries present on first render don't flash; only fresh events do
  const [initial] = useState(() => new Set(logs.map(keyOf)))
  const recent = logs.slice(-9).reverse()

  return (
    <section className="swiss-panel">
      <header className="swiss-panel-head" data-perch="journal" data-perch-y="bottom" data-perch-scale="0.32" data-perch-fit="gap">
        <span className="swiss-label swiss-label-ink">{t('swiss.journal')}</span>
      </header>
      <div className="swiss-panel-body">
        {recent.length === 0 ? (
          <p className="swiss-empty">{t('swiss.journalEmpty')}</p>
        ) : (
          recent.map(e => (
            <div key={keyOf(e)} className={cn('swiss-log-row', !initial.has(keyOf(e)) && 'row-in')}>
              <span className="swiss-mono swiss-log-time">{clock(e.timestamp)}</span>
              <span className={cn('swiss-log-msg', e.level !== 'info' && 'is-warn')} title={e.message}>
                {e.message}
              </span>
            </div>
          ))
        )}
      </div>
    </section>
  )
}
