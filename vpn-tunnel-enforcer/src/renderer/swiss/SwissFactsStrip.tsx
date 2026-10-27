import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { cn } from '../design-system/utils'
import { useAppStore } from '../store'
import { isIpcRemoteErrorData } from '../../shared/ipc-result'
import { MASCOT_EVENT, type MascotEvent } from './useMascot'

interface Props {
  /** The dashboard's existing route/leak check (runLeakCheck under the hood). */
  onCheckLeaks: () => void
  checking: boolean
}

const nudge = (kind: MascotEvent) => window.dispatchEvent(new CustomEvent(MASCOT_EVENT, { detail: kind }))

/** «Пломба» facts strip: mode · Smart RU · kill-switch · leaks — all from the real store. */
export function SwissFactsStrip({ onCheckLeaks, checking }: Props) {
  const { t } = useTranslation()
  const routingMode = useAppStore(s => s.settings.routingMode)
  const smart = useAppStore(s => s.settings.smartRuSplit)
  const setSettings = useAppStore(s => s.setSettings)
  const addLog = useAppStore(s => s.addLog)
  const fw = useAppStore(s => s.firewallKillSwitchStatus)
  const leakChecks = useAppStore(s => s.leakChecks)
  const [savingSmart, setSavingSmart] = useState(false)

  // When a check finishes, let the mascot react to its actual verdict
  const wasChecking = useRef(checking)
  useEffect(() => {
    if (wasChecking.current && !checking && leakChecks) {
      nudge(leakChecks.summary === 'ok' ? 'leak-ok' : leakChecks.summary === 'fail' ? 'leak-fail' : 'leak-warn')
    }
    wasChecking.current = checking
  }, [checking, leakChecks])

  const toggleSmart = async () => {
    const next = !smart
    setSavingSmart(true)
    try {
      // Same persisted setting as the Settings page; applies on the next connect
      setSettings(await window.electronAPI.saveSettings({ smartRuSplit: next }))
      // Only a saved change gets the mascot's comment
      nudge(next ? 'smart-on' : 'smart-off')
    } catch (err) {
      addLog('error', t('swiss.smartSaveFailed') + ': ' + (isIpcRemoteErrorData(err) || err instanceof Error ? err.message : String(err)))
    } finally {
      setSavingSmart(false)
    }
  }

  const checkLeaks = () => {
    nudge('leak-start')
    onCheckLeaks()
  }

  const ksValue = fw.reason === 'checking' ? t('swiss.ksChecking')
    : fw.state === 'verified' ? t('swiss.ksHolding')
    : fw.state === 'inactive' ? t('swiss.ksOff')
    : t('swiss.ksUnknown')
  const leakValue = checking ? t('swiss.leakChecking')
    : !leakChecks ? '—'
    : leakChecks.summary === 'ok' ? t('swiss.leakNone')
    : leakChecks.summary === 'fail' ? t('swiss.leakFound')
    : t('swiss.leakWarn')

  return (
    <div className="swiss-facts">
      <Fact label={t('swiss.labelMode')}>
        <span className="swiss-fact-value">{routingMode === 'soft' ? t('swiss.modeSoft') : t('swiss.modeHard')}</span>
      </Fact>

      <Fact label={t('swiss.labelSmart')} perch="smart">
        <span className={cn('swiss-fact-value', !smart && 'is-dim')} title={t('swiss.smartPending')}>
          {smart ? t('swiss.on') : t('swiss.off')}
        </span>
        <button
          type="button"
          className="swiss-fact-action"
          onClick={() => void toggleSmart()}
          disabled={savingSmart}
          aria-label={smart ? t('swiss.smartTurnOff') : t('swiss.smartTurnOn')}
          title={t('swiss.smartPending')}
        >
          {smart ? t('swiss.turnOff') : t('swiss.turnOn')}
        </button>
      </Fact>

      <Fact label={t('swiss.labelKs')} perch="killswitch">
        <span className={cn('swiss-fact-value', fw.state === 'unknown' && fw.reason !== 'checking' && 'is-alert', fw.state === 'inactive' && 'is-dim')}>
          {ksValue}
        </span>
      </Fact>

      <Fact label={t('swiss.labelLeaks')} perch="leak">
        <span className={cn('swiss-fact-value', leakChecks?.summary === 'fail' && 'is-alert', !leakChecks && !checking && 'is-dim')}>
          {leakValue}
          {checking && <span className="blink">_</span>}
        </span>
        {/* Keeps its space while checking so nothing (or the mascot) jumps into it */}
        <button
          type="button"
          className={cn('swiss-fact-action', checking && 'is-hidden')}
          onClick={checkLeaks}
          disabled={checking}
          aria-label={t('swiss.checkAria')}
        >
          {t('swiss.check')}
        </button>
      </Fact>
    </div>
  )
}

function Fact({ label, perch, children }: { label: string; perch?: string; children: ReactNode }) {
  return (
    <div
      className="swiss-fact"
      data-perch={perch}
      data-perch-y="bottom"
      data-perch-x="0.6"
      data-perch-scale="0.36"
      data-perch-fit="gap"
    >
      <span className="swiss-label shrink-0">{label}</span>
      {children}
    </div>
  )
}
