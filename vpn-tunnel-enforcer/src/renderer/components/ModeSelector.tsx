import React, { useCallback, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { MacSegmentedControl, MacModal, MacButton } from '../design-system'
import type { SegmentOption } from '../design-system'
import { useAppStore } from '../store'

/**
 * Mode value used internally — maps to the store's connectionMode and mode fields.
 * - 'hard' → TUN mode (connectionMode: 'localProxy', mode: 'hard')
 * - 'soft' → Autoconfig mode (connectionMode: 'localProxy', mode: 'soft')
 * - 'direct' → Direct VPN (connectionMode: 'directVpn')
 */
export type ModeValue = 'hard' | 'soft' | 'direct'

export interface ModeSelectorProps {
  /** Modes that should be shown as disabled (unavailable) */
  disabledModes?: ModeValue[]
  className?: string
}

/**
 * Derives the current ModeValue from the Zustand store state.
 */
function deriveCurrentMode(
  connectionMode: 'localProxy' | 'directVpn',
  storeMode: string
): ModeValue {
  if (connectionMode === 'directVpn') return 'direct'
  if (storeMode === 'soft') return 'soft'
  return 'hard'
}

/**
 * ModeSelector — segmented control for switching between VPN operation modes.
 *
 * Displays three segments: Hard (TUN), Soft (Autoconfig), Direct VPN.
 * Shows a confirmation dialog when switching mode while VPN is connected.
 * Disables unavailable modes with opacity 0.5.
 *
 * Validates: Requirements 4.1, 4.2, 4.3, 4.4
 */
export const ModeSelector: React.FC<ModeSelectorProps> = ({
  disabledModes = [],
  className,
}) => {
  const { t } = useTranslation()

  const settings = useAppStore((s) => s.settings)
  const tunRunning = useAppStore((s) => s.tunRunning)
  const mode = useAppStore((s) => s.mode)
  const setMode = useAppStore((s) => s.setMode)
  const updateSettings = useAppStore((s) => s.updateSettings)
  const addLog = useAppStore((s) => s.addLog)

  const [confirmOpen, setConfirmOpen] = useState(false)
  const [pendingMode, setPendingMode] = useState<ModeValue | null>(null)

  const currentMode = deriveCurrentMode(settings.connectionMode, mode)

  const options: SegmentOption[] = [
    {
      value: 'hard',
      label: t('modes.hard'),
      disabled: disabledModes.includes('hard'),
    },
    {
      value: 'soft',
      label: t('modes.soft'),
      disabled: disabledModes.includes('soft'),
    },
    {
      value: 'direct',
      label: t('modes.direct'),
      disabled: disabledModes.includes('direct'),
    },
  ]

  const applyMode = useCallback(
    async (newMode: ModeValue) => {
      // Stop current VPN if running
      if (tunRunning) {
        try {
          await window.electronAPI.stopTun()
        } catch (err: any) {
          addLog('error', `Failed to stop VPN before mode switch: ${err.message}`)
        }
      }

      // Apply the new mode to settings and store
      switch (newMode) {
        case 'hard':
          updateSettings({ connectionMode: 'localProxy' })
          setMode('hard')
          try {
            await window.electronAPI.saveSettings({ connectionMode: 'localProxy' })
          } catch { /* settings will sync on next load */ }
          break
        case 'soft':
          updateSettings({ connectionMode: 'localProxy' })
          setMode('soft')
          try {
            await window.electronAPI.saveSettings({ connectionMode: 'localProxy' })
          } catch { /* settings will sync on next load */ }
          break
        case 'direct':
          updateSettings({ connectionMode: 'directVpn' })
          setMode('off')
          try {
            await window.electronAPI.saveSettings({ connectionMode: 'directVpn' })
          } catch { /* settings will sync on next load */ }
          break
      }

      addLog('info', `Mode switched to: ${newMode}`)
    },
    [tunRunning, updateSettings, setMode, addLog]
  )

  const handleChange = useCallback(
    (value: string) => {
      const newMode = value as ModeValue
      if (newMode === currentMode) return

      // If VPN is connected, show confirmation dialog
      if (tunRunning || mode === 'hard' || mode === 'soft') {
        // Only show dialog if VPN is actually active
        if (tunRunning) {
          setPendingMode(newMode)
          setConfirmOpen(true)
          return
        }
      }

      applyMode(newMode)
    },
    [currentMode, tunRunning, mode, applyMode]
  )

  const handleConfirm = useCallback(() => {
    setConfirmOpen(false)
    if (pendingMode) {
      applyMode(pendingMode)
      setPendingMode(null)
    }
  }, [pendingMode, applyMode])

  const handleCancel = useCallback(() => {
    setConfirmOpen(false)
    setPendingMode(null)
  }, [])

  return (
    <>
      <MacSegmentedControl
        options={options}
        value={currentMode}
        onChange={handleChange}
        className={className}
      />

      {/* Confirmation dialog when switching mode with active VPN */}
      <MacModal
        open={confirmOpen}
        onClose={handleCancel}
        title={t('common.warning')}
        size="sm"
        footer={
          <>
            <MacButton variant="secondary" onClick={handleCancel}>
              {t('common.cancel')}
            </MacButton>
            <MacButton variant="primary" onClick={handleConfirm}>
              {t('common.confirm')}
            </MacButton>
          </>
        }
      >
        <p className="text-sm text-[var(--color-text-secondary)]">
          {t('common.switchModeWarning')}
        </p>
      </MacModal>
    </>
  )
}
