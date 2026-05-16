/**
 * KillSwitchSettings — Settings UI for the granular kill-switch feature.
 *
 * Shows:
 * 1. A MacSegmentedControl with three levels: Off / Standard / Strict
 * 2. Exception list with type, value, label, and remove button
 * 3. "Add Exception" form with type selector, value input (+ file dialog for apps), label input, and Add button
 *
 * Calls IPC channels:
 * - kill-switch:get-level / kill-switch:set-level
 * - kill-switch:get-exceptions / kill-switch:add-exception / kill-switch:remove-exception
 *
 * Validates: Requirements 8.1, 8.4
 */

import React, { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { motion } from 'framer-motion'
import { Shield, Trash2, Plus, FolderOpen } from 'lucide-react'
import { MacCard } from '../design-system/MacCard'
import { MacSegmentedControl } from '../design-system/MacSegmentedControl'
import { MacInput } from '../design-system/MacInput'
import { MacButton } from '../design-system/MacButton'
import { MacSelect } from '../design-system/MacSelect'
import type { KillSwitchLevel, KillSwitchException } from '../../shared/ipc-types'

export const KillSwitchSettings: React.FC = () => {
  const { t } = useTranslation()

  const [level, setLevel] = useState<KillSwitchLevel>('off')
  const [exceptions, setExceptions] = useState<KillSwitchException[]>([])
  const [loading, setLoading] = useState(true)

  // Add exception form state
  const [newType, setNewType] = useState<'app' | 'ip'>('app')
  const [newValue, setNewValue] = useState('')
  const [newLabel, setNewLabel] = useState('')
  const [adding, setAdding] = useState(false)

  // Load initial state from main process
  const loadState = useCallback(async () => {
    try {
      const api = window.electronAPI
      const [currentLevel, currentExceptions] = await Promise.all([
        api.killSwitchGetLevel(),
        api.killSwitchGetExceptions()
      ])
      setLevel(currentLevel)
      setExceptions(currentExceptions)
    } catch (err) {
      console.error('Failed to load kill-switch state:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadState()
  }, [loadState])

  // Handle level change
  const handleLevelChange = async (newLevel: string) => {
    const lvl = newLevel as KillSwitchLevel
    setLevel(lvl)
    try {
      await window.electronAPI.killSwitchSetLevel(lvl)
    } catch (err) {
      console.error('Failed to set kill-switch level:', err)
      // Revert on error
      loadState()
    }
  }

  // Handle browse for app path via file dialog
  const handleBrowseApp = async () => {
    try {
      const result = await window.electronAPI.killSwitchBrowseApp()
      if (result) {
        setNewValue(result.path)
        if (!newLabel.trim()) {
          setNewLabel(result.name)
        }
      }
    } catch (err) {
      console.error('Failed to browse for app:', err)
    }
  }

  // Handle add exception
  const handleAddException = async () => {
    if (!newValue.trim()) return

    setAdding(true)
    try {
      const added = await window.electronAPI.killSwitchAddException({
        type: newType,
        value: newValue.trim(),
        label: newLabel.trim() || newValue.trim()
      })
      setExceptions((prev) => [...prev, added])
      // Reset form
      setNewValue('')
      setNewLabel('')
    } catch (err) {
      console.error('Failed to add kill-switch exception:', err)
    } finally {
      setAdding(false)
    }
  }

  // Handle remove exception
  const handleRemoveException = async (id: string) => {
    try {
      await window.electronAPI.killSwitchRemoveException(id)
      setExceptions((prev) => prev.filter((e) => e.id !== id))
    } catch (err) {
      console.error('Failed to remove kill-switch exception:', err)
    }
  }

  const levelOptions = [
    { value: 'off', label: t('settings.killSwitchOff') },
    { value: 'standard', label: t('settings.killSwitchStandard') },
    { value: 'strict', label: t('settings.killSwitchStrict') }
  ]

  const typeOptions = [
    { value: 'app', label: t('killSwitch.typeApp') },
    { value: 'ip', label: t('killSwitch.typeIp') }
  ]

  if (loading) {
    return (
      <MacCard>
        <div className="flex items-center gap-2 text-[var(--color-text-secondary)]">
          <Shield size={18} />
          <span className="text-sm">{t('common.loading')}</span>
        </div>
      </MacCard>
    )
  }

  return (
    <div className="space-y-4">
      {/* Level Selector */}
      <MacCard>
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Shield size={18} className="text-[var(--color-accent)]" />
            <h3 className="text-sm font-semibold text-[var(--color-text)]">
              {t('settings.killSwitch')}
            </h3>
          </div>
          <p className="text-xs text-[var(--color-text-secondary)]">
            {t('settings.killSwitchDescription')}
          </p>
          <MacSegmentedControl
            options={levelOptions}
            value={level}
            onChange={handleLevelChange}
            className="w-full"
          />
          <motion.div
            key={level}
            initial={{ opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.2 }}
            className="mt-3 p-3 rounded-[var(--radius-sm)] bg-[var(--color-bg)] border border-[var(--color-border)]"
          >
            <p className="text-xs text-[var(--color-text-secondary)]">
              {level === 'off' && t('onboarding.killSwitchOffDesc')}
              {level === 'standard' && t('onboarding.killSwitchStandardDesc')}
              {level === 'strict' && t('onboarding.killSwitchStrictDesc')}
            </p>
          </motion.div>
        </div>
      </MacCard>

      {/* Exceptions List */}
      <MacCard>
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-[var(--color-text)]">
            {t('killSwitch.exceptions')}
          </h3>
          <p className="text-xs text-[var(--color-text-secondary)]">
            {t('killSwitch.exceptionsDescription')}
          </p>

          {exceptions.length === 0 ? (
            <p className="text-xs text-[var(--color-text-secondary)] italic py-2">
              {t('killSwitch.noExceptions')}
            </p>
          ) : (
            <div className="space-y-2">
              {exceptions.map((exception) => (
                <div
                  key={exception.id}
                  className="flex items-center gap-3 p-2.5 rounded-[var(--radius-sm)] bg-[var(--color-bg)] border border-[var(--color-border)]"
                >
                  <span className="text-xs font-medium px-1.5 py-0.5 rounded bg-[var(--color-accent)]/10 text-[var(--color-accent)] uppercase">
                    {exception.type}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-[var(--color-text)] truncate">
                      {exception.label}
                    </p>
                    <p className="text-xs text-[var(--color-text-secondary)] truncate">
                      {exception.value}
                    </p>
                  </div>
                  <MacButton
                    variant="ghost"
                    size="sm"
                    onClick={() => handleRemoveException(exception.id)}
                    aria-label={t('common.remove')}
                  >
                    <Trash2 size={14} className="text-[var(--color-danger)]" />
                  </MacButton>
                </div>
              ))}
            </div>
          )}
        </div>
      </MacCard>

      {/* Add Exception Form */}
      <MacCard>
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-[var(--color-text)]">
            {t('killSwitch.addException')}
          </h3>

          <MacSelect
            options={typeOptions}
            value={newType}
            onChange={(v) => setNewType(v as 'app' | 'ip')}
            label={t('killSwitch.exceptionType')}
          />

          <div className="flex items-end gap-2">
            <div className="flex-1">
              <MacInput
                label={t('killSwitch.exceptionValue')}
                placeholder={
                  newType === 'app'
                    ? t('killSwitch.valuePlaceholderApp')
                    : t('killSwitch.valuePlaceholderIp')
                }
                value={newValue}
                onChange={(e) => setNewValue(e.target.value)}
              />
            </div>
            {newType === 'app' && (
              <MacButton
                variant="secondary"
                size="md"
                onClick={handleBrowseApp}
                aria-label={t('killSwitch.browseApp')}
                title={t('killSwitch.browseApp')}
              >
                <FolderOpen size={16} />
              </MacButton>
            )}
          </div>

          <MacInput
            label={t('killSwitch.exceptionLabel')}
            placeholder={t('killSwitch.labelPlaceholder')}
            value={newLabel}
            onChange={(e) => setNewLabel(e.target.value)}
          />

          <MacButton
            variant="primary"
            size="md"
            onClick={handleAddException}
            disabled={!newValue.trim() || adding}
            loading={adding}
          >
            <Plus size={14} className="mr-1.5" />
            {t('common.add')}
          </MacButton>
        </div>
      </MacCard>
    </div>
  )
}
