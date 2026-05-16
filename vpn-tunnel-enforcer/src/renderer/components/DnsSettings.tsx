/**
 * DnsSettings — Settings UI for DNS profiles management.
 *
 * Shows:
 * 1. List of all DNS profiles (builtin + custom) with radio selection for active profile
 * 2. Type badge (Plain/DoH/DoT) for each profile using MacBadge
 * 3. "Create Custom" form with name, primary DNS, secondary DNS inputs
 * 4. Inline validation errors on DNS inputs (calls 'dns:validate' IPC on blur)
 * 5. Delete button for custom profiles (not builtin)
 *
 * Uses: MacCard, MacInput, MacButton, MacBadge from design-system
 * Uses: i18n translations from settings.dns* keys
 *
 * IPC calls: 'dns:list', 'dns:create', 'dns:delete', 'dns:select', 'dns:validate'
 *
 * Validates: Requirements 13.1, 13.2, 13.5
 */

import React, { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Globe, Trash2, Plus, CheckCircle2 } from 'lucide-react'
import { MacCard } from '../design-system/MacCard'
import { MacInput } from '../design-system/MacInput'
import { MacButton } from '../design-system/MacButton'
import { MacBadge } from '../design-system/MacBadge'
import type { DnsProfile } from '../../shared/ipc-types'

/** Maps DNS type to badge variant */
function typeBadgeVariant(type: DnsProfile['type']): 'info' | 'success' | 'warning' {
  switch (type) {
    case 'doh':
      return 'success'
    case 'dot':
      return 'warning'
    default:
      return 'info'
  }
}

/** Maps DNS type to display label */
function typeBadgeLabel(type: DnsProfile['type'], t: (key: string) => string): string {
  switch (type) {
    case 'doh':
      return t('settings.dnsTypeDoh')
    case 'dot':
      return t('settings.dnsTypeDot')
    default:
      return t('settings.dnsTypePlain')
  }
}

export const DnsSettings: React.FC = () => {
  const { t } = useTranslation()

  // State
  const [profiles, setProfiles] = useState<DnsProfile[]>([])
  const [activeId, setActiveId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  // Create form state
  const [formName, setFormName] = useState('')
  const [formPrimary, setFormPrimary] = useState('')
  const [formSecondary, setFormSecondary] = useState('')
  const [primaryError, setPrimaryError] = useState('')
  const [secondaryError, setSecondaryError] = useState('')
  const [creating, setCreating] = useState(false)

  // Load profiles from main process
  const loadProfiles = useCallback(async () => {
    try {
      const list = await window.electronAPI.dnsList()
      setProfiles(list)
      // Determine active profile from the list (the one that was selected)
      // We'll track it locally after selection
    } catch (err) {
      console.error('Failed to load DNS profiles:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadProfiles()
  }, [loadProfiles])

  // Handle profile selection
  const handleSelect = async (id: string) => {
    setActiveId(id)
    try {
      await window.electronAPI.dnsSelect(id)
    } catch (err) {
      console.error('Failed to select DNS profile:', err)
      setActiveId(null)
    }
  }

  // Validate DNS address on blur
  const handleValidatePrimary = async () => {
    if (!formPrimary.trim()) {
      setPrimaryError('')
      return
    }
    try {
      const result = await window.electronAPI.dnsValidate(formPrimary.trim())
      if (!result.valid) {
        setPrimaryError(result.error || t('settings.dnsInvalidAddress'))
      } else {
        setPrimaryError('')
      }
    } catch (err) {
      setPrimaryError(t('settings.dnsInvalidAddress'))
    }
  }

  const handleValidateSecondary = async () => {
    if (!formSecondary.trim()) {
      setSecondaryError('')
      return
    }
    try {
      const result = await window.electronAPI.dnsValidate(formSecondary.trim())
      if (!result.valid) {
        setSecondaryError(result.error || t('settings.dnsInvalidAddress'))
      } else {
        setSecondaryError('')
      }
    } catch (err) {
      setSecondaryError(t('settings.dnsInvalidAddress'))
    }
  }

  // Handle create custom profile
  const handleCreate = async () => {
    if (!formName.trim() || !formPrimary.trim()) return
    if (primaryError || secondaryError) return

    setCreating(true)
    try {
      // Validate primary before creating
      const primaryResult = await window.electronAPI.dnsValidate(formPrimary.trim())
      if (!primaryResult.valid) {
        setPrimaryError(primaryResult.error || t('settings.dnsInvalidAddress'))
        setCreating(false)
        return
      }

      // Validate secondary if provided
      let secondaryType: 'plain' | 'doh' | 'dot' = 'plain'
      if (formSecondary.trim()) {
        const secondaryResult = await window.electronAPI.dnsValidate(formSecondary.trim())
        if (!secondaryResult.valid) {
          setSecondaryError(secondaryResult.error || t('settings.dnsInvalidAddress'))
          setCreating(false)
          return
        }
        secondaryType = secondaryResult.type
      }

      const newProfile = await window.electronAPI.dnsCreate({
        name: formName.trim(),
        primary: formPrimary.trim(),
        secondary: formSecondary.trim(),
        type: primaryResult.type
      })

      setProfiles((prev) => [...prev, newProfile])
      // Reset form
      setFormName('')
      setFormPrimary('')
      setFormSecondary('')
      setPrimaryError('')
      setSecondaryError('')
    } catch (err) {
      console.error('Failed to create DNS profile:', err)
    } finally {
      setCreating(false)
    }
  }

  // Handle delete custom profile
  const handleDelete = async (id: string) => {
    try {
      await window.electronAPI.dnsDelete(id)
      setProfiles((prev) => prev.filter((p) => p.id !== id))
      if (activeId === id) {
        setActiveId(null)
      }
    } catch (err) {
      console.error('Failed to delete DNS profile:', err)
    }
  }

  if (loading) {
    return (
      <MacCard>
        <div className="flex items-center gap-2 text-[var(--color-text-secondary)]">
          <Globe size={18} />
          <span className="text-sm">{t('common.loading')}</span>
        </div>
      </MacCard>
    )
  }

  return (
    <div className="space-y-4">
      {/* Profile List & Selector */}
      <MacCard>
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Globe size={18} className="text-[var(--color-accent)]" />
            <h3 className="text-sm font-semibold text-[var(--color-text)]">
              {t('settings.dns')}
            </h3>
          </div>
          <p className="text-xs text-[var(--color-text-secondary)]">
            {t('settings.dnsDescription')}
          </p>

          {/* Profile list */}
          <div className="space-y-2">
            {profiles.map((profile) => (
              <div
                key={profile.id}
                onClick={() => handleSelect(profile.id)}
                className={`flex items-center gap-3 p-3 rounded-[var(--radius-sm)] border cursor-pointer transition-all duration-[var(--transition-fast)] ${
                  activeId === profile.id
                    ? 'border-[var(--color-accent)] bg-[var(--color-accent)]/5'
                    : 'border-[var(--color-border)] bg-[var(--color-bg)] hover:border-[var(--color-accent)]/40'
                }`}
                role="radio"
                aria-checked={activeId === profile.id}
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    handleSelect(profile.id)
                  }
                }}
              >
                {/* Selection indicator */}
                <div
                  className={`w-4 h-4 rounded-full border-2 flex items-center justify-center flex-shrink-0 ${
                    activeId === profile.id
                      ? 'border-[var(--color-accent)]'
                      : 'border-[var(--color-border)]'
                  }`}
                >
                  {activeId === profile.id && (
                    <div className="w-2 h-2 rounded-full bg-[var(--color-accent)]" />
                  )}
                </div>

                {/* Profile info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-[var(--color-text)] truncate">
                      {profile.name}
                    </span>
                    <MacBadge variant={typeBadgeVariant(profile.type)}>
                      {typeBadgeLabel(profile.type, t)}
                    </MacBadge>
                    {profile.isBuiltin && (
                      <MacBadge variant="neutral">
                        {t('settings.dnsBuiltin')}
                      </MacBadge>
                    )}
                  </div>
                  <p className="text-xs text-[var(--color-text-secondary)] mt-0.5 truncate">
                    {profile.primary}
                    {profile.secondary ? ` / ${profile.secondary}` : ''}
                  </p>
                </div>

                {/* Delete button for custom profiles */}
                {!profile.isBuiltin && (
                  <MacButton
                    variant="ghost"
                    size="sm"
                    onClick={(e) => {
                      e.stopPropagation()
                      handleDelete(profile.id)
                    }}
                    aria-label={t('settings.dnsDelete')}
                    title={t('settings.dnsDelete')}
                  >
                    <Trash2 size={14} className="text-[var(--color-danger)]" />
                  </MacButton>
                )}
              </div>
            ))}

            {profiles.length === 0 && (
              <p className="text-xs text-[var(--color-text-secondary)] italic py-2">
                {t('settings.dnsNoProfile')}
              </p>
            )}
          </div>
        </div>
      </MacCard>

      {/* Create Custom Profile Form */}
      <MacCard>
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-[var(--color-text)]">
            {t('settings.dnsCreateCustom')}
          </h3>

          <MacInput
            label={t('settings.dnsProfileName')}
            placeholder={t('settings.dnsProfileNamePlaceholder')}
            value={formName}
            onChange={(e) => setFormName(e.target.value)}
          />

          <MacInput
            label={t('settings.dnsPrimary')}
            placeholder={t('settings.dnsPrimaryPlaceholder')}
            value={formPrimary}
            onChange={(e) => {
              setFormPrimary(e.target.value)
              if (primaryError) setPrimaryError('')
            }}
            onBlur={handleValidatePrimary}
            error={primaryError}
          />

          <MacInput
            label={t('settings.dnsSecondary')}
            placeholder={t('settings.dnsSecondaryPlaceholder')}
            value={formSecondary}
            onChange={(e) => {
              setFormSecondary(e.target.value)
              if (secondaryError) setSecondaryError('')
            }}
            onBlur={handleValidateSecondary}
            error={secondaryError}
          />

          <MacButton
            variant="primary"
            size="md"
            onClick={handleCreate}
            disabled={!formName.trim() || !formPrimary.trim() || !!primaryError || !!secondaryError || creating}
            loading={creating}
          >
            <Plus size={14} className="mr-1.5" />
            {t('settings.dnsCreate')}
          </MacButton>
        </div>
      </MacCard>
    </div>
  )
}
