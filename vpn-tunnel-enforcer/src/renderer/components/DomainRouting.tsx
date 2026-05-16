import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import { Globe, Plus, Upload, RotateCcw, Pencil, Trash2, X, Check } from 'lucide-react'
import { MacCard, MacButton, MacInput, MacSelect, MacBadge, MacDragList } from '../design-system'
import type { DragItem } from '../design-system/MacDragList'

type DomainAction = 'vpn' | 'direct' | 'block'

interface DomainRule {
  id: string
  pattern: string
  action: DomainAction
  priority: number
  hitCount: number
}

type DomainRuleDragItem = DomainRule & DragItem

const ACTION_OPTIONS = [
  { value: 'vpn', label: 'VPN' },
  { value: 'direct', label: 'Direct' },
  { value: 'block', label: 'Block' }
]

function getActionBadgeVariant(action: DomainAction) {
  switch (action) {
    case 'vpn':
      return 'info'
    case 'direct':
      return 'success'
    case 'block':
      return 'danger'
  }
}

export function DomainRouting() {
  const { t } = useTranslation()
  const [rules, setRules] = useState<DomainRule[]>([])
  const [loading, setLoading] = useState(true)
  const [showAddForm, setShowAddForm] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [formPattern, setFormPattern] = useState('')
  const [formAction, setFormAction] = useState<DomainAction>('vpn')
  const [formError, setFormError] = useState('')

  const loadRules = useCallback(async () => {
    try {
      const data = await window.electronAPI.domainRoutingList()
      setRules(data.sort((a: DomainRule, b: DomainRule) => a.priority - b.priority))
    } catch (err) {
      console.error('Failed to load domain rules:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadRules()
  }, [loadRules])

  const handleReorder = async (reordered: DomainRuleDragItem[]) => {
    setRules(reordered)
    try {
      const ids = reordered.map((r) => r.id)
      const updated = await window.electronAPI.domainRoutingReorder(ids)
      setRules(updated.sort((a: DomainRule, b: DomainRule) => a.priority - b.priority))
    } catch (err) {
      console.error('Failed to reorder rules:', err)
      loadRules()
    }
  }

  const handleAdd = async () => {
    const trimmed = formPattern.trim()
    if (!trimmed) {
      setFormError(t('common.error'))
      return
    }
    setFormError('')
    try {
      await window.electronAPI.domainRoutingAdd({
        pattern: trimmed,
        action: formAction,
        priority: rules.length
      })
      setFormPattern('')
      setFormAction('vpn')
      setShowAddForm(false)
      loadRules()
    } catch (err) {
      console.error('Failed to add rule:', err)
      setFormError(String(err))
    }
  }

  const handleEdit = async (id: string) => {
    const trimmed = formPattern.trim()
    if (!trimmed) {
      setFormError(t('common.error'))
      return
    }
    setFormError('')
    try {
      await window.electronAPI.domainRoutingUpdate(id, {
        pattern: trimmed,
        action: formAction
      })
      setEditingId(null)
      setFormPattern('')
      setFormAction('vpn')
      loadRules()
    } catch (err) {
      console.error('Failed to update rule:', err)
      setFormError(String(err))
    }
  }

  const handleDelete = async (id: string) => {
    try {
      await window.electronAPI.domainRoutingDelete(id)
      loadRules()
    } catch (err) {
      console.error('Failed to delete rule:', err)
    }
  }

  const handleImport = async () => {
    try {
      const filePath = await window.electronAPI.domainRoutingBrowseFile()
      if (!filePath) return
      await window.electronAPI.domainRoutingImport(filePath)
      loadRules()
    } catch (err) {
      console.error('Failed to import domain list:', err)
    }
  }

  const handleResetHits = async () => {
    try {
      await window.electronAPI.domainRoutingResetHits()
      loadRules()
    } catch (err) {
      console.error('Failed to reset hits:', err)
    }
  }

  const startEdit = (rule: DomainRule) => {
    setEditingId(rule.id)
    setFormPattern(rule.pattern)
    setFormAction(rule.action)
    setFormError('')
    setShowAddForm(false)
  }

  const cancelEdit = () => {
    setEditingId(null)
    setFormPattern('')
    setFormAction('vpn')
    setFormError('')
  }

  const startAdd = () => {
    setShowAddForm(true)
    setEditingId(null)
    setFormPattern('')
    setFormAction('vpn')
    setFormError('')
  }

  const cancelAdd = () => {
    setShowAddForm(false)
    setFormPattern('')
    setFormAction('vpn')
    setFormError('')
  }

  const getActionLabel = (action: DomainAction) => {
    switch (action) {
      case 'vpn':
        return t('domainRouting.actionVpn')
      case 'direct':
        return t('domainRouting.actionDirect')
      case 'block':
        return t('domainRouting.actionBlock')
    }
  }

  const renderRuleItem = (rule: DomainRuleDragItem) => {
    if (editingId === rule.id) {
      return (
        <div className="flex items-center gap-3 py-2 pr-3">
          <div className="flex-1 min-w-0">
            <MacInput
              value={formPattern}
              onChange={(e) => setFormPattern(e.target.value)}
              placeholder={t('domainRouting.patternPlaceholder')}
              error={formError}
            />
          </div>
          <div className="w-32 shrink-0">
            <MacSelect
              options={ACTION_OPTIONS.map((o) => ({
                ...o,
                label: getActionLabel(o.value as DomainAction)
              }))}
              value={formAction}
              onChange={(v) => setFormAction(v as DomainAction)}
            />
          </div>
          <MacButton size="sm" variant="primary" onClick={() => handleEdit(rule.id)}>
            <Check size={14} />
          </MacButton>
          <MacButton size="sm" variant="ghost" onClick={cancelEdit}>
            <X size={14} />
          </MacButton>
        </div>
      )
    }

    return (
      <div className="flex items-center gap-3 py-2 pr-3">
        <div className="flex-1 min-w-0">
          <span className="text-sm font-medium text-[var(--color-text)] truncate block">
            {rule.pattern}
          </span>
        </div>
        <MacBadge variant={getActionBadgeVariant(rule.action)}>
          {getActionLabel(rule.action)}
        </MacBadge>
        <span className="text-xs text-[var(--color-text-secondary)] w-8 text-center shrink-0">
          #{rule.priority + 1}
        </span>
        <span className="text-xs text-[var(--color-text-secondary)] w-12 text-right shrink-0">
          {rule.hitCount} {t('domainRouting.hitCount').toLowerCase()}
        </span>
        <div className="flex items-center gap-1 shrink-0">
          <MacButton size="sm" variant="ghost" onClick={() => startEdit(rule)}>
            <Pencil size={14} />
          </MacButton>
          <MacButton size="sm" variant="ghost" onClick={() => handleDelete(rule.id)}>
            <Trash2 size={14} />
          </MacButton>
        </div>
      </div>
    )
  }

  return (
    <MacCard className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-[var(--color-accent)]" />
          <h3 className="text-sm font-semibold text-[var(--color-text)] uppercase tracking-wider">
            {t('domainRouting.title')}
          </h3>
        </div>
        <div className="flex items-center gap-2">
          <MacButton size="sm" variant="ghost" onClick={handleResetHits} title={t('domainRouting.resetHits')}>
            <RotateCcw size={14} />
          </MacButton>
          <MacButton size="sm" variant="secondary" onClick={handleImport}>
            <Upload size={14} className="mr-1" />
            {t('domainRouting.import')}
          </MacButton>
          <MacButton size="sm" variant="primary" onClick={startAdd}>
            <Plus size={14} className="mr-1" />
            {t('domainRouting.addRule')}
          </MacButton>
        </div>
      </div>

      <p className="text-xs text-[var(--color-text-secondary)]">
        {t('domainRouting.description')}
      </p>

      {showAddForm && (
        <div className="flex items-start gap-3 p-3 rounded-[var(--radius-sm)] border border-[var(--color-border)] bg-[var(--color-bg)]">
          <div className="flex-1 min-w-0">
            <MacInput
              value={formPattern}
              onChange={(e) => setFormPattern(e.target.value)}
              placeholder={t('domainRouting.patternPlaceholder')}
              hint={t('domainRouting.patternHint')}
              error={formError}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleAdd()
                if (e.key === 'Escape') cancelAdd()
              }}
            />
          </div>
          <div className="w-32 shrink-0">
            <MacSelect
              options={ACTION_OPTIONS.map((o) => ({
                ...o,
                label: getActionLabel(o.value as DomainAction)
              }))}
              value={formAction}
              onChange={(v) => setFormAction(v as DomainAction)}
            />
          </div>
          <MacButton size="sm" variant="primary" onClick={handleAdd}>
            <Check size={14} />
          </MacButton>
          <MacButton size="sm" variant="ghost" onClick={cancelAdd}>
            <X size={14} />
          </MacButton>
        </div>
      )}

      {loading ? (
        <p className="text-sm text-[var(--color-text-secondary)]">{t('common.loading')}</p>
      ) : rules.length === 0 ? (
        <p className="text-sm text-[var(--color-text-secondary)] text-center py-6">
          {t('domainRouting.noRules')}
        </p>
      ) : (
        <MacDragList
          items={rules as DomainRuleDragItem[]}
          onReorder={handleReorder}
          renderItem={renderRuleItem}
        />
      )}

      {rules.length > 0 && (
        <p className="text-xs text-[var(--color-text-secondary)] italic">
          {t('domainRouting.dragHint')}
        </p>
      )}
    </MacCard>
  )
}
