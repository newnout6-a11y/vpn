import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Download, Upload, CheckCircle2, AlertTriangle } from 'lucide-react'
import { MacCard, MacButton, MacModal } from '../design-system'
import type { ElectronAPI } from '../../shared/electron-api'
import { ipcError, isIpcRemoteErrorData } from '../../shared/ipc-result'

type ConflictResolution = 'replace' | 'merge'

type ConfigApi = Pick<ElectronAPI, 'configExport' | 'configBrowseImport' | 'configImport' | 'configImportApply' | 'configCancel'>
type ValidationResult = Awaited<ReturnType<ConfigApi['configImport']>> & { filePath: string; requestId: string }

function getApi(): ConfigApi {
  return window.electronAPI
}

const SECTION_KEYS: Record<string, string> = {
  profiles: 'sectionProfiles',
  schedules: 'sectionSchedules',
  splitTunnel: 'sectionSplitTunnel',
  dns: 'sectionDns',
  domainRouting: 'sectionDomainRouting',
  themes: 'sectionThemes',
  rotation: 'sectionRotation',
  killSwitch: 'sectionKillSwitch',
  notifications: 'sectionNotifications'
}

export function ImportExportSettings() {
  const { t, i18n } = useTranslation()
  const mounted = useRef(false)
  const requests = useRef(new Set<string>())
  const timers = useRef(new Map<string, ReturnType<typeof setTimeout>>())
  const current = (id: string) => mounted.current && requests.current.has(id)
  const beginRequest = () => {
    const id = crypto.randomUUID()
    requests.current.add(id)
    return id
  }
  const cancelRequest = (id: string) => {
    requests.current.delete(id)
    void getApi().configCancel(id).catch(() => {})
  }
  const flash = (kind: string, update: (value: boolean) => void) => {
    clearTimeout(timers.current.get(kind))
    update(true)
    timers.current.set(kind, setTimeout(() => {
      timers.current.delete(kind)
      if (mounted.current) update(false)
    }, 3000))
  }
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
      for (const id of requests.current) void getApi().configCancel(id).catch(() => {})
      requests.current.clear()
      for (const timer of timers.current.values()) clearTimeout(timer)
      timers.current.clear()
    }
  }, [])

  const [exporting, setExporting] = useState(false)
  const [exportSuccess, setExportSuccess] = useState(false)
  const [importing, setImporting] = useState(false)
  const [applying, setApplying] = useState(false)

  // Validation state
  const [validation, setValidation] = useState<ValidationResult | null>(null)
  const [selectedSections, setSelectedSections] = useState<string[]>([])
  const [conflictResolution, setConflictResolution] = useState<ConflictResolution>('replace')

  // Error modal
  const [errorModal, setErrorModal] = useState<{ open: boolean; message: string }>({
    open: false,
    message: ''
  })

  // Success state for import
  const [importSuccess, setImportSuccess] = useState(false)
  const showError = (error: unknown) => setErrorModal({ open: true, message:
    isIpcRemoteErrorData(error) ? error.message : ipcError('internal', i18n?.language?.startsWith('ru') ? 'ru' : 'en').message
  })

  const getSectionLabel = (section: string): string => {
    const key = SECTION_KEYS[section]
    return key ? t(`settings.${key}`) : section
  }

  const handleExport = async (mode: 'redacted' | 'secrets' = 'redacted') => {
    if (exporting) return
    const requestId = beginRequest()
    setExporting(true)
    setExportSuccess(false)
    try {
      await getApi().configExport(mode, requestId)
      if (current(requestId)) flash('export', setExportSuccess)
    } catch (err: unknown) {
      if (current(requestId) && (!isIpcRemoteErrorData(err) || err.category !== 'cancelled')) showError(err)
    } finally {
      if (current(requestId)) setExporting(false)
      requests.current.delete(requestId)
    }
  }

  const handleImport = async () => {
    if (importing || (validation && current(validation.requestId))) return
    const requestId = beginRequest()
    let retainSelection = false
    setImporting(true)
    setValidation(null)
    setImportSuccess(false)
    try {
      const filePath = await getApi().configBrowseImport(requestId)
      if (!current(requestId)) return
      if (!filePath) {
        setImporting(false)
        return
      }

      const result = await getApi().configImport(filePath, requestId)
      if (!current(requestId)) return
      retainSelection = true
      // Show validation results with sections and conflicts
      setValidation({
        ...result,
        filePath, requestId
      })
      setSelectedSections([...result.sections])
      setConflictResolution('replace')
    } catch (err: unknown) {
      if (current(requestId) && (!isIpcRemoteErrorData(err) || err.category !== 'cancelled')) showError(err)
    } finally {
      if (current(requestId)) {
        setImporting(false)
        if (!retainSelection) cancelRequest(requestId)
      }
    }
  }

  const handleApplyImport = async () => {
    if (!validation || applying || !current(validation.requestId)) return
    const { requestId } = validation

    setApplying(true)
    try {
      await getApi().configImportApply(
        validation.filePath,
        selectedSections,
        conflictResolution,
        requestId
      )
      if (!current(requestId)) return
      flash('import', setImportSuccess)
      setValidation(null)
    } catch (err: unknown) {
      if (current(requestId) && (!isIpcRemoteErrorData(err) || err.category !== 'cancelled')) showError(err)
    } finally {
      // Main consumes the snapshot even on failure. Keep choices for inspection;
      // the user can select a fresh file, but cannot retry the consumed token.
      if (current(requestId)) setApplying(false)
      requests.current.delete(requestId)
    }
  }

  const handleCancelImport = () => {
    if (validation) cancelRequest(validation.requestId)
    setValidation(null)
    setSelectedSections([])
  }

  const toggleSection = (section: string) => {
    setSelectedSections((prev) =>
      prev.includes(section) ? prev.filter((s) => s !== section) : [...prev, section]
    )
  }

  return (
    <>
      <MacCard>
        <div className="space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-[var(--color-text)] uppercase tracking-wider flex items-center gap-2">
              <Download className="w-4 h-4 text-[var(--color-accent)]" />
              {t('settings.importExport')}
            </h3>
            <p className="text-xs text-[var(--color-text-secondary)] mt-1">
              {t('settings.importExportDescription')}
            </p>
          </div>

          {/* Export / Import buttons */}
          <div className="flex flex-wrap gap-3">
            <MacButton
              variant="secondary"
              onClick={() => handleExport()}
              loading={exporting}
              disabled={exporting}
            >
              <Download className="w-4 h-4 mr-2" />
              {exportSuccess ? (
                <span className="flex items-center gap-1">
                  <CheckCircle2 className="w-4 h-4 text-green-500" />
                  {t('settings.exportSuccess')}
                </span>
              ) : (
                t('settings.exportSettings')
              )}
            </MacButton>

            <MacButton
              variant="secondary"
              onClick={() => handleExport('secrets')}
              disabled={exporting}
              aria-busy={exporting}
            >
              {t('settings.exportSettingsWithSecrets')}
            </MacButton>

            <MacButton
              variant="secondary"
              onClick={handleImport}
              loading={importing}
              disabled={importing || (!!validation && current(validation.requestId))}
            >
              <Upload className="w-4 h-4 mr-2" />
              {importSuccess ? (
                <span className="flex items-center gap-1">
                  <CheckCircle2 className="w-4 h-4 text-green-500" />
                  {t('settings.importSuccess')}
                </span>
              ) : (
                t('settings.importSettings')
              )}
            </MacButton>
          </div>

          {/* Validation results panel */}
          {validation && (
            <div className="border border-[var(--color-border)] rounded-[var(--radius-sm)] p-4 space-y-4">
              <h4 className="text-sm font-medium text-[var(--color-text)]">
                {t('settings.importSections')}
              </h4>

              {/* Section checkboxes */}
              <div className="grid grid-cols-2 gap-2">
                {validation.sections.map((section) => (
                  <label
                    key={section}
                    className="flex items-center gap-2 text-sm text-[var(--color-text)] cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={selectedSections.includes(section)}
                      onChange={() => toggleSection(section)}
                      className="rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)]"
                    />
                    <span>{getSectionLabel(section)}</span>
                    {validation.conflicts.includes(section) && (
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                    )}
                  </label>
                ))}
              </div>

              {/* Conflicts section */}
              {validation.conflicts.length > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-500" />
                    <h4 className="text-sm font-medium text-amber-500">
                      {t('settings.importConflicts')}
                    </h4>
                  </div>
                  <p className="text-xs text-[var(--color-text-secondary)]">
                    {t('settings.importConflictsDescription')}
                  </p>

                  {/* Conflict resolution selector */}
                  <div className="flex gap-3">
                    <label className="flex items-center gap-2 text-sm text-[var(--color-text)] cursor-pointer">
                      <input
                        type="radio"
                        name="conflictResolution"
                        value="replace"
                        checked={conflictResolution === 'replace'}
                        onChange={() => setConflictResolution('replace')}
                        className="text-[var(--color-accent)] focus:ring-[var(--color-accent)]"
                      />
                      {t('settings.conflictReplace')}
                    </label>
                    <label className="flex items-center gap-2 text-sm text-[var(--color-text)] cursor-pointer">
                      <input
                        type="radio"
                        name="conflictResolution"
                        value="merge"
                        checked={conflictResolution === 'merge'}
                        onChange={() => setConflictResolution('merge')}
                        className="text-[var(--color-accent)] focus:ring-[var(--color-accent)]"
                      />
                      {t('settings.conflictMerge')}
                    </label>
                  </div>
                </div>
              )}

              {/* Action buttons */}
              <div className="flex gap-2 pt-2">
                <MacButton
                  variant="primary"
                  onClick={handleApplyImport}
                  loading={applying}
                  disabled={applying || selectedSections.length === 0 || !current(validation.requestId)}
                >
                  {t('settings.applyImport')}
                </MacButton>
                <MacButton variant="ghost" onClick={handleCancelImport} disabled={applying}>
                  {t('common.cancel')}
                </MacButton>
              </div>
            </div>
          )}
        </div>
      </MacCard>

      {/* Error Modal */}
      <MacModal
        open={errorModal.open}
        onClose={() => setErrorModal({ open: false, message: '' })}
        title={t('settings.importError')}
        size="sm"
        footer={
          <MacButton variant="primary" onClick={() => setErrorModal({ open: false, message: '' })}>
            {t('common.ok')}
          </MacButton>
        }
      >
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
          <p className="text-sm text-[var(--color-text)]">{errorModal.message}</p>
        </div>
      </MacModal>
    </>
  )
}
