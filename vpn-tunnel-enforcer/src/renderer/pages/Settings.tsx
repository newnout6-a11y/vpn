import { useAppStore } from '../store'
import { Bell, EyeOff, FileArchive, FolderOpen, Globe2, Loader2, Network, Palette, RefreshCw, Save, Settings2, ShieldAlert, ShieldCheck, Wand2, Languages } from 'lucide-react'
import { ReactNode, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { KillSwitchSettings } from '../components/KillSwitchSettings'
import { RotationSettings } from '../components/RotationSettings'
import { DnsSettings } from '../components/DnsSettings'
import { DomainRouting } from '../components/DomainRouting'
import { ImportExportSettings } from '../components/ImportExportSettings'
import { NotificationSettings } from '../components/NotificationSettings'
import { MacCard } from '../design-system/MacCard'
import { MacSelect } from '../design-system/MacSelect'
import { MacSegmentedControl } from '../design-system/MacSegmentedControl'
import { MacSwitch } from '../design-system/MacSwitch'
import { useTheme } from '../providers/ThemeProvider'
import { navigateTo } from '../nav'

interface ToggleRowProps {
  title: ReactNode
  description: ReactNode
  checked: boolean
  onChange: (next: boolean) => void
  icon?: ReactNode
}

function ToggleRow({ title, description, checked, onChange, icon }: ToggleRowProps) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="flex-1">
        <p className="text-sm text-[var(--color-text)] flex items-center gap-2">
          {icon}
          {title}
        </p>
        <p className="text-xs text-[var(--color-text-secondary)] mt-1 leading-relaxed">{description}</p>
      </div>
      <MacSwitch checked={checked} onChange={onChange} />
    </div>
  )
}

/* ─── Language Selector Section ─────────────────────────────────────────────── */

function LanguageSettings() {
  const { t, i18n } = useTranslation()
  const [currentLocale, setCurrentLocale] = useState(i18n.language || 'en')

  const handleLocaleChange = async (locale: string) => {
    setCurrentLocale(locale)
    i18n.changeLanguage(locale)
    try {
      await (window as any).electronAPI?.i18nSetLocale?.(locale)
    } catch (err) {
      console.warn('[LanguageSettings] Failed to persist locale:', err)
    }
  }

  return (
    <MacCard>
      <div className="space-y-4">
        <h3 className="text-sm font-semibold text-[var(--color-text)] uppercase tracking-wider flex items-center gap-2">
          <Languages className="w-4 h-4 text-[var(--color-accent)]" />
          {t('settings.language')}
        </h3>
        <p className="text-xs text-[var(--color-text-secondary)]">
          {t('settings.languageDescription')}
        </p>
        <MacSelect
          options={[
            { value: 'en', label: 'English' },
            { value: 'ru', label: 'Русский' }
          ]}
          value={currentLocale}
          onChange={handleLocaleChange}
        />
      </div>
    </MacCard>
  )
}

/* ─── Theme Selector Section ────────────────────────────────────────────────── */

function ThemeSettings() {
  const { t } = useTranslation()
  const { theme, themes, setTheme } = useTheme()

  // Determine current mode for the segmented control
  const currentMode = theme?.mode || 'system'

  const handleModeChange = (mode: string) => {
    // Find a built-in theme matching the selected mode
    const target = themes.find(th => th.mode === mode && !th.isCustom)
    if (target) {
      setTheme(target.id)
    }
  }

  return (
    <MacCard>
      <div className="space-y-4">
        <h3 className="text-sm font-semibold text-[var(--color-text)] uppercase tracking-wider flex items-center gap-2">
          <Palette className="w-4 h-4 text-[var(--color-accent)]" />
          {t('settings.theme')}
        </h3>
        <p className="text-xs text-[var(--color-text-secondary)]">
          {t('settings.themeDescription')}
        </p>
        <MacSegmentedControl
          options={[
            { value: 'light', label: t('settings.themeLight') },
            { value: 'dark', label: t('settings.themeDark') },
            { value: 'system', label: t('settings.themeSystem') }
          ]}
          value={currentMode}
          onChange={handleModeChange}
        />
        {themes.filter(th => th.isCustom).length > 0 && (
          <div className="mt-3">
            <p className="text-xs text-[var(--color-text-secondary)] mb-2">{t('themes.custom')}</p>
            <div className="flex flex-wrap gap-2">
              {themes.filter(th => th.isCustom).map(th => (
                <button
                  key={th.id}
                  onClick={() => setTheme(th.id)}
                  className={`px-3 py-1.5 text-xs rounded-[var(--radius-sm)] border transition-all duration-[var(--transition-fast)] ${
                    theme?.id === th.id
                      ? 'border-[var(--color-accent)] bg-[var(--color-accent)]/10 text-[var(--color-accent)]'
                      : 'border-[var(--color-border)] text-[var(--color-text-secondary)] hover:border-[var(--color-accent)]/50'
                  }`}
                >
                  {th.name}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </MacCard>
  )
}

/* ─── Main Settings Page ────────────────────────────────────────────────────── */

export function Settings() {
  const { t } = useTranslation()
  const settings = useAppStore(s => s.settings)
  const updateSettings = useAppStore(s => s.updateSettings)
  const setSettings = useAppStore(s => s.setSettings)
  const setProxy = useAppStore(s => s.setProxy)
  const addLog = useAppStore(s => s.addLog)
  const [saved, setSaved] = useState(false)
  const [saving, setSaving] = useState(false)
  const [openingLogs, setOpeningLogs] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [osNotificationsBlocked, setOsNotificationsBlocked] = useState(false)

  useEffect(() => {
    ;(async () => {
      try {
        const state = await window.electronAPI.checkOsNotificationState()
        setOsNotificationsBlocked(!state.osNotificationsEnabled)
      } catch {
        // assume allowed
      }
    })()
  }, [])

  const handleSave = async () => {
    setSaving(true)
    try {
      const result = await window.electronAPI.saveSettings(settings)
      setSettings(result)
      const override = result.proxyOverride.trim()
      if (result.connectionMode !== 'directVpn' && override) {
        const separator = override.lastIndexOf(':')
        const host = override.slice(0, separator).trim()
        const port = parseInt(override.slice(separator + 1), 10)
        if (separator > 0 && host && Number.isInteger(port)) {
          setProxy({ host, port, type: result.proxyType, verified: true, publicIpViaProxy: null })
        }
      }
      setSaved(true)
      addLog('info', 'Настройки сохранены и применены к активной сессии')
      setTimeout(() => setSaved(false), 2000)
    } catch (err: any) {
      addLog('error', `Не удалось сохранить настройки: ${err.message}`)
    } finally {
      setSaving(false)
    }
  }

  const handleOpenLogs = async () => {
    setOpeningLogs(true)
    try {
      const folder = await window.electronAPI.openTunLogFolder()
      addLog('info', `Открыта папка логов: ${folder}`)
    } catch (err: any) {
      addLog('error', `Не удалось открыть папку логов: ${err.message}`)
    } finally {
      setOpeningLogs(false)
    }
  }

  const handleExportDiagnostics = async () => {
    setExporting(true)
    try {
      const result = await window.electronAPI.exportDiagnostics()
      if (result.cancelled) {
        addLog('info', 'Экспорт диагностики отменён.')
      } else if (result.success && result.path) {
        addLog('info', `Диагностика сохранена: ${result.path}`)
      } else {
        addLog('error', `Не удалось собрать диагностику: ${result.error || 'неизвестная ошибка'}`)
      }
    } catch (err: any) {
      addLog('error', `Ошибка экспорта диагностики: ${err.message}`)
    } finally {
      setExporting(false)
    }
  }

  const handleResetWizard = async () => {
    try {
      const result = await window.electronAPI.saveSettings({ firstRunComplete: false })
      setSettings(result)
      addLog('info', 'Мастер первого запуска будет показан при следующем открытии главной.')
    } catch (err: any) {
      addLog('error', `Не удалось сбросить мастер: ${err.message}`)
    }
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h2 className="text-2xl font-bold text-[var(--color-text)]">{t('settings.title')}</h2>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">Главные параметры защиты и поведения приложения</p>
      </div>

      {/* Section: Language */}
      <LanguageSettings />

      {/* Section: Theme */}
      <ThemeSettings />

      {/* Section: Connection */}
      <MacCard>
        <div className="space-y-5">
          <h3 className="text-sm font-semibold text-[var(--color-text)] uppercase tracking-wider flex items-center gap-2">
            <Network className="w-4 h-4 text-[var(--color-accent)]" />
            Подключение
          </h3>

          <div>
            <label className="block text-xs text-[var(--color-text-secondary)] mb-1.5">Источник VPN</label>
            <MacSelect
              options={[
                { value: 'localProxy', label: 'Локальный proxy-клиент (Happ / 127.0.0.1)' },
                { value: 'directVpn', label: 'Direct VPN ключ в VPNTE (без Happ)' }
              ]}
              value={settings.connectionMode}
              onChange={(val) => updateSettings({ connectionMode: val === 'directVpn' ? 'directVpn' : 'localProxy' })}
            />
            <p className="text-xs text-[var(--color-text-secondary)] mt-1">
              Direct VPN запускает наш sing-box напрямую к серверу и не использует правила маршрутизации Happ.
            </p>
          </div>

          {settings.connectionMode === 'directVpn' && (
            <div className="rounded-[var(--radius-sm)] border border-[var(--color-border)] bg-[var(--color-card)]/40 p-4 text-sm flex items-start gap-3">
              <Globe2 className="h-5 w-5 text-[var(--color-accent)] flex-shrink-0 mt-0.5" />
              <div className="flex-1 space-y-1">
                <p className="text-[var(--color-text)] font-medium">
                  VPN-серверы управляются в разделе «Серверы»
                </p>
                <p className="text-xs text-[var(--color-text-secondary)]">
                  Вставьте subscription URL или ключ протокола (vless://, trojan://, ss://,
                  vmess://, hysteria2://, happ://add/…) — список серверов сохранится автоматически.
                  При запуске будет использован выбранный там сервер.
                </p>
                <button
                  type="button"
                  onClick={() => navigateTo('servers')}
                  className="mt-1 inline-flex items-center gap-1 text-xs font-medium text-[var(--color-accent)] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-accent)] rounded"
                >
                  Открыть «Серверы» →
                </button>
              </div>
            </div>
          )}
        </div>
      </MacCard>

      {/* Section: Защита */}
      <MacCard>
        <div className="space-y-5">
          <h3 className="text-sm font-semibold text-[var(--color-text)] uppercase tracking-wider flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-green-500" />
            Защита
          </h3>

          {/* Read-only banner: surfaces the always-on adapter-disguise
              behaviour added in the disguise feature commit. No toggle —
              we want this on by default for everyone. */}
          <div className="rounded-[var(--radius-sm)] border border-[var(--color-border)] bg-[var(--color-bg)] p-3 flex gap-3">
            <EyeOff className="w-4 h-4 text-[var(--color-accent)] flex-shrink-0 mt-0.5" />
            <div className="text-xs text-[var(--color-text-secondary)] space-y-1">
              <p className="text-[var(--color-text)] font-medium">
                Другие программы не видят, что вы под VPN
              </p>
              <p>
                <span className="text-[var(--color-text-secondary)]">Сейчас:</span>{' '}
                игры, банковские клиенты и сайты часто отказываются работать,
                если замечают характерное «VPN-соединение» в системе.
              </p>
              <p>
                <span className="text-[var(--color-text-secondary)]">Станет:</span>{' '}
                ваш канал в системе выглядит как обычная домашняя сеть, без
                выпирающих VPN-меток. Большинство таких проверок не
                сработает.
              </p>
              <p className="text-[var(--color-text-muted)]">
                Работает автоматически при каждом включении защиты — отдельный
                переключатель не нужен.
              </p>
            </div>
          </div>

          <ToggleRow
            icon={<Network className="w-4 h-4 text-green-500" />}
            title={<>Жёсткая блокировка адаптеров <span className="text-green-500">(рекомендуется)</span></>}
            description={
              <>
                На всех физических адаптерах (Wi-Fi, Ethernet) пока работает защита: выключаем
                IPv6 и, если выключена совместимость с публичным Wi-Fi, форсируем DNS на TUN.
                Это закрывает утечки, которые kill-switch одного файрвола не ловит.
              </>
            }
            checked={settings.strictAdapterLockdown}
            onChange={(next) => updateSettings({ strictAdapterLockdown: next })}
          />

          <ToggleRow
            icon={<Network className="w-4 h-4 text-[var(--color-accent)]" />}
            title={<>Совместимость с публичным Wi-Fi <span className="text-[var(--color-accent)]">(меньше ломает интернет)</span></>}
            description={
              <>
                Оставляет DHCP/DNS физического адаптера как есть, чтобы captive portal и Windows не
                считали сеть «без интернета». Отключение IPv6 остается активным.
              </>
            }
            checked={settings.publicWifiCompatibility}
            onChange={(next) => updateSettings({ publicWifiCompatibility: next })}
          />

          <ToggleRow
            icon={<RefreshCw className="w-4 h-4 text-[var(--color-accent)]" />}
            title="Авто-перезапуск sing-box при крахе"
            description="Если процесс sing-box внезапно упадёт, попробуем перезапустить до 3 раз с экспоненциальной паузой."
            checked={settings.autoRestartOnCrash}
            onChange={(next) => updateSettings({ autoRestartOnCrash: next })}
          />

          <ToggleRow
            icon={
              <div className="relative">
                <Bell className="w-4 h-4 text-[var(--color-accent)]" />
                {osNotificationsBlocked && (
                  <ShieldAlert
                    size={10}
                    className="absolute -top-1 -right-1.5 text-[var(--color-warning)]"
                  />
                )}
              </div>
            }
            title={
              <span className="flex items-center gap-2">
                Уведомления Windows
                {osNotificationsBlocked && (
                  <span className="text-[var(--color-warning)] text-xs font-medium" title="Уведомления отключены в системе">
                    ⚠
                  </span>
                )}
              </span>
            }
            description={
              osNotificationsBlocked
                ? '⚠ Система блокирует уведомления для приложения. Включите: Параметры Windows → Система → Уведомления → VPN Tunnel Enforcer'
                : 'Показывать toast при включении защиты, падении sing-box, утечке IP.'
            }
            checked={settings.desktopNotifications}
            onChange={(next) => updateSettings({ desktopNotifications: next })}
          />

          <ToggleRow
            icon={<EyeOff className="w-4 h-4 text-[var(--color-warning)]" />}
            title={<>Невидимка против «фильтров» <span className="text-[var(--color-warning)]">(когда «режут» VPN)</span></>}
            description={
              <>
                <span className="block">
                  <span className="text-[var(--color-text-secondary)]">Сейчас:</span>{' '}
                  поток через защиту виден провайдеру как «типичный VPN»,
                  и его могут замедлять или резать пакетами.
                </span>
                <span className="block mt-1">
                  <span className="text-[var(--color-text-secondary)]">Станет:</span>{' '}
                  поток будет выглядеть «обычнее», и фильтрам сложнее его
                  опознать. Помогает, если страницы зависают, видео
                  тормозит или сайты грузятся «через раз», хотя интернет
                  вроде есть.
                </span>
                <span className="block mt-1 text-[var(--color-text-secondary)]">
                  Цена: пара процентов скорости и чуть более долгий первый
                  отклик. Изменения вступят в силу после следующего
                  включения защиты.
                </span>
              </>
            }
            checked={settings.stealthMode}
            onChange={(next) => updateSettings({ stealthMode: next })}
          />
        </div>
      </MacCard>

      {/* Section: Гранулярный Kill-Switch */}
      <KillSwitchSettings />

      {/* Section: Поведение приложения */}
      <MacCard>
        <div className="space-y-5">
          <h3 className="text-sm font-semibold text-[var(--color-text)] uppercase tracking-wider">Поведение</h3>

          <ToggleRow
            title="Автозапуск с Windows"
            description="Запускать приложение при входе в систему."
            checked={settings.autoStart}
            onChange={(next) => updateSettings({ autoStart: next })}
          />

          <ToggleRow
            title="Сворачивать в трей при закрытии"
            description="Кнопка X сворачивает в трей вместо выхода. Защита продолжает работать в фоне."
            checked={settings.minimizeToTray}
            onChange={(next) => updateSettings({ minimizeToTray: next })}
          />

          <ToggleRow
            title="Автопилот маршрута"
            description="При запуске сам решает: оставить как есть (если уже работает внешний VPN) или включить TUN."
            checked={settings.autoPilotEnabled}
            onChange={(next) => updateSettings({ autoPilotEnabled: next })}
          />

          <ToggleRow
            icon={<Globe2 className="w-4 h-4 text-[var(--color-accent)]" />}
            title="Скрывать местоположение Windows"
            description="Запрещает Windows-приложениям использовать геолокацию: при выключении VPN автоматически возвращается в исходное состояние, чтобы Карты, Погода и т.д. снова работали."
            checked={settings.locationPrivacyEnabled}
            onChange={async (next) => {
              try {
                if (next) {
                  const status = await window.electronAPI.applyLocationPrivacy()
                  updateSettings({ locationPrivacyEnabled: Boolean(status?.applied) })
                  addLog('info', 'Местоположение Windows ограничено. Откатим автоматически при выключении VPN.')
                } else {
                  const status = await window.electronAPI.rollbackLocationPrivacy()
                  updateSettings({ locationPrivacyEnabled: Boolean(status?.applied) })
                  addLog('info', 'Доступ к местоположению Windows восстановлен.')
                }
              } catch (err: any) {
                addLog('error', `Не удалось переключить настройку местоположения: ${err?.message ?? err}`)
              }
            }}
          />
        </div>
      </MacCard>

      {/* Section: Profile Rotation */}
      <RotationSettings />

      {/* Section: DNS Profiles */}
      <DnsSettings />

      {/* Section: Domain Routing */}
      <DomainRouting />

      {/* Section: Notification Settings */}
      <NotificationSettings />

      {/* Section: Import/Export */}
      <ImportExportSettings />

      {/* Section: Расширенный режим */}
      <MacCard>
        <div className="space-y-5">
          <ToggleRow
            icon={<Settings2 className="w-4 h-4 text-amber-500" />}
            title={<>Расширенный режим <span className="text-amber-500">(для опытных)</span></>}
            description="Открывает страницы Приложения и Диагностика, разрешает менять ручной адрес прокси и потенциально опасные параметры."
            checked={settings.advancedMode}
            onChange={(next) => updateSettings({ advancedMode: next })}
          />

          <ToggleRow
            icon={<Wand2 className="w-4 h-4 text-[var(--color-accent)]" />}
            title="Показывать мастер первого запуска"
            description="Снимите галочку чтобы скрыть мастер. Включите чтобы запустить его снова при следующем открытии."
            checked={!settings.firstRunComplete}
            onChange={(next) => {
              if (next) {
                void handleResetWizard()
              } else {
                updateSettings({ firstRunComplete: true })
              }
            }}
          />
        </div>
      </MacCard>

      {/* Section: Расширенные параметры — видны только если advancedMode включён */}
      {settings.advancedMode && (
        <MacCard className="border-amber-500/30">
          <div className="space-y-5">
            <h3 className="text-sm font-semibold uppercase tracking-wider flex items-center gap-2 text-amber-500">
              <Settings2 className="w-4 h-4" />
              Расширенные параметры
            </h3>

            <div>
              <label className="block text-xs text-[var(--color-text-secondary)] mb-1.5">Ручной адрес прокси</label>
              <input
                type="text"
                value={settings.proxyOverride}
                onChange={e => updateSettings({ proxyOverride: e.target.value })}
                placeholder="например, 127.0.0.1:2080"
                className="w-full bg-[var(--color-card)] border border-[var(--color-border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--color-text)] placeholder-[var(--color-text-secondary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)] transition-all duration-[var(--transition-fast)]"
              />
              <p className="text-xs text-[var(--color-text-secondary)] mt-1">
                Переопределяет автоопределение Happ. Оставьте пустым для автопоиска.
              </p>
            </div>

            <div>
              <label className="block text-xs text-[var(--color-text-secondary)] mb-1.5">Тип прокси для ручного адреса</label>
              <MacSelect
                options={[
                  { value: 'socks5', label: 'SOCKS5' },
                  { value: 'http', label: 'HTTP' }
                ]}
                value={settings.proxyType}
                onChange={(val) => updateSettings({ proxyType: val === 'http' ? 'http' : 'socks5' })}
                className="w-40"
              />
            </div>

            <div>
              <label className="block text-xs text-[var(--color-text-secondary)] mb-1.5">Интервал проверки IP (секунды)</label>
              <input
                type="number"
                value={settings.checkInterval / 1000}
                onChange={e => updateSettings({ checkInterval: Math.max(5, parseInt(e.target.value) || 30) * 1000 })}
                min={5}
                max={300}
                className="w-32 bg-[var(--color-card)] border border-[var(--color-border)] rounded-[var(--radius-sm)] px-3 py-2 text-sm text-[var(--color-text)] focus:outline-none focus:ring-2 focus:ring-[var(--color-accent)] transition-all duration-[var(--transition-fast)]"
              />
            </div>

            <ToggleRow
              title={<>Авто baseline сети для TUN <span className="text-amber-500">(агрессивно)</span></>}
              description={
                <>
                  Перед Hard mode сбрасывает WinHTTP/User/PAC/env proxy с резервной копией. По умолчанию
                  выключено: TUN ловит трафик и без этого. Откатывается автоматически при остановке защиты.
                </>
              }
              checked={settings.autoNetworkBaseline}
              onChange={(next) => updateSettings({ autoNetworkBaseline: next })}
            />
          </div>
        </MacCard>
      )}

      <div className="flex flex-wrap gap-3">
        <button
          onClick={handleSave}
          disabled={saving}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-[var(--radius-sm)] bg-[var(--color-accent)] text-white hover:opacity-90 transition-opacity duration-[var(--transition-fast)] disabled:opacity-50"
        >
          {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
          {saved ? 'Сохранено!' : saving ? 'Сохранение...' : 'Сохранить и применить'}
        </button>
        <button
          onClick={handleOpenLogs}
          disabled={openingLogs}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-[var(--radius-sm)] border border-[var(--color-border)] bg-[var(--color-card)] text-[var(--color-text)] hover:border-[var(--color-accent)]/50 transition-all duration-[var(--transition-fast)] disabled:opacity-50"
        >
          {openingLogs ? <Loader2 className="w-4 h-4 animate-spin" /> : <FolderOpen className="w-4 h-4" />}
          Открыть папку логов
        </button>
        <button
          onClick={handleExportDiagnostics}
          disabled={exporting}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-[var(--radius-sm)] border border-[var(--color-border)] bg-[var(--color-card)] text-[var(--color-text)] hover:border-[var(--color-accent)]/50 transition-all duration-[var(--transition-fast)] disabled:opacity-50"
        >
          {exporting ? <Loader2 className="w-4 h-4 animate-spin" /> : <FileArchive className="w-4 h-4" />}
          Экспорт диагностики (ZIP)
        </button>
      </div>
    </div>
  )
}
