import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useTranslation } from 'react-i18next'
import {
  Globe,
  Palette,
  Search,
  Shield,
  Loader2,
  CheckCircle2,
  ArrowRight,
  ArrowLeft,
  Zap,
  Lock,
  Sparkles,
} from 'lucide-react'
import { MacButton } from '../design-system/MacButton'
import { MacCard } from '../design-system/MacCard'
import { MacSegmentedControl } from '../design-system/MacSegmentedControl'
import { useAppStore } from '../store'

/**
 * Fullscreen macOS-style onboarding wizard shown on first launch.
 *
 * Steps:
 *   1. Language selection
 *   2. Theme selection
 *   3. VPN client detection
 *   4. Mode selection
 *   5. Kill-switch configuration
 *   6. Completion
 */

interface Props {
  onComplete: () => void
  onSkip: () => void
}

type Step = 'language' | 'theme' | 'detect' | 'mode' | 'killswitch' | 'complete'

const STEPS: Step[] = ['language', 'theme', 'detect', 'mode', 'killswitch', 'complete']
const TOTAL_STEPS = STEPS.length

const slideVariants = {
  enter: (direction: number) => ({
    x: direction > 0 ? 80 : -80,
    opacity: 0,
  }),
  center: {
    x: 0,
    opacity: 1,
  },
  exit: (direction: number) => ({
    x: direction > 0 ? -80 : 80,
    opacity: 0,
  }),
}

export function FirstRunWizard({ onComplete, onSkip }: Props) {
  const { t, i18n } = useTranslation()
  const proxy = useAppStore((s) => s.proxy)
  const settings = useAppStore((s) => s.settings)
  const updateSettings = useAppStore((s) => s.updateSettings)
  const setProxy = useAppStore((s) => s.setProxy)
  const addLog = useAppStore((s) => s.addLog)

  const [step, setStep] = useState<Step>('language')
  const [direction, setDirection] = useState(1)
  const [detecting, setDetecting] = useState(false)
  const [detectionDone, setDetectionDone] = useState(false)

  // Wizard state
  const [selectedLang, setSelectedLang] = useState<'en' | 'ru'>(
    (i18n.language as 'en' | 'ru') || 'en'
  )
  const [selectedTheme, setSelectedTheme] = useState<'light' | 'dark' | 'system'>('system')
  const [selectedMode, setSelectedMode] = useState<'hard' | 'soft' | 'direct'>('hard')
  const [killSwitchLevel, setKillSwitchLevel] = useState<'off' | 'standard' | 'strict'>('standard')

  const currentIndex = STEPS.indexOf(step)

  // Auto-detect VPN when entering the detect step
  useEffect(() => {
    if (step !== 'detect') return
    if (proxy) {
      setDetectionDone(true)
      return
    }
    void detectVpn()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step])

  async function detectVpn() {
    setDetecting(true)
    setDetectionDone(false)
    try {
      const result = await window.electronAPI.detectHapp()
      if (result) {
        setProxy(result)
        addLog('info', t('onboarding.vpnFound', { host: result.host, port: result.port, type: result.type }))
      } else {
        addLog('warn', t('onboarding.vpnNotFound'))
      }
    } catch (err: any) {
      addLog('error', t('onboarding.vpnError', { error: err.message }))
    } finally {
      setDetecting(false)
      setDetectionDone(true)
    }
  }

  function goNext() {
    const idx = STEPS.indexOf(step)
    if (idx < TOTAL_STEPS - 1) {
      setDirection(1)
      setStep(STEPS[idx + 1])
    }
  }

  function goBack() {
    const idx = STEPS.indexOf(step)
    if (idx > 0) {
      setDirection(-1)
      setStep(STEPS[idx - 1])
    }
  }

  function handleLanguageChange(lang: 'en' | 'ru') {
    setSelectedLang(lang)
    i18n.changeLanguage(lang)
  }

  async function handleFinish() {
    // Save all wizard settings
    try {
      await window.electronAPI.saveSettings({
        firstRunComplete: true,
        firewallKillSwitch: killSwitchLevel !== 'off',
      })
    } catch {
      updateSettings({ firstRunComplete: true })
    }

    // Save theme via IPC if available
    try {
      const themeId = selectedTheme === 'light' ? 'light' : selectedTheme === 'dark' ? 'dark' : 'system'
      if ((window.electronAPI as any).themeSetActive) {
        await (window.electronAPI as any).themeSetActive(themeId)
      }
    } catch { /* theme save is best-effort */ }

    // Save locale via IPC if available
    try {
      if ((window.electronAPI as any).i18nSetLocale) {
        await (window.electronAPI as any).i18nSetLocale(selectedLang)
      }
    } catch { /* locale save is best-effort */ }

    // Save kill-switch level via IPC if available
    try {
      if ((window.electronAPI as any).killSwitchSetLevel) {
        await (window.electronAPI as any).killSwitchSetLevel(killSwitchLevel)
      }
    } catch { /* kill-switch save is best-effort */ }

    onComplete()
  }

  function handleSkip() {
    // Apply defaults: English, system theme, hard mode, standard kill-switch
    i18n.changeLanguage('en')
    onSkip()
  }

  const stepIcon = (s: Step) => {
    switch (s) {
      case 'language': return <Globe size={16} />
      case 'theme': return <Palette size={16} />
      case 'detect': return <Search size={16} />
      case 'mode': return <Zap size={16} />
      case 'killswitch': return <Lock size={16} />
      case 'complete': return <Sparkles size={16} />
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--color-bg)]">
      {/* Background gradient decoration */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-1/4 -right-1/4 w-[600px] h-[600px] rounded-full bg-[var(--color-accent)]/5 blur-3xl" />
        <div className="absolute -bottom-1/4 -left-1/4 w-[500px] h-[500px] rounded-full bg-[var(--color-accent)]/3 blur-3xl" />
      </div>

      <div className="relative w-full max-w-2xl mx-auto px-6">
        {/* Progress indicator */}
        <div className="flex items-center justify-center gap-2 mb-8">
          {STEPS.map((s, i) => {
            const done = i < currentIndex
            const active = i === currentIndex
            return (
              <div key={s} className="flex items-center gap-2">
                <motion.div
                  className={`flex items-center justify-center w-8 h-8 rounded-full transition-colors duration-200 ${
                    done
                      ? 'bg-[var(--color-accent)] text-white'
                      : active
                        ? 'bg-[var(--color-accent)]/20 text-[var(--color-accent)] ring-2 ring-[var(--color-accent)]'
                        : 'bg-[var(--color-border)] text-[var(--color-text-secondary)]'
                  }`}
                  animate={{ scale: active ? 1.1 : 1 }}
                  transition={{ type: 'spring', stiffness: 300, damping: 20 }}
                >
                  {done ? <CheckCircle2 size={16} /> : stepIcon(s)}
                </motion.div>
                {i < STEPS.length - 1 && (
                  <div
                    className={`w-8 h-0.5 rounded-full transition-colors duration-200 ${
                      done ? 'bg-[var(--color-accent)]' : 'bg-[var(--color-border)]'
                    }`}
                  />
                )}
              </div>
            )
          })}
        </div>

        {/* Step counter */}
        <p className="text-center text-sm text-[var(--color-text-secondary)] mb-6">
          {t('onboarding.step', { current: currentIndex + 1, total: TOTAL_STEPS })}
        </p>

        {/* Step content */}
        <MacCard className="min-h-[380px] relative overflow-hidden">
          <AnimatePresence mode="wait" custom={direction}>
            <motion.div
              key={step}
              custom={direction}
              variants={slideVariants}
              initial="enter"
              animate="center"
              exit="exit"
              transition={{ duration: 0.25, ease: 'easeOut' }}
              className="w-full"
            >
              {step === 'language' && (
                <StepLanguage
                  selected={selectedLang}
                  onChange={handleLanguageChange}
                  t={t}
                />
              )}
              {step === 'theme' && (
                <StepTheme
                  selected={selectedTheme}
                  onChange={setSelectedTheme}
                  t={t}
                />
              )}
              {step === 'detect' && (
                <StepDetect
                  detecting={detecting}
                  detectionDone={detectionDone}
                  proxy={proxy}
                  onRetry={detectVpn}
                  t={t}
                />
              )}
              {step === 'mode' && (
                <StepMode
                  selected={selectedMode}
                  onChange={setSelectedMode}
                  t={t}
                />
              )}
              {step === 'killswitch' && (
                <StepKillSwitch
                  level={killSwitchLevel}
                  onChange={setKillSwitchLevel}
                  t={t}
                />
              )}
              {step === 'complete' && (
                <StepComplete t={t} />
              )}
            </motion.div>
          </AnimatePresence>
        </MacCard>

        {/* Navigation footer */}
        <div className="flex items-center justify-between mt-6">
          <div>
            {currentIndex > 0 && step !== 'complete' && (
              <MacButton variant="ghost" onClick={goBack}>
                <ArrowLeft size={16} className="mr-1.5" />
                {t('onboarding.back')}
              </MacButton>
            )}
          </div>

          <div className="flex items-center gap-3">
            {step !== 'complete' && (
              <MacButton variant="ghost" onClick={handleSkip}>
                {t('onboarding.skip')}
              </MacButton>
            )}
            {step !== 'complete' ? (
              <MacButton variant="primary" onClick={goNext}>
                {t('onboarding.next')}
                <ArrowRight size={16} className="ml-1.5" />
              </MacButton>
            ) : (
              <MacButton variant="primary" size="lg" onClick={handleFinish}>
                {t('onboarding.finish')}
                <CheckCircle2 size={16} className="ml-1.5" />
              </MacButton>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

/* ─── Step Components ─────────────────────────────────────────────────── */

interface StepProps {
  t: (key: string, opts?: any) => string
}

function StepLanguage({ selected, onChange, t }: StepProps & { selected: 'en' | 'ru'; onChange: (l: 'en' | 'ru') => void }) {
  return (
    <div className="space-y-6">
      <div className="text-center">
        <motion.div
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.1, duration: 0.3 }}
          className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-[var(--color-accent)]/10 mb-4"
        >
          <Globe size={32} className="text-[var(--color-accent)]" />
        </motion.div>
        <h2 className="text-2xl font-semibold text-[var(--color-text)]">
          {t('onboarding.selectLanguage')}
        </h2>
      </div>

      <div className="grid grid-cols-2 gap-4 max-w-sm mx-auto">
        <LanguageOption
          label="English"
          flag="🇬🇧"
          active={selected === 'en'}
          onClick={() => onChange('en')}
        />
        <LanguageOption
          label="Русский"
          flag="🇷🇺"
          active={selected === 'ru'}
          onClick={() => onChange('ru')}
        />
      </div>
    </div>
  )
}

function LanguageOption({ label, flag, active, onClick }: { label: string; flag: string; active: boolean; onClick: () => void }) {
  return (
    <motion.button
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      onClick={onClick}
      className={`flex flex-col items-center gap-2 p-5 rounded-[var(--radius-md)] border-2 transition-colors duration-200 ${
        active
          ? 'border-[var(--color-accent)] bg-[var(--color-accent)]/5'
          : 'border-[var(--color-border)] hover:border-[var(--color-accent)]/50'
      }`}
    >
      <span className="text-3xl">{flag}</span>
      <span className={`text-sm font-medium ${active ? 'text-[var(--color-accent)]' : 'text-[var(--color-text)]'}`}>
        {label}
      </span>
    </motion.button>
  )
}

function StepTheme({ selected, onChange, t }: StepProps & { selected: 'light' | 'dark' | 'system'; onChange: (th: 'light' | 'dark' | 'system') => void }) {
  return (
    <div className="space-y-6">
      <div className="text-center">
        <motion.div
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.1, duration: 0.3 }}
          className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-[var(--color-accent)]/10 mb-4"
        >
          <Palette size={32} className="text-[var(--color-accent)]" />
        </motion.div>
        <h2 className="text-2xl font-semibold text-[var(--color-text)]">
          {t('onboarding.selectTheme')}
        </h2>
      </div>

      <div className="grid grid-cols-3 gap-3 max-w-md mx-auto">
        <ThemeOption
          label={t('themes.light')}
          value="light"
          active={selected === 'light'}
          onClick={() => onChange('light')}
          preview="bg-[#ffffff] border-[#e5e5ea]"
        />
        <ThemeOption
          label={t('themes.dark')}
          value="dark"
          active={selected === 'dark'}
          onClick={() => onChange('dark')}
          preview="bg-[#1c1c1e] border-[#38383a]"
        />
        <ThemeOption
          label={t('themes.system')}
          value="system"
          active={selected === 'system'}
          onClick={() => onChange('system')}
          preview="bg-gradient-to-br from-[#ffffff] to-[#1c1c1e] border-[#86868b]"
        />
      </div>
    </div>
  )
}

function ThemeOption({ label, active, onClick, preview }: { label: string; value: string; active: boolean; onClick: () => void; preview: string }) {
  return (
    <motion.button
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      onClick={onClick}
      className={`flex flex-col items-center gap-3 p-4 rounded-[var(--radius-md)] border-2 transition-colors duration-200 ${
        active
          ? 'border-[var(--color-accent)] bg-[var(--color-accent)]/5'
          : 'border-[var(--color-border)] hover:border-[var(--color-accent)]/50'
      }`}
    >
      <div className={`w-12 h-12 rounded-[var(--radius-sm)] border ${preview}`} />
      <span className={`text-xs font-medium ${active ? 'text-[var(--color-accent)]' : 'text-[var(--color-text)]'}`}>
        {label}
      </span>
    </motion.button>
  )
}

function StepDetect({ detecting, detectionDone, proxy, onRetry, t }: StepProps & { detecting: boolean; detectionDone: boolean; proxy: any; onRetry: () => void }) {
  return (
    <div className="space-y-6">
      <div className="text-center">
        <motion.div
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.1, duration: 0.3 }}
          className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-[var(--color-accent)]/10 mb-4"
        >
          {detecting ? (
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ repeat: Infinity, duration: 1.5, ease: 'linear' }}
            >
              <Loader2 size={32} className="text-[var(--color-accent)]" />
            </motion.div>
          ) : (
            <Search size={32} className="text-[var(--color-accent)]" />
          )}
        </motion.div>
        <h2 className="text-2xl font-semibold text-[var(--color-text)]">
          {t('onboarding.detectVpn')}
        </h2>
        <p className="text-sm text-[var(--color-text-secondary)] mt-2">
          {t('onboarding.detectVpnDescription')}
        </p>
      </div>

      <div className="max-w-sm mx-auto">
        {detecting && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex items-center justify-center gap-3 p-4 rounded-[var(--radius-md)] bg-[var(--color-accent)]/5 border border-[var(--color-accent)]/20"
          >
            <Loader2 size={20} className="animate-spin text-[var(--color-accent)]" />
            <span className="text-sm text-[var(--color-text-secondary)]">
              {t('common.loading')}
            </span>
          </motion.div>
        )}

        {detectionDone && proxy && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-3 p-4 rounded-[var(--radius-md)] bg-green-500/10 border border-green-500/30"
          >
            <CheckCircle2 size={20} className="text-green-500 flex-shrink-0" />
            <div>
              <p className="text-sm font-medium text-[var(--color-text)]">
                {t('onboarding.vpnFoundShort')}
              </p>
              <p className="text-xs text-[var(--color-text-secondary)] font-mono">
                {proxy.host}:{proxy.port} ({proxy.type.toUpperCase()})
              </p>
            </div>
          </motion.div>
        )}

        {detectionDone && !proxy && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-3"
          >
            <div className="flex items-center gap-3 p-4 rounded-[var(--radius-md)] bg-[var(--color-border)]/30 border border-[var(--color-border)]">
              <Search size={20} className="text-[var(--color-text-secondary)] flex-shrink-0" />
              <p className="text-sm text-[var(--color-text-secondary)]">
                {t('onboarding.vpnNotFoundShort')}
              </p>
            </div>
            <MacButton variant="secondary" className="w-full" onClick={onRetry}>
              {t('common.retry')}
            </MacButton>
          </motion.div>
        )}
      </div>
    </div>
  )
}

function StepMode({ selected, onChange, t }: StepProps & { selected: 'hard' | 'soft' | 'direct'; onChange: (m: 'hard' | 'soft' | 'direct') => void }) {
  const modes = [
    { value: 'hard', label: t('onboarding.modeHard'), description: t('onboarding.modeHardDescription'), icon: <Shield size={24} /> },
    { value: 'soft', label: t('onboarding.modeSoft'), description: t('onboarding.modeSoftDescription'), icon: <Zap size={24} /> },
    { value: 'direct', label: t('onboarding.modeDirect'), description: t('onboarding.modeDirectDescription'), icon: <Globe size={24} /> },
  ] as const

  return (
    <div className="space-y-6">
      <div className="text-center">
        <motion.div
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.1, duration: 0.3 }}
          className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-[var(--color-accent)]/10 mb-4"
        >
          <Zap size={32} className="text-[var(--color-accent)]" />
        </motion.div>
        <h2 className="text-2xl font-semibold text-[var(--color-text)]">
          {t('onboarding.selectMode')}
        </h2>
        <p className="text-sm text-[var(--color-text-secondary)] mt-2">
          {t('onboarding.selectModeDescription')}
        </p>
      </div>

      <div className="space-y-3 max-w-md mx-auto">
        {modes.map((mode) => (
          <motion.button
            key={mode.value}
            whileHover={{ scale: 1.01 }}
            whileTap={{ scale: 0.99 }}
            onClick={() => onChange(mode.value)}
            className={`w-full flex items-start gap-4 p-4 rounded-[var(--radius-md)] border-2 text-left transition-colors duration-200 ${
              selected === mode.value
                ? 'border-[var(--color-accent)] bg-[var(--color-accent)]/5'
                : 'border-[var(--color-border)] hover:border-[var(--color-accent)]/50'
            }`}
          >
            <div className={`flex-shrink-0 mt-0.5 ${selected === mode.value ? 'text-[var(--color-accent)]' : 'text-[var(--color-text-secondary)]'}`}>
              {mode.icon}
            </div>
            <div>
              <p className={`text-sm font-medium ${selected === mode.value ? 'text-[var(--color-accent)]' : 'text-[var(--color-text)]'}`}>
                {mode.label}
              </p>
              <p className="text-xs text-[var(--color-text-secondary)] mt-0.5">
                {mode.description}
              </p>
            </div>
          </motion.button>
        ))}
      </div>
    </div>
  )
}

function StepKillSwitch({ level, onChange, t }: StepProps & { level: 'off' | 'standard' | 'strict'; onChange: (l: 'off' | 'standard' | 'strict') => void }) {
  const options = [
    { value: 'off', label: t('settings.killSwitchOff') },
    { value: 'standard', label: t('settings.killSwitchStandard') },
    { value: 'strict', label: t('settings.killSwitchStrict') },
  ]

  return (
    <div className="space-y-6">
      <div className="text-center">
        <motion.div
          initial={{ scale: 0.8, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 0.1, duration: 0.3 }}
          className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-[var(--color-accent)]/10 mb-4"
        >
          <Lock size={32} className="text-[var(--color-accent)]" />
        </motion.div>
        <h2 className="text-2xl font-semibold text-[var(--color-text)]">
          {t('onboarding.configureKillSwitch')}
        </h2>
        <p className="text-sm text-[var(--color-text-secondary)] mt-2">
          {t('onboarding.configureKillSwitchDescription')}
        </p>
      </div>

      <div className="max-w-sm mx-auto">
        <MacSegmentedControl
          options={options}
          value={level}
          onChange={(v) => onChange(v as 'off' | 'standard' | 'strict')}
          className="w-full"
        />

        <motion.div
          key={level}
          initial={{ opacity: 0, y: 5 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.2 }}
          className="mt-4 p-4 rounded-[var(--radius-md)] bg-[var(--color-border)]/20 border border-[var(--color-border)]"
        >
          <p className="text-sm text-[var(--color-text-secondary)]">
            {level === 'off' && t('onboarding.killSwitchOffDesc')}
            {level === 'standard' && t('onboarding.killSwitchStandardDesc')}
            {level === 'strict' && t('onboarding.killSwitchStrictDesc')}
          </p>
        </motion.div>
      </div>
    </div>
  )
}

function StepComplete({ t }: StepProps) {
  return (
    <div className="space-y-6 text-center">
      <motion.div
        initial={{ scale: 0, rotate: -180 }}
        animate={{ scale: 1, rotate: 0 }}
        transition={{ type: 'spring', stiffness: 200, damping: 15, delay: 0.1 }}
        className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-green-500/10"
      >
        <CheckCircle2 size={40} className="text-green-500" />
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3, duration: 0.3 }}
      >
        <h2 className="text-2xl font-semibold text-[var(--color-text)]">
          {t('onboarding.complete')}
        </h2>
        <p className="text-sm text-[var(--color-text-secondary)] mt-2 max-w-sm mx-auto">
          {t('onboarding.completeDescription')}
        </p>
      </motion.div>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.5, duration: 0.3 }}
        className="flex justify-center"
      >
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-green-500/10 text-green-600 text-sm font-medium">
          <Shield size={16} />
          VPN Tunnel Enforcer
        </div>
      </motion.div>
    </div>
  )
}
