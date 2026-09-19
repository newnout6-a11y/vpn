import React from 'react'
import { AlertTriangle, RotateCcw, Copy, Check } from 'lucide-react'

interface Props {
  children: React.ReactNode
}

interface State {
  hasError: boolean
  error: Error | null
  componentStack: string | null
  copied: boolean
}

export class RootErrorBoundary extends React.Component<Props, State> {
  private autoReloadTimer: ReturnType<typeof setTimeout> | null = null

  constructor(props: Props) {
    super(props)
    this.state = {
      hasError: false,
      error: null,
      componentStack: null,
      copied: false
    }
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo): void {
    this.setState({ componentStack: errorInfo.componentStack || null })

    try {
      const api = typeof window !== 'undefined' ? window.electronAPI : null
      if (api?.logRenderer) {
        void api.logRenderer(
          'error',
          `[RootErrorBoundary] caught crash: ${error.message}\nStack: ${error.stack}\nComponent stack: ${errorInfo.componentStack}`
        )
      }
    } catch {
      /* ignore logging error */
    }

    // If the error happens while the window is hidden/background (e.g. system wake/sleep),
    // automatically reload after a brief backoff so the user never sees a persistent error state.
    if (typeof document !== 'undefined' && document.hidden) {
      this.scheduleAutoReload()
    }
  }

  componentWillUnmount(): void {
    if (this.autoReloadTimer) {
      clearTimeout(this.autoReloadTimer)
    }
  }

  private scheduleAutoReload(): void {
    if (this.autoReloadTimer) clearTimeout(this.autoReloadTimer)
    this.autoReloadTimer = setTimeout(() => {
      window.location.reload()
    }, 2000)
  }

  private handleReload = (): void => {
    window.location.reload()
  }

  private handleRetry = (): void => {
    this.setState({ hasError: false, error: null, componentStack: null, copied: false })
  }

  private handleCopy = (): void => {
    const details = [
      `Error: ${this.state.error?.message || 'Unknown'}`,
      `Stack: ${this.state.error?.stack || 'None'}`,
      `Component Stack: ${this.state.componentStack || 'None'}`,
      `URL: ${window.location.href}`,
      `UserAgent: ${navigator.userAgent}`
    ].join('\n\n')

    void navigator.clipboard.writeText(details).then(() => {
      this.setState({ copied: true })
      setTimeout(() => this.setState({ copied: false }), 2000)
    }).catch(() => undefined)
  }

  render(): React.ReactNode {
    if (!this.state.hasError) {
      return this.props.children
    }

    return (
      <div className="min-h-screen w-full flex items-center justify-center p-6 bg-[var(--color-bg,#1f1f1f)] text-[var(--color-text,#f0f0f0)] font-sans select-none">
        <div className="max-w-md w-full rounded-2xl bg-[var(--color-card,#262626)] border border-[var(--color-border,#333333)] p-6 shadow-2xl flex flex-col items-center text-center">
          <div className="w-12 h-12 rounded-full bg-[var(--color-danger,#ef4444)]/15 border border-[var(--color-danger,#ef4444)]/30 flex items-center justify-center mb-4 text-[var(--color-danger,#ef4444)]">
            <AlertTriangle className="w-6 h-6" />
          </div>

          <h1 className="text-lg font-semibold mb-2 text-[var(--color-text,#f0f0f0)]">
            Сбой интерфейса приложения
          </h1>

          <p className="text-sm text-[var(--color-text-secondary,#a1a1aa)] mb-5 leading-relaxed">
            Фоновая защита и VPN продолжают работать в системе. Визуальный интерфейс приостановлен из-за неожиданной ошибки.
          </p>

          <div className="flex flex-col w-full gap-2.5 mb-4">
            <button
              onClick={this.handleReload}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-xl font-medium text-sm bg-[var(--color-accent,#2563eb)] hover:bg-[var(--color-accent-hover,#1d4ed8)] text-white transition-colors cursor-pointer"
            >
              <RotateCcw className="w-4 h-4" />
              Перезагрузить интерфейс
            </button>

            <div className="flex gap-2">
              <button
                onClick={this.handleRetry}
                className="flex-1 py-2 px-3 rounded-xl text-xs font-medium border border-[var(--color-border,#333333)] hover:bg-white/5 transition-colors cursor-pointer text-[var(--color-text,#f0f0f0)]"
              >
                Попробовать снова
              </button>
              <button
                onClick={this.handleCopy}
                className="flex-1 py-2 px-3 rounded-xl text-xs font-medium border border-[var(--color-border,#333333)] hover:bg-white/5 transition-colors flex items-center justify-center gap-1.5 cursor-pointer text-[var(--color-text,#f0f0f0)]"
              >
                {this.state.copied ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Скопировано</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Копировать детали</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {this.state.error && (
            <details className="w-full text-left mt-2 border-t border-[var(--color-border,#333333)]/50 pt-3">
              <summary className="text-xs text-[var(--color-text-secondary,#a1a1aa)] cursor-pointer hover:underline mb-1">
                Технические подробности
              </summary>
              <pre className="mt-1 p-2.5 bg-black/40 rounded-lg text-[11px] font-mono text-red-300/90 overflow-x-auto max-h-36 overflow-y-auto leading-tight whitespace-pre-wrap select-text">
                {this.state.error.message}
                {this.state.error.stack && `\n\n${this.state.error.stack}`}
              </pre>
            </details>
          )}
        </div>
      </div>
    )
  }
}
