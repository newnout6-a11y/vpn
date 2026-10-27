/** Small text-motion helpers for the «Пломба» redesign. */

/** Each changed character re-mounts and rolls in from above. */
export function Roll({ value, className = '' }: { value: string; className?: string }) {
  return (
    <span className={'inline-flex ' + className} aria-label={value}>
      {value.split('').map((ch, i) => (
        <span key={i + '-' + ch} className="roll" aria-hidden="true">
          {ch === ' ' ? '\u00A0' : ch}
        </span>
      ))}
    </span>
  )
}

/** Letters fly in one by one. Re-key the parent to replay. */
export function Stagger({ text, step = 38 }: { text: string; step?: number }) {
  return (
    <span>
      {text.split('').map((ch, i) => (
        <span key={i} className="letter" style={{ animationDelay: i * step + 'ms' }}>
          {ch === ' ' ? '\u00A0' : ch}
        </span>
      ))}
    </span>
  )
}
