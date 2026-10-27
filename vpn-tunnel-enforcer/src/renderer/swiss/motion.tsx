/** Text-motion helper for the «Пломба» redesign. */

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
