import 'flag-icons/css/flag-icons.min.css'
import { Globe2 } from 'lucide-react'
import { cn } from '../design-system/utils'
import { detectCountry } from './countryGlyph'

interface CountryFlagIconProps {
  country?: string | null
  name?: string | null
  className?: string
  /**
   * Edge length in CSS pixels. A number, not a Tailwind class — see the note on
   * sizing below.
   */
  size?: number
}

const DEFAULT_SIZE = 20

/**
 * Country flag rendered as a round "coin", or a globe when the country can't be
 * determined.
 *
 * SIZING IS INLINE ON PURPOSE — do not convert it back to `w-*` / `h-*`.
 * flag-icons declares `.fi { width: 1.3333em }` and `.fi.fis { width: 1em }`.
 * `.fi.fis` is a two-class selector, so it outranks every single-class Tailwind
 * width utility regardless of stylesheet order. Callers used to pass
 * `className="h-5 w-5"`; the `h-5` applied, the `w-5` was silently dead, the box
 * fell to `1em` (inherited font-size), and the flag was stretched into a
 * non-square. width, height and font-size are set together via `style` so
 * specificity can't win, and the box is always exactly square.
 *
 * We use the `fis` (1x1) asset — flag-icons' own square redrawing of each flag,
 * with crosses and cantons recentred for a square frame. It fills the circle
 * edge to edge with nothing cropped. The 4x3 asset would need a `cover` crop
 * that shoves the Swedish/Norwegian cross and the US canton off to one side.
 *
 * A single themed inset hairline is the only decoration: it reads as an edge in
 * both themes without adding to the footprint. No gloss / dome overlay — at
 * 16-24px a highlight just washes the flag out.
 */
export function CountryFlagIcon({ country, name, className, size = DEFAULT_SIZE }: CountryFlagIconProps) {
  const hit = detectCountry(name) ?? detectCountry(country)
  const box = { width: size, height: size, fontSize: size }

  if (!hit?.iso2) {
    return (
      <Globe2
        style={box}
        className={cn('shrink-0 text-[var(--color-text-secondary)]', className)}
        aria-label="Unknown country"
      />
    )
  }

  return (
    <span
      style={box}
      className={cn(
        'fi fis inline-block shrink-0 rounded-full',
        'ring-1 ring-inset ring-[color-mix(in_srgb,var(--color-border-strong)_45%,transparent)]',
        `fi-${hit.iso2.toLowerCase()}`,
        className
      )}
      role="img"
      aria-label={hit.label}
      title={hit.label}
    />
  )
}
