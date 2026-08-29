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
 * Country flag, or a globe when the country can't be determined.
 *
 * SIZING IS INLINE ON PURPOSE — do not convert it back to `w-*` / `h-*`.
 * flag-icons declares
 *
 *     .fi     { display:inline-block; width:1.3333em; line-height:1em }
 *     .fi.fis { width:1em }
 *
 * and `.fi.fis` is a TWO-class selector, so it outranks every single-class
 * Tailwind width utility no matter what order the stylesheets load in. Callers
 * used to pass `className="h-5 w-5"`; the `h-5` applied, the `w-5` was silently
 * dead, and the width fell through to `1em` — i.e. whatever font-size happened
 * to be inherited. In a `text-sm` list row that produced a 14x20 box, and inside
 * the profile chip (`text-lg` wrapper) a 18x24 one. With `bg-cover` on top, the
 * square flag was then cropped and stretched to fill a non-square box, which is
 * why flags looked both mis-sized and fuzzy.
 *
 * An inline style beats class specificity outright, so width, height and
 * font-size are set together and the box is always exactly square.
 *
 * `background-size` is left at flag-icons' own `contain` rather than forced to
 * `cover`: on an exact square the two are equivalent, but `contain` cannot crop
 * if a flag's viewBox is ever slightly off-square.
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
        // `fis` selects the 1x1 asset, which is the only square variant — the
        // default `fi-xx` is 4x3 and would letterbox inside a circle.
        'fi fis inline-block shrink-0 rounded-full',
        // A themed hairline reads as an edge in both themes; the previous
        // `ring-black/15` went muddy against the light canvas.
        'ring-1 ring-[color-mix(in_srgb,var(--color-border-strong)_70%,transparent)]',
        `fi-${hit.iso2.toLowerCase()}`,
        className
      )}
      role="img"
      aria-label={hit.label}
      title={hit.label}
    />
  )
}
