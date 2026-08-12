import 'flag-icons/css/flag-icons.min.css'
import { Globe2 } from 'lucide-react'
import { cn } from '../design-system/utils'
import { detectCountry } from './countryGlyph'

interface CountryFlagIconProps {
  country?: string | null
  name?: string | null
  className?: string
}

export function CountryFlagIcon({ country, name, className }: CountryFlagIconProps) {
  const hit = detectCountry(name) ?? detectCountry(country)
  if (!hit?.iso2) {
    return (
      <Globe2
        className={cn('h-5 w-5 shrink-0 text-[var(--color-text-secondary)]', className)}
        aria-label="Unknown country"
      />
    )
  }

  return (
    <span
      className={cn(
        'fi fis inline-block h-5 w-5 shrink-0 rounded-full bg-cover bg-center shadow-sm ring-1 ring-black/15',
        `fi-${hit.iso2.toLowerCase()}`,
        className
      )}
      role="img"
      aria-label={hit.label}
      title={hit.label}
    />
  )
}
