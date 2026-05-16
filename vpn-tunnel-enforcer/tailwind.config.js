/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/renderer/**/*.{ts,tsx,html}'],
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        // Theme-aware tokens. Each colour is wired to a CSS custom property in
        // RGB-channel form so Tailwind's `/<alpha>` modifier still works:
        //   bg-card/60       → rgb(var(--rgb-card) / 0.6)
        //   text-warning/90  → rgb(var(--rgb-warning) / 0.9)
        //
        // The CSS variables themselves live in src/renderer/styles/globals.css
        // and switch between :root (light) and [data-theme="dark"].
        bg: 'rgb(var(--rgb-bg) / <alpha-value>)',
        card: 'rgb(var(--rgb-card) / <alpha-value>)',
        sidebar: 'rgb(var(--rgb-sidebar) / <alpha-value>)',
        border: 'rgb(var(--rgb-border) / <alpha-value>)',

        accent: {
          DEFAULT: 'rgb(var(--rgb-accent) / <alpha-value>)',
          hover: 'rgb(var(--rgb-accent-hover) / <alpha-value>)',
          foreground: '#ffffff'
        },
        success: 'rgb(var(--rgb-success) / <alpha-value>)',
        danger: 'rgb(var(--rgb-danger) / <alpha-value>)',
        warning: 'rgb(var(--rgb-warning) / <alpha-value>)',

        // Legacy `surface.*` palette kept so existing pages don't break.
        // Maps onto the theme-aware card/elevated/muted layers instead of
        // hardcoded greys, so light mode renders correctly.
        surface: {
          DEFAULT: 'rgb(var(--rgb-bg) / <alpha-value>)',
          light: 'rgb(var(--rgb-card) / <alpha-value>)',
          lighter: 'rgb(var(--rgb-card-elevated) / <alpha-value>)'
        },

        // Theme-aware foreground tokens. We override Tailwind's `gray.*` family
        // to point at our text scale, so `text-gray-100` / `text-gray-400` etc.
        // automatically respect the current theme without rewriting templates.
        // Order roughly matches Tailwind defaults (100 = brightest, 500 = mid).
        gray: {
          50: 'rgb(var(--rgb-text) / <alpha-value>)',
          100: 'rgb(var(--rgb-text) / <alpha-value>)',
          200: 'rgb(var(--rgb-text) / <alpha-value>)',
          300: 'rgb(var(--rgb-text) / <alpha-value>)',
          400: 'rgb(var(--rgb-text-secondary) / <alpha-value>)',
          500: 'rgb(var(--rgb-text-secondary) / <alpha-value>)',
          600: 'rgb(var(--rgb-text-muted) / <alpha-value>)',
          700: 'rgb(var(--rgb-border-strong) / <alpha-value>)',
          800: 'rgb(var(--rgb-border) / <alpha-value>)',
          900: 'rgb(var(--rgb-card-elevated) / <alpha-value>)'
        }
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite'
      }
    }
  },
  plugins: []
}
