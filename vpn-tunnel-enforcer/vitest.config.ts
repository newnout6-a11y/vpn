import { defineConfig } from 'vitest/config'
import { resolve } from 'path'

export default defineConfig(({ mode }) => ({
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src/renderer'),
      '@main': resolve(__dirname, 'src/main')
    }
  },
  test: {
    globals: true,
    environment: mode === 'integration' ? 'node' : 'jsdom',
    setupFiles: [],
    include: mode === 'integration' ? ['src/**/*.itest.ts'] : ['src/**/*.{test,spec}.{ts,tsx}'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.{test,spec,itest}.{ts,tsx}', 'src/**/index.ts']
    }
  }
}))
