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
    maxWorkers: 2,
    isolate: true,
    environment: 'node',
    setupFiles: [],
    // Keep the inherited include empty: Vite merges project include arrays.
    include: mode === 'integration' ? ['src/**/*.itest.ts'] : [],
    ...(mode === 'integration' ? {} : {
      projects: [
        {
          extends: true,
          test: {
            name: 'node',
            environment: 'node',
            include: ['src/**/*.{test,spec}.{ts,tsx}'],
            exclude: ['src/renderer/**', 'src/main/recoveryManifestStorage.test.ts']
          }
        },
        {
          extends: true,
          test: {
            name: 'jsdom',
            environment: 'jsdom',
            // This native fixture relies on jsdom's child_process mock resolution.
            include: ['src/renderer/**/*.{test,spec}.{ts,tsx}', 'src/main/recoveryManifestStorage.test.ts']
          }
        }
      ]
    }),
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.{test,spec,itest}.{ts,tsx}', 'src/**/index.ts']
    }
  }
}))
