import { readFileSync } from 'fs'
import { resolve } from 'path'
import { defineConfig, externalizeDepsPlugin } from 'electron-vite'
import react from '@vitejs/plugin-react'
import { transform } from 'esbuild'

// ── V8 snapshot bootstrap banner ───────────────────────────────────
//
// Rollup hoists externalized `require()` calls (axios, electron-store,
// socks, sudo-prompt) to the TOP of the bundle — before any inlined
// module code. So a plain `import './snapshotBootstrap'` in index.ts
// would run AFTER those requires, defeating the purpose. This plugin
// compiles snapshotBootstrap.ts to JS and PREPENDS it as an IIFE banner
// to the main entry chunk, guaranteeing the Module._load patch is
// installed before the first externalized require executes.
//
// If the bootstrap source can't be compiled (rare), the plugin silently
// skips — the inlined import in index.ts remains as a harmless no-op
// fallback.
const snapshotBootstrapPlugin = {
  name: 'v8-snapshot-bootstrap-banner',
  enforce: 'post' as const,
  async renderChunk(code: string, chunk: { facadeModuleId: string | null }) {
    const facade = chunk.facadeModuleId
    if (!facade) return null
    if (!facade.replace(/\\/g, '/').endsWith('src/main/index.ts')) return null
    try {
      const src = readFileSync(resolve(__dirname, 'src/main/snapshotBootstrap.ts'), 'utf8')
      const compiled = await transform(src, { loader: 'ts', format: 'cjs' })
      // IIFE wrapper prevents module-scoped vars from leaking into the
      // bundle's top-level scope and colliding with bundled code.
      return `;(function () {\n${compiled.code}\n})();\n${code}`
    } catch {
      return null
    }
  }
}

export default defineConfig({
  main: {
    plugins: [externalizeDepsPlugin(), snapshotBootstrapPlugin],
    build: {
      outDir: 'out/main',
      rollupOptions: {
        input: {
          index: resolve(__dirname, 'src/main/index.ts')
        }
      }
    }
  },
  preload: {
    plugins: [externalizeDepsPlugin()],
    build: {
      outDir: 'out/preload',
      rollupOptions: {
        input: {
          index: resolve(__dirname, 'src/preload/index.ts')
        }
      }
    }
  },
  renderer: {
    plugins: [react()],
    root: resolve(__dirname, 'src/renderer'),
    server: {
      host: '127.0.0.1',
      port: 5173,
      strictPort: false
    },
    build: {
      outDir: 'out/renderer',
      rollupOptions: {
        input: {
          index: resolve(__dirname, 'src/renderer/index.html')
        }
      }
    }
  }
})
