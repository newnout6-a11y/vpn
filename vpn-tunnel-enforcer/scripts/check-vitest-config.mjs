import assert from 'node:assert/strict'
import { dirname, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')

// WP-0: retain collection of existing AT-* oracles, including AT-03-012's
// native fixture and integration-mode AT-11-002. This does not execute them.
function validateMode(report, integration) {
  assert.equal(report.maxWorkers, 2, 'default worker limit must remain two')
  const paths = report.files.map(file => file.path)
  assert.equal(new Set(paths).size, paths.length, 'duplicate test files')
  assert.deepEqual([...paths].sort(), [...report.expected].sort(), 'missing or unexpected test files')
  for (const file of report.files) {
    const dom = !integration && (file.path.startsWith('src/renderer/') || file.path === 'src/main/recoveryManifestStorage.test.ts')
    assert.equal(file.environment, dom ? 'jsdom' : 'node', `wrong environment: ${file.path}`)
    assert.equal(file.isolate, true, `isolation disabled: ${file.path}`)
    assert.equal(file.globals, true, `test globals lost: ${file.path}`)
    assert.equal(file.maxWorkers, 2, `worker limit overridden: ${file.path}`)
  }
}

function validate(report) {
  validateMode(report.normal, false)
  validateMode(report.integration, true)
}

async function collect(mode, reference) {
  const { createVitest } = await import('vitest/node')
  const context = await createVitest('test', {
    root, watch: false, mode,
    ...(reference ? { config: false, include: [mode === 'integration' ? 'src/**/*.itest.ts' : 'src/**/*.{test,spec}.{ts,tsx}'] } : {})
  })
  try {
    const specs = await context.globTestSpecifications()
    return {
      maxWorkers: context.config.maxWorkers,
      files: specs.map(spec => ({
        path: relative(root, spec.moduleId).replaceAll('\\', '/'),
        environment: spec.project.config.environment,
        isolate: spec.project.config.isolate,
        globals: spec.project.config.globals,
        maxWorkers: spec.project.config.maxWorkers ?? context.config.maxWorkers
      }))
    }
  } finally {
    await context.close()
  }
}

try {
  if (process.argv[2] === '--validate') {
    let input = ''
    for await (const chunk of process.stdin) input += chunk
    validate(JSON.parse(input))
    console.log('PASS')
  } else {
    const report = {}
    for (const [key, mode] of [['normal', 'test'], ['integration', 'integration']]) {
      report[key] = await collect(mode, false)
      const reference = await collect(mode, true)
      report[key].expected = reference.files.map(file => file.path)
    }
    validate(report)
    console.log(JSON.stringify(report))
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error))
  process.exitCode = 1
}
