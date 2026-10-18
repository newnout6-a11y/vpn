// AT-00-006 subset: actual pinned Electron before/after ready, isolated userData.
// Intercept only the native box to keep the fixture invisible on the workstation.
import { describe, expect, it } from 'vitest'
import { createRequire } from 'node:module'
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { dirname, join } from 'node:path'
import { spawnSync } from 'node:child_process'
import ts from 'typescript'

const require = createRequire(import.meta.url)
const hash = (data: Buffer) => createHash('sha256').update(data).digest('hex')
describe('native storage startup refusal', () => {
  it.each([false, true])('handles future schema with app.ready=%s', async ready => {
    await mkdir('.tmp', { recursive: true })
    const directory = await mkdtemp(join(process.cwd(), '.tmp', 'schema-electron-'))
    try {
      await mkdir(join(directory, 'main'))
      await mkdir(join(directory, 'shared'))
      await mkdir(join(directory, 'userData'))
      await writeFile(join(directory, 'package.json'), '{"type":"commonjs","version":"1.0.0","name":"storage-fixture"}')
      for (const source of ['main/versionedStore', 'main/storeSchema', 'main/storeSchemaStartup', 'shared/ipc-result']) {
        const code = ts.transpileModule(await readFile(`src/${source}.ts`, 'utf8'), {
          compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true }
        }).outputText
        await writeFile(join(directory, `${source}.js`), code)
      }
      const data = join(directory, 'settings.json'), evidence = join(directory, 'evidence.json')
      await writeFile(data, '{"schemaVersion":3,"privateValue":"must-not-log"}')
      const before = hash(await readFile(data))
      const script = `
const {app,dialog}=require('electron'),fs=require('node:fs');
app.setPath('userData',${JSON.stringify(join(directory, 'userData'))});
const evidence={boxes:[],ready:null,caught:null};
dialog.showErrorBox=(title,message)=>{evidence.boxes.push({title,message});evidence.ready=app.isReady();fs.writeFileSync(${JSON.stringify(evidence)},JSON.stringify(evidence))};
function run(){
  const Store=require('./main/versionedStore').default;
  try {new Store({name:'settings',cwd:__dirname,defaults:{value:0}})}
  catch(error){evidence.caught=error.code;evidence.ready=app.isReady();fs.writeFileSync(${JSON.stringify(evidence)},JSON.stringify(evidence));app.exit(0)}
}
${ready ? 'app.whenReady().then(run);' : 'run();'}
`
      const main = join(directory, 'fixture.cjs')
      await writeFile(main, script)
      const environment = { ...process.env }
      delete environment.ELECTRON_RUN_AS_NODE
      const result = spawnSync(require('electron') as string, [main], { cwd: directory, env: environment, windowsHide: true, timeout: 20_000, encoding: 'utf8' })
      expect(result.error).toBeUndefined()
      expect(result.status, result.stderr).toBe(ready ? 0 : 1)
      const report = JSON.parse(await readFile(evidence, 'utf8'))
      expect(report.ready).toBe(ready)
      expect(report.boxes).toHaveLength(ready ? 0 : 1)
      expect(report.caught).toBe(ready ? 'STORE_SCHEMA_FUTURE' : null)
      if (!ready) expect(report.boxes[0].message).toContain('Хранилище создано более новой версией')
      expect(result.stdout + result.stderr + JSON.stringify(report)).not.toContain('must-not-log')
      expect(hash(await readFile(data))).toBe(before)
    } finally {
      expect(dirname(directory)).toBe(join(process.cwd(), '.tmp'))
      await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })
    }
  }, 30_000)
})
