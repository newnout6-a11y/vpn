import ts from 'typescript'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'

const parse = (name, source) => ts.createSourceFile(name, source, ts.ScriptTarget.Latest, true)
const walk = (node, visit) => { visit(node); ts.forEachChild(node, child => walk(child, visit)) }
const called = (node, name) => ts.isCallExpression(node) && node.expression.getText() === name
const literal = node => node && ts.isStringLiteral(node) ? node.text : undefined

export function inspectIpcContract({ main, preload, shared }) {
  const registered = [], exposed = [], declared = [], problems = []
  for (const [file, source] of Object.entries(main)) {
    const tree = parse(file, source), wrappers = new Set()
    walk(tree, node => {
      if (!called(node, 'ipcMain.handle')) return
      const channel = literal(node.arguments[0])
      if (channel !== undefined) { registered.push(channel); return }
      let parent = node.parent
      while (parent && !ts.isFunctionDeclaration(parent)) parent = parent.parent
      if (parent?.name && parent.parameters[0]?.name.getText() === node.arguments[0]?.getText()) wrappers.add(parent.name.text)
      else problems.push(`${file}: unresolved ipcMain.handle channel`)
    })
    walk(tree, node => {
      if (!ts.isCallExpression(node) || !ts.isIdentifier(node.expression) || !wrappers.has(node.expression.text)) return
      const channel = literal(node.arguments[0])
      if (channel !== undefined) registered.push(channel)
      else problems.push(`${file}: unresolved wrapper channel`)
    })
  }
  walk(parse('preload.ts', preload), node => {
    if (!called(node, 'contextBridge.exposeInMainWorld')) return
    let object = node.arguments[1]
    if (object && called(object, 'withIpcFailures')) object = object.arguments[0]
    if (object && ts.isSatisfiesExpression(object)) object = object.expression
    if (!object || !ts.isObjectLiteralExpression(object)) { problems.push('Unresolved preload bridge'); return }
    for (const property of object.properties) {
      if (!ts.isPropertyAssignment(property)) { problems.push('Unresolved preload property'); continue }
      walk(property.initializer, child => {
        if (called(child, 'ipcRenderer.invoke')) problems.push(`Preload bypasses result decoder: ${property.name.getText()}`)
        if (!called(child, 'invoke')) return
        const channel = literal(child.arguments[0])
        if (channel === undefined) problems.push('Unresolved preload invoke channel')
        else exposed.push({ channel, method: property.name.getText() })
      })
    }
  })
  walk(parse('shared.ts', shared), node => {
    if (!ts.isVariableDeclaration(node) || node.name.getText() !== 'IPC_REQUESTS') return
    let object = node.initializer
    if (object && ts.isAsExpression(object)) object = object.expression
    if (!object || !ts.isObjectLiteralExpression(object)) { problems.push('Unresolved shared registry'); return }
    for (const property of object.properties) {
      if (!ts.isPropertyAssignment(property) || !called(property.initializer, 'request')) { problems.push('Unresolved request declaration'); continue }
      const channel = literal(property.name), method = literal(property.initializer.arguments[0])
      if (channel === undefined || method === undefined || !ts.isArrayLiteralExpression(property.initializer.arguments[1])) problems.push('Incomplete request declaration')
      else declared.push({ channel, method })
    }
  })
  const lists = [registered, exposed.map(e => e.channel), declared.map(e => e.channel)]
  const sets = lists.map(values => new Set(values)), names = ['main', 'preload', 'shared']
  for (let index = 0; index < sets.length; index++) {
    for (const name of new Set(lists[index].filter((v, i) => lists[index].indexOf(v) !== i))) problems.push(`${names[index]} duplicate: ${name}`)
    if (!sets[index].size) problems.push(`${names[index]} has no request channels`)
    for (const name of new Set(sets.flatMap(set => [...set]))) if (!sets[index].has(name)) problems.push(`${names[index]} missing: ${name}`)
  }
  for (const entry of exposed) if (declared.find(d => d.channel === entry.channel)?.method !== entry.method) problems.push(`Method mismatch: ${entry.channel} (${entry.method})`)
  return { registered, exposed, declared, problems }
}

export function checkIpcContract(root = process.cwd()) {
  const main = {}
  function collect(dir) {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const file = join(dir, entry.name)
      if (entry.isDirectory()) collect(file)
      else if (file.endsWith('.ts') && !/\.(test|spec|itest)\.ts$/.test(file)) main[file] = readFileSync(file, 'utf8')
    }
  }
  collect(join(root, 'src/main'))
  return inspectIpcContract({ main, preload: readFileSync(join(root, 'src/preload/index.ts'), 'utf8'), shared: readFileSync(join(root, 'src/shared/ipc-contract.ts'), 'utf8') })
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = checkIpcContract()
  if (result.problems.length) { console.error(result.problems.join('\n')); process.exitCode = 1 }
  else console.log(`IPC contract: ${result.registered.length} main/preload/shared request channels`)
}
