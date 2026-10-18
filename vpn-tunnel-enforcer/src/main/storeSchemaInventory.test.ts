// AT-00-006 / F-074: new/duplicate entrypoints must share the schema guard.
import { describe, expect, it } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { STORE_SCHEMA_VERSIONS } from './storeSchema'

function sources(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = join(directory, entry.name)
    return entry.isDirectory() ? sources(path) : entry.name.endsWith('.ts') && !/\.(test|spec|itest)\.ts$/.test(entry.name) ? [path] : []
  })
}

describe('persisted store inventory', () => {
  it('routes every production constructor through a registered version guard', () => {
    const names = new Set<string>()
    for (const path of sources('src/main')) {
      const source = ts.createSourceFile(path, readFileSync(path, 'utf8'), ts.ScriptTarget.Latest, true)
      const aliases = new Set<string>()
      for (const statement of source.statements) {
        if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue
        const module = statement.moduleSpecifier.text
        if (module === 'electron-store' && !statement.importClause?.isTypeOnly) {
          expect(path, 'Only the guarded adapter may import electron-store at runtime').toBe(join('src/main', 'versionedStore.ts'))
        }
        if (module.endsWith('/versionedStore') && statement.importClause?.name) aliases.add(statement.importClause.name.text)
      }
      function visit(node: ts.Node) {
        if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && aliases.has(node.expression.text)) {
          const options = node.arguments?.[0]
          expect(options && ts.isObjectLiteralExpression(options), path).toBe(true)
          if (!options || !ts.isObjectLiteralExpression(options)) return
          const name = options.properties.find(p => p.name?.getText(source) === 'name')
          expect(name && ts.isPropertyAssignment(name) && ts.isStringLiteral(name.initializer), path).toBe(true)
          if (name && ts.isPropertyAssignment(name) && ts.isStringLiteral(name.initializer)) {
            expect(Object.hasOwn(STORE_SCHEMA_VERSIONS, name.initializer.text), path).toBe(true)
            names.add(name.initializer.text)
          }
        }
        ts.forEachChild(node, visit)
      }
      visit(source)
    }
    expect([...names].sort()).toEqual(Object.keys(STORE_SCHEMA_VERSIONS).sort())
  })
})
