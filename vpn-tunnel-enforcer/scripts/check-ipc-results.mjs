import ts from 'typescript'

const walk = (node, visit) => { visit(node); ts.forEachChild(node, child => walk(child, visit)) }
const isHandle = node => ts.isCallExpression(node) && node.expression.getText() === 'ipcMain.handle'

function containsAny(checker, type, seen = new Set()) {
  if (type.flags & ts.TypeFlags.Any) return true
  if (seen.has(type)) return false
  seen.add(type)
  if (type.isUnionOrIntersection()) return type.types.some(child => containsAny(checker, child, seen))
  if (!(type.flags & ts.TypeFlags.Object)) return false
  if (checker.isArrayType(type) || checker.isTupleType(type)) return checker.getTypeArguments(type).some(child => containsAny(checker, child, seen))
  return [type.getStringIndexType(), type.getNumberIndexType(),
    ...type.getProperties().map(property => checker.getTypeOfSymbol(property))]
    .some(child => child && containsAny(checker, child, seen))
}

/** Check the actual listener, including local registration wrappers, against the bridge API. */
export function inspectIpcResults(program, { declared, mainFiles, apiFile }) {
  const checker = program.getTypeChecker(), problems = [], legacy = [], checked = []
  const api = program.getSourceFile(apiFile)?.statements.find(node => ts.isInterfaceDeclaration(node) && node.name.text === 'ElectronAPI')
  if (!api) return { problems: ['Missing ElectronAPI result declarations'], checked, legacy }
  const apiType = checker.getTypeAtLocation(api)
  const methods = new Map(declared.map(({ channel, method }) => [channel, method]))
  for (const file of mainFiles) {
    const source = program.getSourceFile(file)
    if (!source) { problems.push(`Missing IPC source: ${file}`); continue }
    const wrappers = new Set()
    walk(source, node => {
      if (!isHandle(node) || ts.isStringLiteral(node.arguments[0])) return
      let parent = node.parent
      while (parent && !ts.isFunctionDeclaration(parent)) parent = parent.parent
      if (parent?.name && parent.parameters[0]?.name.getText() === node.arguments[0]?.getText()) wrappers.add(parent.name.text)
    })
    walk(source, node => {
      if (!ts.isCallExpression(node) || (!isHandle(node) && !wrappers.has(node.expression.getText()))) return
      const [channel, listener] = node.arguments
      if (!channel || !ts.isStringLiteral(channel) || !methods.has(channel.text)) return
      const method = apiType.getProperty(methods.get(channel.text))
      const actualSignature = listener && checker.getSignaturesOfType(checker.getTypeAtLocation(listener), ts.SignatureKind.Call)[0]
      const expectedSignature = method && checker.getSignaturesOfType(checker.getTypeOfSymbolAtLocation(method, api), ts.SignatureKind.Call)[0]
      if (!actualSignature || !expectedSignature) { problems.push(`Unresolved IPC result: ${channel.text}`); return }
      const actual = checker.getAwaitedType(checker.getReturnTypeOfSignature(actualSignature))
      const expected = checker.getAwaitedType(checker.getReturnTypeOfSignature(expectedSignature))
      checked.push(channel.text)
      const publicAny = containsAny(checker, expected)
      if (!checker.isTypeAssignableTo(actual, expected) || (!publicAny && containsAny(checker, actual))) {
        problems.push(`IPC result mismatch: ${channel.text}: ${checker.typeToString(actual)} is not assignable to ${checker.typeToString(expected)}`)
      }
      if (publicAny) legacy.push(channel.text)
    })
  }
  for (const { channel } of declared) if (!checked.includes(channel)) problems.push(`Unchecked IPC result: ${channel}`)
  return { problems, checked, legacy }
}

export function checkIpcResults(root, inventory) {
  const configPath = ts.findConfigFile(root, ts.sys.fileExists, 'tsconfig.json')
  if (!configPath) return { problems: ['Missing tsconfig for IPC result check'], checked: [], legacy: [] }
  const config = ts.readConfigFile(configPath, ts.sys.readFile)
  if (config.error) return { problems: [ts.flattenDiagnosticMessageText(config.error.messageText, '\n')], checked: [], legacy: [] }
  const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, root)
  if (parsed.errors.length) return { problems: parsed.errors.map(error => ts.flattenDiagnosticMessageText(error.messageText, '\n')), checked: [], legacy: [] }
  const program = ts.createProgram(parsed.fileNames, parsed.options)
  return inspectIpcResults(program, { declared: inventory.declared, mainFiles: inventory.mainFiles, apiFile: `${root}/src/shared/electron-api.ts` })
}
