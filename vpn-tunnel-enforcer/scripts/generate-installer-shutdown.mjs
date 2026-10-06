import { readFileSync, writeFileSync } from 'node:fs'

const source = readFileSync(new URL('../build/shutdown-for-update.ps1', import.meta.url), 'utf8')
const command = source.split(/\r?\n/).filter(line => !line.trimStart().startsWith('#')).map(line => line.trim()).join('\n')
const encoded = Buffer.from(command, 'utf16le').toString('base64')
if (encoded.length > 7000) throw new Error('Installer shutdown command exceeds the NSIS command budget')
writeFileSync(new URL('../build/shutdown-for-update.base64', import.meta.url), encoded)
console.log('[installer-shutdown] Embedded immutable EncodedCommand generated')
