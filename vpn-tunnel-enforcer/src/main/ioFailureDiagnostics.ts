import { classifyIpcError } from '../shared/ipc-result'

const IO_CODES = new Set(['EACCES', 'EPERM', 'ENOENT', 'EISDIR', 'ENOTDIR', 'ENOSPC', 'EROFS',
  'EIO', 'EMFILE', 'ENFILE', 'EBADF', 'EINVAL', 'EEXIST', 'EBUSY', 'EFBIG', 'ENAMETOOLONG',
  'ETIMEDOUT', 'ECONNRESET', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'ENETUNREACH', 'EHOSTUNREACH'])
/** Keep diagnostic errno useful without accepting arbitrary exception data. */
export function ioFailureDetails(error: unknown) {
  const reason = classifyIpcError(error)
  let ioCode: string | undefined
  try {
    const code = error && typeof error === 'object' ? Object.getOwnPropertyDescriptor(error, 'code')?.value : undefined
    if (typeof code === 'string' && IO_CODES.has(code)) ioCode = code
  } catch { /* Unreadable exceptions still retain their bounded category. */ }
  return { reason, ...(ioCode ? { ioCode } : {}) }
}
