// The browser-side twin of the API's shared.SafeReturnTo. The server cleans
// every return_to it hands back; this is the second check, for the paths the
// SPA follows on its own (and for anything read straight from the address bar).
//
// Only a path on App Central's own origin passes. Browsers resolve
// "//evil.example" and "/\evil.example" to another host, read a backslash as a
// slash, and strip tabs and newlines before parsing, so each is refused rather
// than normalised.
export function safeReturnTo(value) {
  if (typeof value !== 'string' || value === '' || value.length > 2048 || value[0] !== '/') return ''
  for (const ch of value) {
    const code = ch.codePointAt(0)
    if (code < 0x20 || code === 0x7f || ch === '\\') return ''
  }
  if (value.startsWith('//')) return ''
  try {
    const probe = 'https://app-central.invalid'
    if (new URL(value, probe).origin !== probe) return ''
  } catch {
    return ''
  }
  return value
}

// Paths the API serves rather than the SPA. Following one needs a real
// navigation, so the request carries the session cookie to the server.
const SERVER_PREFIXES = ['/oauth/', '/auth/', '/api/', '/.well-known/']

export function isServerPath(path) {
  return SERVER_PREFIXES.some(p => path.startsWith(p))
}
