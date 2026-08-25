// Decode the payload of a JWT without verifying the signature.
// Signature verification happens server-side on every authenticated request.
export function parseJwtPayload(token) {
  try {
    const [, payloadB64] = token.split('.')
    return JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')))
  } catch {
    return null
  }
}
