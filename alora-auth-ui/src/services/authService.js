import { api } from './apiClient'

export async function resetPassword(token, new_password) {
  const res = await api.post('/auth/reset-password', { token, new_password })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error ?? 'Failed to reset password')
  }
}

export async function authorize(email, password, { productId, redirectUrl, codeChallenge, codeChallengeMethod, state }) {
  const res = await api.post('/auth/authorize', {
    email, password,
    product_id:            productId,
    redirect_url:          redirectUrl,
    code_challenge:        codeChallenge,
    code_challenge_method: codeChallengeMethod,
    ...(state != null && { state }),
  })
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error ?? 'Authorization failed')
  }
  const { code } = await res.json()
  return code
}

/**
 * Build the Google OAuth initiation URL.
 * Embeds all PKCE params in the request so the Google callback can issue
 * an authorization code — identical to the password login flow.
 * The product app exchanges the code via POST /auth/token with the code_verifier.
 */
export function getGoogleAuthUrl({ productId, redirectUrl, codeChallenge, codeChallengeMethod, state }) {
  const params = new URLSearchParams({
    product_id:            productId,
    redirect_url:          redirectUrl,
    code_challenge:        codeChallenge,
    code_challenge_method: codeChallengeMethod,
  })
  if (state != null) params.set('state', state)
  return `/auth/google?${params}`
}
