import { useSearchParams } from 'react-router-dom'
import LoginForm from '../../components/auth/LoginForm'
import Alert     from '../../components/ui/Alert'

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const GOOGLE_ERROR_MESSAGES = {
  not_linked:       'This Google account is not linked to any workspace account. Contact your administrator.',
  no_access:        "You don't have access to this product. Contact your administrator.",
  account_disabled: 'Your account has been disabled. Contact your administrator.',
  google_not_allowed: 'Google sign-in is not enabled for your workspace.',
  tenant_inactive:  'Your workspace is inactive. Contact your administrator.',
  invalid_product:  'Invalid product. Please try again.',
  invalid_redirect: 'Invalid redirect URL. Please try again.',
}

export default function Login() {
  const [params] = useSearchParams()

  const productId           = params.get('product_id')
  const redirectUrl         = params.get('redirect_url')
  const codeChallenge       = params.get('code_challenge')
  const codeChallengeMethod = params.get('code_challenge_method')
  const googleError         = params.get('google_error')
  const state               = params.get('state')
  // scope intentionally ignored — permissions are JWT-embedded via product roles

  // Validate all required PKCE params are present and well-formed
  const missing = []
  if (!productId)           missing.push('product_id')
  if (!redirectUrl)         missing.push('redirect_url')
  if (!codeChallenge)       missing.push('code_challenge')
  if (!codeChallengeMethod) missing.push('code_challenge_method')
  if (!state)               missing.push('state')

  if (missing.length > 0) {
    return <ParamError message={`Missing required parameter${missing.length > 1 ? 's' : ''}: ${missing.join(', ')}`} />
  }

  if (!UUID_RE.test(productId)) {
    return <ParamError message="Invalid product_id format." />
  }

  if (codeChallengeMethod !== 'S256') {
    return <ParamError message={`Unsupported code_challenge_method "${codeChallengeMethod}". Only S256 is accepted.`} />
  }

  try { new URL(redirectUrl) } catch {
    return <ParamError message="Invalid redirect_url: must be a valid URL." />
  }

  return (
    <LoginForm
      productId           = {productId}
      redirectUrl         = {redirectUrl}
      codeChallenge       = {codeChallenge}
      codeChallengeMethod = {codeChallengeMethod}
      googleError         = {googleError ? (GOOGLE_ERROR_MESSAGES[googleError] ?? 'Google sign-in failed. Please try again.') : null}
      state               = {state}
    />
  )
}

function ParamError({ message }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50 px-4">
      <div className="w-full max-w-md rounded-xl bg-white p-8 shadow-md">
        <h1 className="mb-4 text-xl font-bold text-gray-900 text-center">Alora Auth</h1>
        <Alert type="error">{message}</Alert>
        <p className="mt-3 text-xs text-gray-400 text-center">
          Launch this page from your application with the required OAuth parameters.
        </p>
      </div>
    </div>
  )
}
