import { useEffect, useState } from 'react'
import { Navigate, useNavigate, useSearchParams } from 'react-router-dom'
import useAuthStore from '../../store/authStore'
import { establish } from '../../services/session'
import {
  chooseCompany, discover, googleStartURL, loginChoices, passwordLogin, ssoStartURL,
} from '../../services/authService'
import { isServerPath, safeReturnTo } from '../../utils/returnTo'
import AuthCard from '../../components/auth/AuthCard'
import Input from '../../components/ui/Input'
import Button from '../../components/ui/Button'
import Alert from '../../components/ui/Alert'
import Spinner from '../../components/ui/Spinner'
import { LIMITS } from '../../utils/limits'

// Identifier-first sign-in. The address comes first; its DOMAIN decides which
// methods to offer (the same answer for every address there, so the page never
// reveals whether an account exists). Whatever is offered, the API enforces
// the login policy at the end of every path — this page only lays them out.

// The codes the API's Google and SSO callbacks send back (?google_error=,
// ?sso_error=). Never provider text, so each maps to a fixed message.
const CALLBACK_MESSAGES = {
  invalid_request:     'The sign-in request was incomplete. Please start again.',
  state_mismatch:      'Your sign-in could not be verified in this browser. Please try again.',
  state_expired:       'Your sign-in took too long. Please try again.',
  exchange_failed:     '%s could not confirm your sign-in. Please try again.',
  email_unverified:    'Your address is not verified with %s. Verify it, then try again.',
  account_unavailable: 'There is no account here that you can sign in to with %s. Contact your administrator.',
  sso_unavailable:     'Single sign-on is not available for this address.',
  google_disabled:     'Google sign-in is not available.',
  server_error:        'Something went wrong signing you in. Please try again.',
  cancelled:           'Sign-in was cancelled.',
}

function callbackMessage(params) {
  const google = params.get('google_error')
  const sso = params.get('sso_error')
  const code = google ?? sso
  if (!code) return null
  const provider = google ? 'Google' : 'your identity provider'
  const template = CALLBACK_MESSAGES[code] ?? 'Sign-in failed. Please try again.'
  const text = template.replace('%s', provider)
  return text.charAt(0).toUpperCase() + text.slice(1)
}

function failureMessage(err) {
  if (err?.status === 401) return 'Invalid email or password.'
  if (err?.status === 429) return 'Too many attempts. Wait a minute, then try again.'
  if (err?.status === undefined) return 'App Central could not be reached. Check your connection and try again.'
  return err.message
}

export default function Login() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const status = useAuthStore(s => s.status)
  const notice = useAuthStore(s => s.notice)

  const returnTo = safeReturnTo(params.get('return_to') ?? '')
  const choosing = params.get('choose') === '1'

  const [step, setStep]           = useState(choosing ? 'loading' : 'email')
  const [email, setEmail]         = useState('')
  const [methods, setMethods]     = useState(null)
  const [password, setPassword]   = useState('')
  const [companies, setCompanies] = useState([])
  const [error, setError]         = useState(() => callbackMessage(params))
  const [busy, setBusy]           = useState(false)

  // Coming back from Google or SSO with accounts in several companies.
  useEffect(() => {
    if (!choosing) return
    loginChoices()
      .then(res => { setCompanies(res.companies); setStep('choose') })
      .catch(() => { setError('Your sign-in expired. Please start again.'); setStep('email') })
  }, [choosing])

  // Signed in with nothing to resume: straight to the launcher. With a
  // return_to the form stays — that is how a product asks for a fresh sign-in.
  if (status === 'authenticated' && !returnTo && !choosing) return <Navigate to="/" replace />

  function follow(target) {
    const safe = safeReturnTo(target ?? '')
    if (safe && isServerPath(safe)) {
      window.location.assign(safe) // e.g. resuming /oauth/authorize: the API answers it
      return
    }
    navigate(safe || '/', { replace: true })
  }

  async function finish(res) {
    if (res.status === 'choose_company') {
      setCompanies(res.companies)
      setStep('choose')
      return
    }
    await establish(res.access_token)
    follow(res.return_to)
  }

  async function submitEmail(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      setMethods(await discover(email.trim()))
      setStep('methods')
    } catch (err) {
      setError(failureMessage(err))
    } finally {
      setBusy(false)
    }
  }

  async function submitPassword(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await finish(await passwordLogin(email.trim(), password, returnTo))
    } catch (err) {
      setError(failureMessage(err))
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  async function pick(company) {
    setBusy(true)
    setError(null)
    try {
      await finish(await chooseCompany(company.client_id))
    } catch (err) {
      setError(err?.status === 401 ? 'Your sign-in expired. Please start again.' : failureMessage(err))
      if (err?.status === 401) setStep('email')
    } finally {
      setBusy(false)
    }
  }

  function startOver() {
    setStep('email')
    setMethods(null)
    setPassword('')
    setError(null)
  }

  const offersNothing = methods && !methods.password && !methods.google && !methods.sso

  return (
    <AuthCard title="Sign in to App Central" subtitle={step === 'choose' ? null : 'One sign-in for every Alora app'}>
      {notice && step === 'email' && <Alert type="info">{notice}</Alert>}
      {error && <Alert type="error">{error}</Alert>}

      {step === 'loading' && <div className="flex justify-center py-6"><Spinner /></div>}

      {step === 'email' && (
        <form onSubmit={submitEmail} className="space-y-4" noValidate>
          <Input
            id="email" maxLength={LIMITS.email} label="Email" type="email" autoComplete="username" autoFocus required
            value={email} onChange={e => setEmail(e.target.value)}
          />
          <Button type="submit" className="w-full" loading={busy} disabled={!email.trim()}>Continue</Button>
        </form>
      )}

      {step === 'methods' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between rounded-md bg-gray-50 px-3 py-2 text-sm">
            <span className="truncate text-gray-700" data-testid="login-email">{email}</span>
            <button type="button" onClick={startOver} className="ml-3 shrink-0 text-brand-600 hover:underline">Change</button>
          </div>

          {methods.password && (
            <form onSubmit={submitPassword} className="space-y-4">
              <Input
                id="password" maxLength={LIMITS.password} label="Password" type="password" autoComplete="current-password" autoFocus required
                value={password} onChange={e => setPassword(e.target.value)}
              />
              <Button type="submit" className="w-full" loading={busy} disabled={!password}>Sign in</Button>
            </form>
          )}

          {methods.password && (methods.sso || methods.google) && <Divider>or</Divider>}

          {methods.sso && (
            <Button
              variant={methods.password ? 'secondary' : 'primary'} className="w-full"
              onClick={() => window.location.assign(ssoStartURL({ connectionId: methods.sso.connection_id, returnTo }))}
            >
              Continue with single sign-on
            </Button>
          )}

          {methods.google && (
            <Button variant="secondary" className="w-full" onClick={() => window.location.assign(googleStartURL(returnTo))}>
              <GoogleIcon /> Continue with Google
            </Button>
          )}

          {offersNothing && (
            <Alert type="warning">No sign-in method is available for this address. Contact your administrator.</Alert>
          )}
        </div>
      )}

      {step === 'choose' && (
        <div className="space-y-3">
          <div>
            <h2 className="text-base font-semibold text-gray-900">Choose a company</h2>
            <p className="mt-1 text-sm text-gray-500">Your address has accounts in more than one company. Which one do you want?</p>
          </div>
          <ul className="space-y-2" aria-label="Companies">
            {companies.map(c => (
              <li key={c.client_id}>
                <button
                  type="button" disabled={busy} onClick={() => pick(c)}
                  className="w-full rounded-md border border-gray-200 px-4 py-3 text-left text-sm font-medium text-gray-800 hover:border-brand-500 hover:bg-brand-50 disabled:opacity-50"
                >
                  {c.name}
                </button>
              </li>
            ))}
          </ul>
          <button type="button" onClick={startOver} className="text-sm text-gray-500 hover:underline">Use another address</button>
        </div>
      )}
    </AuthCard>
  )
}

function Divider({ children }) {
  return (
    <div className="flex items-center gap-3">
      <hr className="flex-1 border-gray-200" />
      <span className="text-xs text-gray-400">{children}</span>
      <hr className="flex-1 border-gray-200" />
    </div>
  )
}

export function GoogleIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true">
      <path d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.716v2.259h2.908c1.702-1.567 2.684-3.875 2.684-6.615z" fill="#4285F4" />
      <path d="M9 18c2.43 0 4.467-.806 5.956-2.18l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18z" fill="#34A853" />
      <path d="M3.964 10.71A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.71V4.958H.957A8.996 8.996 0 0 0 0 9c0 1.452.348 2.827.957 4.042l3.007-2.332z" fill="#FBBC05" />
      <path d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.958L3.964 7.29C4.672 5.163 6.656 3.58 9 3.58z" fill="#EA4335" />
    </svg>
  )
}
