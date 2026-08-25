import { useState, useEffect } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import Input   from '../../components/ui/Input'
import Button  from '../../components/ui/Button'
import Alert   from '../../components/ui/Alert'
import Spinner from '../../components/ui/Spinner'

const API = import.meta.env.VITE_API_URL ?? 'http://localhost:3001'

async function lookupInvitation(token) {
  const res  = await fetch(`${API}/auth/accept-invitation/lookup?token=${encodeURIComponent(token)}`)
  const body = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(body.error ?? 'Invalid or expired invitation link')
  return body
}

async function acceptWithPassword(token, password) {
  const res = await fetch(`${API}/auth/accept-invitation`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ token, password }),
  })
  if (res.status === 204) return
  const body = await res.json().catch(() => ({}))
  throw new Error(body.error ?? 'Failed to create account')
}

async function acceptWithGoogle(token) {
  const res = await fetch(`${API}/auth/accept-invitation/google`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ token }),
  })
  if (res.status === 204) return
  const body = await res.json().catch(() => ({}))
  throw new Error(body.error ?? 'Failed to create account')
}

export default function AcceptInvitation() {
  const [params]   = useSearchParams()
  const navigate   = useNavigate()
  const token      = params.get('token') ?? ''

  const [invite,    setInvite]    = useState(null)
  const [loading,   setLoading]   = useState(true)
  const [error,     setError]     = useState(null)
  const [password,  setPassword]  = useState('')
  const [password2, setPassword2] = useState('')
  const [saving,    setSaving]    = useState(false)
  const [done,      setDone]      = useState(null)  // 'password' | 'google'

  useEffect(() => {
    if (!token) { setError('Missing invitation token.'); setLoading(false); return }
    lookupInvitation(token)
      .then(data  => setInvite(data))
      .catch(err  => setError(err.message))
      .finally(() => setLoading(false))
  }, [token])

  async function handlePasswordSubmit(e) {
    e.preventDefault()
    if (password !== password2) { setError('Passwords do not match'); return }
    if (password.length < 8)    { setError('Password must be at least 8 characters'); return }
    setSaving(true)
    setError(null)
    try {
      await acceptWithPassword(token, password)
      setDone('password')
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  async function handleGoogleSubmit() {
    setSaving(true)
    setError(null)
    try {
      await acceptWithGoogle(token)
      setDone('google')
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <Spinner />
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
      <div className="w-full max-w-md bg-white rounded-2xl shadow-md px-8 py-10 space-y-6">

        <div className="text-center space-y-1">
          <h1 className="text-2xl font-bold text-gray-900">Set up your account</h1>
          {invite && (
            <p className="text-sm text-gray-500">
              You've been invited to <strong>{invite.client_name}</strong>
            </p>
          )}
        </div>

        {error && !done && <Alert type="error">{error}</Alert>}

        {/* ── Invalid / expired link ─── */}
        {!invite && !loading && (
          <p className="text-sm text-gray-500 text-center">
            This invitation link is invalid or has expired. Ask your admin to send a new one.
          </p>
        )}

        {/* ── Success: password path ─── */}
        {done === 'password' && (
          <div className="space-y-4 text-center">
            <Alert type="success">Account created! You can now log in.</Alert>
            <Button className="w-full" onClick={() => navigate('/')}>Go to login</Button>
          </div>
        )}

        {/* ── Success: Google path ─── */}
        {done === 'google' && (
          <div className="space-y-3">
            <Alert type="success">Account ready!</Alert>
            <div className="rounded-md bg-blue-50 border border-blue-100 px-4 py-3 text-sm text-blue-700 space-y-1">
              <p className="font-medium">Sign in with Google</p>
              <p>Your account has been created. Go to your product app and click <strong>"Sign in with Google"</strong> using <strong>{invite?.email}</strong>.</p>
              <p className="text-xs text-blue-500 pt-1">Your Google identity will be linked on the first sign-in.</p>
            </div>
          </div>
        )}

        {/* ── Registration form ─── */}
        {invite && !done && (
          <>
            {/* Products summary */}
            <div className="rounded-md bg-gray-50 border border-gray-200 px-4 py-3 space-y-1">
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide">Access granted to</p>
              {invite.products.map(p => (
                <p key={p.key} className="text-sm text-gray-700">
                  {p.name}
                  <span className="ml-2 text-xs text-gray-400 font-medium">{p.role_name}</span>
                </p>
              ))}
            </div>

            {/* Google path */}
            {invite.google_allowed && (
              <>
                <Button
                  type="button"
                  variant="secondary"
                  className="w-full flex items-center justify-center gap-2"
                  loading={saving}
                  onClick={handleGoogleSubmit}
                >
                  <GoogleIcon />
                  Continue with Google
                </Button>

                <div className="flex items-center gap-3">
                  <hr className="flex-1 border-gray-200" />
                  <span className="text-xs text-gray-400">or set a password</span>
                  <hr className="flex-1 border-gray-200" />
                </div>
              </>
            )}

            {/* Password path */}
            <form onSubmit={handlePasswordSubmit} className="space-y-4">
              <Input
                id="email"
                label="Email"
                type="email"
                value={invite.email}
                disabled
                readOnly
              />
              <Input
                id="password"
                label="Password"
                type="password"
                required
                minLength={8}
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="At least 8 characters"
              />
              <Input
                id="password2"
                label="Confirm password"
                type="password"
                required
                value={password2}
                onChange={e => setPassword2(e.target.value)}
                placeholder="Repeat your password"
              />
              <Button type="submit" className="w-full" loading={saving} disabled={!password || !password2}>
                Create account
              </Button>
            </form>
          </>
        )}

      </div>
    </div>
  )
}

function GoogleIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" xmlns="http://www.w3.org/2000/svg">
      <path d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.716v2.259h2.908c1.702-1.567 2.684-3.875 2.684-6.615z" fill="#4285F4"/>
      <path d="M9 18c2.43 0 4.467-.806 5.956-2.18l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18z" fill="#34A853"/>
      <path d="M3.964 10.71A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.71V4.958H.957A8.996 8.996 0 0 0 0 9c0 1.452.348 2.827.957 4.042l3.007-2.332z" fill="#FBBC05"/>
      <path d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.958L3.964 7.29C4.672 5.163 6.656 3.58 9 3.58z" fill="#EA4335"/>
    </svg>
  )
}
