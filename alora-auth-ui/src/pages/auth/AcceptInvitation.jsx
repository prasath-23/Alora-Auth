import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { acceptInvitation, acceptInvitationFederated, lookupInvitation } from '../../services/authService'
import AuthCard from '../../components/auth/AuthCard'
import Input from '../../components/ui/Input'
import Button from '../../components/ui/Button'
import Alert from '../../components/ui/Alert'
import Spinner from '../../components/ui/Spinner'
import { LIMITS } from '../../utils/limits'

// The invite link's landing page. The preview says which company and groups the
// invitation joins and how the invitee will sign in — decided by the login
// policy they will have, so the page offers only what will actually work.
export default function AcceptInvitation() {
  const [params] = useSearchParams()
  const token = params.get('token') ?? ''

  const [invite, setInvite]       = useState(null)
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState(null)
  const [password, setPassword]   = useState('')
  const [password2, setPassword2] = useState('')
  const [saving, setSaving]       = useState(false)
  const [done, setDone]           = useState(null) // 'password' | 'federated'

  useEffect(() => {
    if (!token) {
      setError('This invitation link is incomplete.')
      setLoading(false)
      return
    }
    lookupInvitation(token)
      .then(setInvite)
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [token])

  async function submitPassword(e) {
    e.preventDefault()
    if (password.length < 8) { setError('Use at least 8 characters.'); return }
    if (password !== password2) { setError('The passwords do not match.'); return }
    setSaving(true)
    setError(null)
    try {
      await acceptInvitation(token, password)
      setDone('password')
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  async function submitFederated() {
    setSaving(true)
    setError(null)
    try {
      await acceptInvitationFederated(token)
      setDone('federated')
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return <AuthCard><div className="flex justify-center py-6"><Spinner /></div></AuthCard>
  }

  const federated = invite && (invite.methods.google || invite.methods.sso)
  const federatedName = invite?.methods.sso ? 'your company’s single sign-on' : 'Google'

  return (
    <AuthCard
      title="Set up your account"
      subtitle={invite ? <>You have been invited to <strong>{invite.client_name}</strong></> : null}
    >
      {error && !done && <Alert type="error">{error}</Alert>}

      {!invite && (
        <p className="text-center text-sm text-gray-500">
          This invitation is invalid, expired or already used. Ask your administrator for a new one.
        </p>
      )}

      {done && (
        <div className="space-y-4 text-center">
          <Alert type="success">
            {done === 'password'
              ? 'Your account is ready. Sign in with your new password.'
              : `Your account is ready. Sign in with ${federatedName} using ${invite.email}.`}
          </Alert>
          <Link to="/login" className="inline-block text-sm font-medium text-brand-600 hover:underline">Go to sign-in →</Link>
        </div>
      )}

      {invite && !done && (
        <>
          <dl className="space-y-1 rounded-md border border-gray-200 bg-gray-50 px-4 py-3 text-sm">
            <div className="flex justify-between gap-4"><dt className="text-gray-500">Email</dt><dd className="truncate text-gray-900">{invite.email}</dd></div>
            {invite.groups.length > 0 && (
              <div className="flex justify-between gap-4"><dt className="text-gray-500">Groups</dt><dd className="text-gray-900">{invite.groups.join(', ')}</dd></div>
            )}
          </dl>

          {federated && (
            <Button className="w-full" variant={invite.methods.password ? 'secondary' : 'primary'} loading={saving} onClick={submitFederated}>
              Create my account for {federatedName}
            </Button>
          )}

          {federated && invite.methods.password && (
            <p className="text-center text-xs text-gray-400">or choose a password</p>
          )}

          {invite.methods.password && (
            <form onSubmit={submitPassword} className="space-y-4">
              <Input
                id="password" maxLength={LIMITS.password} label="Password" type="password" autoComplete="new-password" required minLength={8}
                value={password} onChange={e => setPassword(e.target.value)} placeholder="At least 8 characters"
              />
              <Input
                id="password2" maxLength={LIMITS.password} label="Confirm password" type="password" autoComplete="new-password" required
                value={password2} onChange={e => setPassword2(e.target.value)}
              />
              <Button type="submit" className="w-full" loading={saving} disabled={!password || !password2}>
                Create account
              </Button>
            </form>
          )}

          {!federated && !invite.methods.password && (
            <Alert type="warning">No sign-in method is available for this invitation. Contact your administrator.</Alert>
          )}
        </>
      )}
    </AuthCard>
  )
}
