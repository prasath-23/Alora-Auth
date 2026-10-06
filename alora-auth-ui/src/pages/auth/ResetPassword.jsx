import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { resetPassword } from '../../services/authService'
import AuthCard from '../../components/auth/AuthCard'
import Input from '../../components/ui/Input'
import Button from '../../components/ui/Button'
import Alert from '../../components/ui/Alert'
import { LIMITS } from '../../utils/limits'

export default function ResetPassword() {
  const [params] = useSearchParams()
  const token = params.get('token')

  const [password, setPassword] = useState('')
  const [confirm, setConfirm]   = useState('')
  const [error, setError]       = useState(null)
  const [saving, setSaving]     = useState(false)
  const [done, setDone]         = useState(false)

  async function submit(e) {
    e.preventDefault()
    if (password !== confirm) { setError('The passwords do not match.'); return }
    setSaving(true)
    setError(null)
    try {
      await resetPassword(token, password)
      setDone(true)
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  if (!token) {
    return (
      <AuthCard title="Invalid link">
        <p className="text-center text-sm text-gray-500">This password reset link is incomplete.</p>
        <p className="text-center"><Link to="/login" className="text-sm text-brand-600 hover:underline">Back to sign-in</Link></p>
      </AuthCard>
    )
  }

  if (done) {
    return (
      <AuthCard title="Password updated">
        <Alert type="success">Your password was changed and every session was signed out.</Alert>
        <p className="text-center"><Link to="/login" className="text-sm font-medium text-brand-600 hover:underline">Sign in with your new password →</Link></p>
      </AuthCard>
    )
  }

  return (
    <AuthCard title="Choose a new password" subtitle="At least 8 characters.">
      {error && <Alert type="error" onClose={() => setError(null)}>{error}</Alert>}
      <form onSubmit={submit} className="space-y-4">
        <Input
          id="new-password" maxLength={LIMITS.password} label="New password" type="password" autoComplete="new-password" required minLength={8}
          value={password} onChange={e => setPassword(e.target.value)}
        />
        <Input
          id="confirm-password" maxLength={LIMITS.password} label="Confirm new password" type="password" autoComplete="new-password" required minLength={8}
          value={confirm} onChange={e => setConfirm(e.target.value)}
          error={confirm && password !== confirm ? 'The passwords do not match.' : undefined}
        />
        <Button type="submit" loading={saving} className="w-full">Update password</Button>
      </form>
    </AuthCard>
  )
}
