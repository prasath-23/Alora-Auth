import { useState } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import { resetPassword } from '../../services/authService'
import Input  from '../../components/ui/Input'
import Button from '../../components/ui/Button'
import Alert  from '../../components/ui/Alert'

export default function ResetPassword() {
  const [params] = useSearchParams()
  const token    = params.get('token')

  const [newPassword,     setNewPassword]     = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error,           setError]           = useState(null)
  const [loading,         setLoading]         = useState(false)
  const [done,            setDone]            = useState(false)

  if (!token) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-50 px-4">
        <div className="w-full max-w-md rounded-xl bg-white p-8 shadow-md text-center space-y-4">
          <h1 className="text-xl font-bold text-gray-900">Invalid link</h1>
          <p className="text-sm text-gray-500">This password reset link is missing or malformed.</p>
          <Link to="/" className="text-sm text-brand-600 hover:underline">Return to login</Link>
        </div>
      </div>
    )
  }

  if (done) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-50 px-4">
        <div className="w-full max-w-md rounded-xl bg-white p-8 shadow-md text-center space-y-4">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-green-100">
            <svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <h1 className="text-xl font-bold text-gray-900">Password updated</h1>
          <p className="text-sm text-gray-500">
            Your password has been changed. All active sessions have been signed out for security.
          </p>
          <Link to="/" className="inline-block text-sm text-brand-600 hover:underline">
            Sign in with your new password →
          </Link>
        </div>
      </div>
    )
  }

  async function handleSubmit(e) {
    e.preventDefault()
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match')
      return
    }
    setError(null)
    setLoading(true)
    try {
      await resetPassword(token, newPassword)
      setDone(true)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50 px-4">
      <div className="w-full max-w-md space-y-6 rounded-xl bg-white p-8 shadow-md">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-gray-900">Set new password</h1>
          <p className="mt-1 text-sm text-gray-500">Choose a strong password of at least 8 characters.</p>
        </div>

        {error && <Alert type="error" onClose={() => setError(null)}>{error}</Alert>}

        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            id="new-password"
            label="New password"
            type="password"
            autoComplete="new-password"
            required
            minLength={8}
            value={newPassword}
            onChange={e => setNewPassword(e.target.value)}
          />
          <Input
            id="confirm-password"
            label="Confirm new password"
            type="password"
            autoComplete="new-password"
            required
            minLength={8}
            value={confirmPassword}
            onChange={e => setConfirmPassword(e.target.value)}
            error={confirmPassword && newPassword !== confirmPassword ? 'Passwords do not match' : undefined}
          />
          <Button type="submit" loading={loading} className="w-full">
            Update password
          </Button>
        </form>
      </div>
    </div>
  )
}
