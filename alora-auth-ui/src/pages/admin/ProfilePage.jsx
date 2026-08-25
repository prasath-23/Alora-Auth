import { useState } from 'react'
import useAuthStore from '../../store/authStore'
import { changeMyPassword } from '../../services/adminService'
import Input  from '../../components/ui/Input'
import Button from '../../components/ui/Button'
import Alert  from '../../components/ui/Alert'

export default function ProfilePage() {
  const token              = useAuthStore(s => s.accessToken)
  const user               = useAuthStore(s => s.user)
  const setUnauthenticated = useAuthStore(s => s.setUnauthenticated)

  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword,     setNewPassword]     = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error,           setError]           = useState(null)
  const [saving,          setSaving]          = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    if (newPassword !== confirmPassword) {
      setError('New passwords do not match')
      return
    }
    setError(null)
    setSaving(true)
    try {
      await changeMyPassword({ current_password: currentPassword, new_password: newPassword }, token)
      // Sessions are revoked server-side. setUnauthenticated(true) causes
      // ProtectedRoute to replace this page with the login panel + "signed out" notice.
      setUnauthenticated(true)
    } catch (err) {
      setError(err.message)
      setSaving(false)
    }
  }

  const roles = user?.roles ? Object.entries(user.roles) : []

  return (
    <div className="space-y-6 max-w-xl">
      <h1 className="text-2xl font-bold text-gray-900">Profile</h1>

      <div className="rounded-lg border border-gray-200 bg-white p-6 space-y-4">
        <h2 className="text-sm font-semibold text-gray-700">Account</h2>
        <div className="grid grid-cols-[auto_1fr] gap-x-8 gap-y-2 text-sm items-center">
          <span className="text-gray-500">Email</span>
          <span className="text-gray-900 font-medium">{user?.email}</span>

          <span className="text-gray-500">Global admin</span>
          <span>
            {user?.is_global_admin
              ? <span className="inline-block rounded-full bg-brand-100 px-2 py-0.5 text-xs font-medium text-brand-700">Yes</span>
              : <span className="text-gray-400 text-xs">No</span>
            }
          </span>

          {roles.length > 0 && (
            <>
              <span className="text-gray-500">Product roles</span>
              <div className="flex flex-wrap gap-1">
                {roles.map(([product, role]) => (
                  <span key={product} className="inline-block rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-700">
                    {product}: {role}
                  </span>
                ))}
              </div>
            </>
          )}

          <span className="text-gray-500">Tenant</span>
          <span className="font-mono text-xs text-gray-500">{user?.client_id}</span>
        </div>
      </div>

      <div className="rounded-lg border border-gray-200 bg-white p-6 space-y-4">
        <h2 className="text-sm font-semibold text-gray-700">Change password</h2>
        <p className="text-xs text-gray-400">
          Changing your password signs out all active sessions, including this one.
        </p>

        {error && <Alert type="error" onClose={() => setError(null)}>{error}</Alert>}

        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            id="current-pw"
            label="Current password"
            type="password"
            autoComplete="current-password"
            required
            value={currentPassword}
            onChange={e => setCurrentPassword(e.target.value)}
          />
          <Input
            id="new-pw"
            label="New password"
            type="password"
            autoComplete="new-password"
            required
            minLength={8}
            value={newPassword}
            onChange={e => setNewPassword(e.target.value)}
          />
          <Input
            id="confirm-pw"
            label="Confirm new password"
            type="password"
            autoComplete="new-password"
            required
            minLength={8}
            value={confirmPassword}
            onChange={e => setConfirmPassword(e.target.value)}
            error={confirmPassword && newPassword !== confirmPassword ? 'Passwords do not match' : undefined}
          />
          <Button
            type="submit"
            loading={saving}
            disabled={!currentPassword || !newPassword || newPassword !== confirmPassword}
          >
            Update password
          </Button>
        </form>
      </div>
    </div>
  )
}
