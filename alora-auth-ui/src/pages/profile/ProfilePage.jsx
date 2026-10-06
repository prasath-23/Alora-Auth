import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import useAuthStore from '../../store/authStore'
import { changePassword } from '../../services/meService'
import { forget } from '../../services/session'
import { FEATURES } from '../../utils/scopes'
import { formatDate } from '../../utils/format'
import { Badge, Card, EmptyState, PageHeader } from '../../components/ui/Layout'
import ScopeGrid from '../../components/company/ScopeGrid'
import Input from '../../components/ui/Input'
import Button from '../../components/ui/Button'
import ErrorAlert from '../../components/ui/ErrorAlert'
import Alert from '../../components/ui/Alert'
import { LIMITS } from '../../utils/limits'

export default function ProfilePage() {
  const me = useAuthStore(s => s.me)
  const navigate = useNavigate()

  const [current, setCurrent] = useState('')
  const [next, setNext]       = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError]     = useState(null)
  const [mismatch, setMismatch] = useState(false)
  const [saving, setSaving]   = useState(false)

  async function submit(e) {
    e.preventDefault()
    if (next !== confirm) { setMismatch(true); return }
    setMismatch(false)
    setSaving(true)
    setError(null)
    try {
      await changePassword(current, next)
      // The API signs out every session of the account, this one included.
      forget('Your password was changed and every session was signed out. Sign in with your new password.')
      navigate('/login', { replace: true })
    } catch (err) {
      setError(err)
      setSaving(false)
    }
  }

  return (
    <div className="max-w-2xl space-y-6">
      <PageHeader title="Profile" />

      <Card title="Account">
        <dl className="grid grid-cols-3 gap-y-2 text-sm">
          <dt className="text-gray-500">Email</dt><dd className="col-span-2 text-gray-900">{me.email}</dd>
          <dt className="text-gray-500">Company</dt><dd className="col-span-2 text-gray-900">{me.company.name}</dd>
          <dt className="text-gray-500">Signed in</dt><dd className="col-span-2 text-gray-900">{formatDate(me.authenticated_at)}</dd>
          <dt className="text-gray-500">Roles</dt>
          <dd className="col-span-2 flex gap-1">
            {me.is_owner && <Badge tone="amber">Owner</Badge>}
            {me.is_admin && <Badge tone="brand">Admin</Badge>}
            {!me.is_owner && !me.is_admin && <span className="text-gray-400">Member</span>}
          </dd>
        </dl>
      </Card>

      <YourAccess me={me} />

      <Card title="Change password">
        <form onSubmit={submit} className="space-y-4">
          <ErrorAlert error={error} onClose={() => setError(null)} />
          {mismatch && <Alert type="error">The new passwords do not match.</Alert>}
          <Input id="current-password" maxLength={LIMITS.password} label="Current password" type="password" autoComplete="current-password" required
            value={current} onChange={e => setCurrent(e.target.value)} />
          <Input id="new-password" maxLength={LIMITS.password} label="New password" hint="(at least 8 characters)" type="password" autoComplete="new-password"
            required minLength={8} value={next} onChange={e => setNext(e.target.value)} />
          <Input id="confirm-password" maxLength={LIMITS.password} label="Confirm new password" type="password" autoComplete="new-password" required
            value={confirm} onChange={e => setConfirm(e.target.value)} />
          <p className="text-xs text-gray-500">Changing your password signs you out everywhere, including every app.</p>
          <Button type="submit" loading={saving} disabled={!current || !next || !confirm}>Change password</Button>
        </form>
      </Card>
    </div>
  )
}

// What the signed-in person may do in App Central, where each part comes from,
// and what their sign-in token says about it: the scope list, and the apps they
// may open (each app's own token carries their roles there).
function YourAccess({ me }) {
  const sources = {}
  for (const f of FEATURES) {
    const names = new Set()
    for (const s of me.scope_sources) {
      if (s.scope === f.read || s.scope === f.edit) names.add(s.source === 'EXTRA' ? 'Extra access' : s.group_name)
    }
    if (names.size) sources[f.key] = [...names].join(', ')
  }
  return (
    <Card title="Your access">
      <div className="space-y-5">
        {me.is_owner && (
          <p className="text-sm text-gray-700"><Badge tone="amber">Owner</Badge> You manage every company, whatever the table below says.</p>
        )}
        <ScopeGrid value={me.scopes} sources={sources} />
        <div>
          <h3 className="text-sm font-medium text-gray-900">Apps you can open</h3>
          {me.products.length === 0 ? <EmptyState>None yet.</EmptyState> : (
            <ul className="mt-2 flex flex-wrap gap-2" data-testid="my-products">
              {me.products.map(k => <li key={k}><Badge>{k}</Badge></li>)}
            </ul>
          )}
        </div>
        {me.manages.length > 0 && (
          <div>
            <h3 className="text-sm font-medium text-gray-900">Groups you manage</h3>
            <ul className="mt-2 flex flex-wrap gap-2" data-testid="my-managed-groups">
              {me.manages.map(g => (
                <li key={g.id}>
                  <Link to={`/admin/my-groups/${g.id}`} className="text-sm text-brand-600 hover:underline">{g.name}</Link>
                </li>
              ))}
            </ul>
            <p className="mt-1 text-xs text-gray-500">You add and remove their members; what each gives is set by your company&apos;s Admins.</p>
          </div>
        )}
        <div>
          <h3 className="text-sm font-medium text-gray-900">In your sign-in token</h3>
          <p className="mt-1 text-xs text-gray-500">
            The <code>scope</code> claim, as it was when you signed in. App Central checks your access again on every request.
          </p>
          <pre className="mt-2 overflow-x-auto rounded-md bg-gray-50 px-3 py-2 text-xs text-gray-700" data-testid="my-scope">{me.scopes.join(' ')}</pre>
        </div>
      </div>
    </Card>
  )
}
