import { useState, useEffect } from 'react'
import useAuthStore from '../../store/authStore'
import { useFeature, ADMIN_FEATURES } from '../../utils/features'
import { getClientInfo, updateClientInfo } from '../../services/adminService'
import Button  from '../../components/ui/Button'
import Input   from '../../components/ui/Input'
import Alert   from '../../components/ui/Alert'
import Spinner from '../../components/ui/Spinner'

export default function ClientPage() {
  const token    = useAuthStore(s => s.accessToken)
  const canEdit  = useFeature(ADMIN_FEATURES.CLIENT_EDIT)

  const [client,  setClient]  = useState(null)
  const [loading, setLoading] = useState(true)
  const [saving,  setSaving]  = useState(false)
  const [error,   setError]   = useState(null)
  const [success, setSuccess] = useState(false)

  // Edit fields
  const [name,       setName]       = useState('')
  const [requireMfa, setRequireMfa] = useState(false)

  useEffect(() => {
    getClientInfo(token)
      .then(data => {
        setClient(data)
        setName(data.name)
        setRequireMfa(data.require_mfa)
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [token])

  async function handleSave(e) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    setSuccess(false)
    try {
      await updateClientInfo({ name, require_mfa: requireMfa }, token)
      setClient(prev => ({ ...prev, name, require_mfa: requireMfa }))
      setSuccess(true)
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  if (loading) return <div className="flex justify-center py-12"><Spinner /></div>

  return (
    <div className="space-y-6 max-w-xl">
      <h1 className="text-2xl font-bold text-gray-900">Client Info</h1>

      {error   && <Alert type="error"   onClose={() => setError(null)}>{error}</Alert>}
      {success && <Alert type="success" onClose={() => setSuccess(false)}>Saved successfully.</Alert>}

      <div className="rounded-lg border border-gray-200 bg-white p-6 space-y-4">
        <div className="grid grid-cols-2 gap-4 text-sm">
          <InfoRow label="ID"                  value={client?.id} mono />
          <InfoRow label="Subscription"        value={client?.subscription_status} />
          <InfoRow label="Domain"              value={client?.domain ?? '—'} />
          <InfoRow label="Domain verified"     value={client?.domain_verified_at ? new Date(client.domain_verified_at).toLocaleDateString() : 'No'} />
          <InfoRow label="IdP providers"       value={(client?.allowed_idp_providers ?? []).join(', ')} />
          <InfoRow label="Created"             value={new Date(client?.created_at).toLocaleDateString()} />
        </div>
      </div>

      {canEdit && (
        <form onSubmit={handleSave} className="rounded-lg border border-gray-200 bg-white p-6 space-y-4">
          <h2 className="text-sm font-semibold text-gray-700">Edit</h2>
          <Input id="client-name" label="Display name" value={name}
            onChange={e => setName(e.target.value)} required />
          <label className="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
            <input type="checkbox" checked={requireMfa} onChange={e => setRequireMfa(e.target.checked)}
              className="rounded border-gray-300 text-gray-900" />
            Require MFA for all users
          </label>
          <Button type="submit" loading={saving}>Save changes</Button>
        </form>
      )}
    </div>
  )
}

function InfoRow({ label, value, mono = false }) {
  return (
    <>
      <div className="text-gray-500">{label}</div>
      <div className={`text-gray-900 ${mono ? 'font-mono text-xs' : ''}`}>{value}</div>
    </>
  )
}
