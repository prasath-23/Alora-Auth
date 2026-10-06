import { useState } from 'react'
import useAuthStore from '../../store/authStore'
import useResource from '../../hooks/useResource'
import { adminApi } from '../../services/companyApi'
import { loadMe } from '../../services/session'
import { can } from '../../utils/scopes'
import { formatDate } from '../../utils/format'
import { Badge, Card, Loading, PageHeader } from '../../components/ui/Layout'
import Input from '../../components/ui/Input'
import Button from '../../components/ui/Button'
import ErrorAlert from '../../components/ui/ErrorAlert'
import { LIMITS } from '../../utils/limits'

const api = adminApi()

export default function CompanyPage() {
  const me = useAuthStore(s => s.me)
  const { data: company, error, loading, setData } = useResource(() => api.getCompany(), [])

  if (loading && !company) return <Loading />
  if (!company) return <ErrorAlert error={error} />

  return (
    <div className="max-w-2xl space-y-6">
      <PageHeader title="Company" />
      <Card title="Details">
        <dl className="grid grid-cols-3 gap-y-2 text-sm">
          <dt className="text-gray-500">Name</dt><dd className="col-span-2 text-gray-900" data-testid="company-name">{company.name}</dd>
          <dt className="text-gray-500">Domain</dt>
          <dd className="col-span-2 text-gray-900">
            {company.domain ?? '—'}{' '}
            {company.domain && (company.domain_verified_at ? <Badge tone="green">Verified</Badge> : <Badge tone="amber">Unverified</Badge>)}
          </dd>
          <dt className="text-gray-500">Subscription</dt><dd className="col-span-2 text-gray-900">{company.subscription_status}</dd>
          <dt className="text-gray-500">Seats</dt><dd className="col-span-2 text-gray-900">{company.max_seats ?? 'Unlimited'}</dd>
          <dt className="text-gray-500">Created</dt><dd className="col-span-2 text-gray-900">{formatDate(company.created_at)}</dd>
        </dl>
      </Card>
      {can(me, 'company:edit') && <Rename company={company} onRenamed={setData} />}
    </div>
  )
}

function Rename({ company, onRenamed }) {
  const [name, setName] = useState(company.name)
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    try {
      onRenamed(await api.renameCompany(name.trim()))
      await loadMe() // the header shows the company's name
    } catch (err) {
      setError(err)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card title="Rename">
      <form onSubmit={submit} className="space-y-3">
        <ErrorAlert error={error} onClose={() => setError(null)} />
        <Input id="company-name-input" maxLength={LIMITS.companyName} label="Company name" required value={name} onChange={e => setName(e.target.value)} />
        <Button type="submit" loading={saving} disabled={!name.trim() || name.trim() === company.name}>Save</Button>
      </form>
    </Card>
  )
}
