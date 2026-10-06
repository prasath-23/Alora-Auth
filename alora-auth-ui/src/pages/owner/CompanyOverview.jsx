import { useState } from 'react'
import { useCompany } from './CompanyLayout'
import { formatDate } from '../../utils/format'
import { Badge, Card } from '../../components/ui/Layout'
import Input, { Checkbox, Select } from '../../components/ui/Input'
import Button from '../../components/ui/Button'
import ErrorAlert from '../../components/ui/ErrorAlert'
import Alert from '../../components/ui/Alert'
import { LIMITS, domainProblem } from '../../utils/limits'

const STATUSES = ['TRIAL', 'ACTIVE', 'SUSPENDED', 'CANCELLED']

export default function CompanyOverview() {
  const { company } = useCompany()
  return (
    <div className="max-w-3xl space-y-6">
      <Settings />
      <Domain key={`${company.domain}|${company.domain_verified_at}`} />
    </div>
  )
}

function Settings() {
  const { company, api, setCompany } = useCompany()
  const [name, setName] = useState(company.name)
  const [status, setStatus] = useState(company.subscription_status)
  const [seats, setSeats] = useState(company.max_seats ?? '')
  const [active, setActive] = useState(company.is_active)
  const [error, setError] = useState(null)
  const [saved, setSaved] = useState(false)
  const [saving, setSaving] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    setSaved(false)
    const changes = { name: name.trim(), subscription_status: status, is_active: active }
    if (seats === '') changes.clear_max_seats = true
    else changes.max_seats = Number(seats)
    try {
      setCompany(await api.updateCompany(changes))
      setSaved(true)
    } catch (err) {
      setError(err)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card title="Company">
      <form onSubmit={submit} className="space-y-4">
        <ErrorAlert error={error} onClose={() => setError(null)} />
        {saved && <Alert type="success" onClose={() => setSaved(false)}>Saved.</Alert>}
        {company.is_platform && (
          <Alert type="info">This is the platform company, home of the Owners. It cannot be suspended or deactivated.</Alert>
        )}
        <div className="grid gap-4 sm:grid-cols-2">
          <Input id="co-name" maxLength={LIMITS.companyName} label="Name" required value={name} onChange={e => setName(e.target.value)} />
          <Select id="co-status" label="Subscription" value={status} onChange={e => setStatus(e.target.value)} disabled={company.is_platform}>
            {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
          </Select>
          <Input id="co-seats" label="Seats" hint="(empty = unlimited)" type="number" min={1} max={2147483647} value={seats} onChange={e => setSeats(e.target.value)} />
        </div>
        <Checkbox id="co-active" label="Active" description="An inactive company signs nobody in, and every session in it stops working."
          checked={active} onChange={e => setActive(e.target.checked)} disabled={company.is_platform} />
        <p className="text-xs text-gray-400">Created {formatDate(company.created_at)} · updated {formatDate(company.updated_at)}</p>
        <Button type="submit" loading={saving} disabled={!name.trim()}>Save</Button>
      </form>
    </Card>
  )
}

function Domain() {
  const { company, api, setCompany } = useCompany()
  const [domain, setDomain] = useState(company.domain ?? '')
  const [verified, setVerified] = useState(!!company.domain_verified_at)
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)

  async function submit(e) {
    e.preventDefault()
    const d = domain.trim().toLowerCase()
    const problem = d && domainProblem(d)
    if (problem) return setError(new Error(problem))
    setSaving(true)
    setError(null)
    try {
      setCompany(await api.setDomain(d, verified))
    } catch (err) {
      setError(err)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card title="Domain">
      <form onSubmit={submit} className="space-y-4">
        <ErrorAlert error={error} onClose={() => setError(null)} />
        <p className="text-sm text-gray-500">
          A verified domain is unique across companies. The sign-in page uses it to recognise the company&apos;s addresses,
          and it is what lets the company&apos;s SSO connections claim addresses at it.
        </p>
        <div className="flex flex-wrap items-end gap-4">
          <div className="min-w-60 flex-1">
            <Input id="co-domain" maxLength={LIMITS.domain} label="Domain" placeholder="acme.com" value={domain} onChange={e => setDomain(e.target.value)} />
          </div>
          <Checkbox id="co-domain-verified" label="Verified" checked={verified} onChange={e => setVerified(e.target.checked)} disabled={!domain.trim()} />
        </div>
        <p className="text-sm">
          Now: {company.domain ?? 'none'}{' '}
          {company.domain && (company.domain_verified_at ? <Badge tone="green">Verified</Badge> : <Badge tone="amber">Unverified</Badge>)}
        </p>
        <Button type="submit" variant="secondary" loading={saving}>Save domain</Button>
      </form>
    </Card>
  )
}
