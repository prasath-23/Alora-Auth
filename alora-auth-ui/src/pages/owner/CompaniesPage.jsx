import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import useResource from '../../hooks/useResource'
import { createCompany, listCompanies } from '../../services/companyApi'
import { Badge, Card, Cell, EmptyState, Loading, PageHeader, Table } from '../../components/ui/Layout'
import Input from '../../components/ui/Input'
import Button from '../../components/ui/Button'
import ErrorAlert from '../../components/ui/ErrorAlert'
import { LIMITS, domainProblem } from '../../utils/limits'

export default function CompaniesPage() {
  const { data: companies, error, loading } = useResource(listCompanies, [])
  return (
    <div className="space-y-6">
      <PageHeader title="Companies" subtitle="Every customer company. A new company starts with its Admins group and a default login policy." />
      <NewCompany />
      <ErrorAlert error={error} />
      {loading && !companies ? <Loading /> : (
        <Table
          columns={[{ label: 'Company' }, { label: 'Domain' }, { label: 'Subscription' }, { label: 'Users' }, { label: 'Status' }]}
          footer={companies?.length === 0 && <EmptyState>No companies.</EmptyState>}
        >
          {companies?.map(c => (
            <tr key={c.id} data-testid="company-row">
              <Cell>
                <Link to={`/owner/companies/${c.id}`} className="font-medium text-gray-900 hover:text-brand-600">{c.name}</Link>
                {c.is_platform && <span className="ml-2"><Badge tone="amber">Platform</Badge></span>}
              </Cell>
              <Cell className="text-gray-500">{c.domain ?? '—'}</Cell>
              <Cell>{c.subscription_status}</Cell>
              <Cell>{c.user_count}</Cell>
              <Cell>{c.is_active ? <Badge tone="green">Active</Badge> : <Badge tone="red">Inactive</Badge>}</Cell>
            </tr>
          ))}
        </Table>
      )}
    </div>
  )
}

function NewCompany() {
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [domain, setDomain] = useState('')
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
      const co = await createCompany({ name: name.trim(), ...(d ? { domain: d } : {}) })
      navigate(`/owner/companies/${co.id}`)
    } catch (err) {
      setError(err)
      setSaving(false)
    }
  }

  return (
    <Card title="New company">
      <form onSubmit={submit} className="space-y-3">
        <ErrorAlert error={error} onClose={() => setError(null)} />
        <div className="grid gap-3 sm:grid-cols-2">
          <Input id="company-name" maxLength={LIMITS.companyName} label="Name" required value={name} onChange={e => setName(e.target.value)} />
          <Input id="company-domain" maxLength={LIMITS.domain} label="Domain" hint="(optional, unverified)" placeholder="acme.com" value={domain} onChange={e => setDomain(e.target.value)} />
        </div>
        <Button type="submit" loading={saving} disabled={!name.trim()}>Create company</Button>
      </form>
    </Card>
  )
}
