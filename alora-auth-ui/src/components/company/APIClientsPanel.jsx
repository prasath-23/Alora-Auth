import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import useResource from '../../hooks/useResource'
import { formatDate } from '../../utils/format'
import { Badge, Card, Cell, EmptyState, Loading, Table } from '../ui/Layout'
import Input from '../ui/Input'
import Button from '../ui/Button'
import ErrorAlert from '../ui/ErrorAlert'
import { LIMITS } from '../../utils/limits'

// A company's API clients: applications' identities, for a sync job, a backend
// or an agent that calls the company's products with no person present.
// Creating one needs api-clients:edit (`canEdit`); a new client holds nothing
// and is set up on its own page.
export default function APIClientsPanel({ api, canEdit, detailPath }) {
  const { data: clients, error, loading } = useResource(() => api.listAPIClients(), [api])

  return (
    <div className="space-y-4">
      <ErrorAlert error={error} />
      {canEdit && <NewAPIClient api={api} detailPath={detailPath} />}
      {loading && !clients ? <Loading /> : (
        <Table
          columns={[{ label: 'API client' }, { label: 'Products' }, { label: 'Scope' }, { label: 'Secrets' }, { label: 'Last used' }]}
          footer={clients?.length === 0 && <EmptyState>No API clients yet.</EmptyState>}
        >
          {clients?.map(c => <APIClientRow key={c.id} client={c} to={detailPath(c)} />)}
        </Table>
      )}
    </div>
  )
}

/** One row of an API-client table; the Owner's page adds the company. */
export function APIClientRow({ client: c, to, company }) {
  return (
    <tr data-testid="api-client-row">
      <Cell>
        <Link to={to} className="font-medium text-gray-900 hover:text-brand-600">{c.name}</Link>
        {!c.is_active && <span className="ml-2"><Badge tone="red">Off</Badge></span>}
        {c.description && <p className="text-xs text-gray-400">{c.description}</p>}
      </Cell>
      {company && <Cell className="text-gray-500">{c.company_name}</Cell>}
      <Cell className="text-gray-500">
        {c.products.length ? c.products.map(p => (
          <span key={p.product_id} className={`mr-1 ${p.usable ? '' : 'text-gray-300 line-through'}`}>{p.product_key}</span>
        )) : '—'}
      </Cell>
      <Cell className="text-gray-500">{c.scopes.join(' ') || '—'}</Cell>
      <Cell>{c.live_secrets > 0 ? <Badge tone="green">{c.live_secrets} live</Badge> : <Badge tone="amber">None</Badge>}</Cell>
      <Cell className="text-gray-500">{c.last_used_at ? formatDate(c.last_used_at) : 'Never'}</Cell>
    </tr>
  )
}

function NewAPIClient({ api, detailPath }) {
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    try {
      const c = await api.createAPIClient({ name: name.trim(), description: description.trim() })
      navigate(detailPath(c))
    } catch (err) {
      setError(err)
      setSaving(false)
    }
  }

  return (
    <Card title="New API client">
      <form onSubmit={submit} className="space-y-3">
        <ErrorAlert error={error} onClose={() => setError(null)} />
        <div className="grid gap-3 sm:grid-cols-2">
          <Input id="api-client-name" maxLength={LIMITS.apiClientName} label="Name" required value={name} onChange={e => setName(e.target.value)} />
          <Input id="api-client-description" maxLength={LIMITS.apiClientDescription} label="Description" hint="(optional)" value={description} onChange={e => setDescription(e.target.value)} />
        </div>
        <p className="text-xs text-gray-500">It starts with nothing: choose its products and scope, then make it a secret.</p>
        <Button type="submit" loading={saving} disabled={!name.trim()}>Create API client</Button>
      </form>
    </Card>
  )
}
