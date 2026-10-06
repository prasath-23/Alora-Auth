import { useState } from 'react'
import { Link } from 'react-router-dom'
import useResource from '../../hooks/useResource'
import { listAllAPIClients, listProducts } from '../../services/companyApi'
import { formatDate } from '../../utils/format'
import { Badge, Card, Cell, EmptyState, Loading, PageHeader, Table } from '../../components/ui/Layout'
import ErrorAlert from '../../components/ui/ErrorAlert'
import { APIClientRow } from '../../components/company/APIClientsPanel'

// Every credential that can get a token from App Central, in one place: each
// product's own login (the client ID and secret its backend signs people in
// with), and every company's API clients.
export default function CredentialsPage() {
  const products = useResource(listProducts, [])
  const clients = useResource(listAllAPIClients, [])
  const [filter, setFilter] = useState('')
  const f = filter.trim().toLowerCase()
  const shown = (clients.data ?? []).filter(c => !f || c.name.toLowerCase().includes(f) || c.company_name.toLowerCase().includes(f))

  return (
    <div className="space-y-6">
      <PageHeader title="Client credentials" subtitle="Product logins and every company's API clients." />

      <Card title="Product logins">
        <ErrorAlert error={products.error} />
        {products.loading && !products.data ? <Loading /> : (
          <Table
            columns={[{ label: 'Product' }, { label: 'Client ID' }, { label: 'Secret' }, { label: 'API clients' }]}
            footer={products.data?.length === 0 && <EmptyState>No products yet.</EmptyState>}
          >
            {products.data?.map(p => (
              <tr key={p.id} data-testid="product-login-row">
                <Cell>
                  <Link to={`/owner/products/${p.id}`} className="font-medium text-gray-900 hover:text-brand-600">{p.name}</Link>
                  <span className="ml-2 text-xs text-gray-400">{p.key}</span>
                </Cell>
                <Cell><code className="break-all text-xs">{p.id}</code></Cell>
                <Cell>
                  {p.has_secret ? <Badge tone="green">Set {formatDate(p.secret_rotated_at)}</Badge> : <Badge tone="amber">Not issued</Badge>}
                  <Link to={`/owner/products/${p.id}`} className="ml-2 text-xs text-brand-600 hover:underline">Rotate</Link>
                </Cell>
                <Cell>{p.accepts_api_clients ? <Badge tone="blue">Accepted</Badge> : <span className="text-gray-400">Not accepted</span>}</Cell>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Card title="API clients">
        <div className="space-y-3">
          <ErrorAlert error={clients.error} />
          <input
            type="search" placeholder="Filter by name or company…" aria-label="Filter API clients" value={filter}
            onChange={e => setFilter(e.target.value)}
            className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
          {clients.loading && !clients.data ? <Loading /> : (
            <Table
              columns={[{ label: 'API client' }, { label: 'Company' }, { label: 'Products' }, { label: 'Scope' }, { label: 'Secrets' }, { label: 'Last used' }]}
              footer={shown.length === 0 && <EmptyState>No API clients{f ? ' match' : ''}.</EmptyState>}
            >
              {shown.map(c => (
                <APIClientRow key={c.id} client={c} company to={`/owner/companies/${c.company_id}/api-clients/${c.id}`} />
              ))}
            </Table>
          )}
        </div>
      </Card>
    </div>
  )
}
