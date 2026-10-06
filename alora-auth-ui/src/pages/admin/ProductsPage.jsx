import useResource from '../../hooks/useResource'
import { adminApi } from '../../services/companyApi'
import { formatDate } from '../../utils/format'
import { Badge, Cell, EmptyState, Loading, PageHeader, Table } from '../../components/ui/Layout'
import ErrorAlert from '../../components/ui/ErrorAlert'

const api = adminApi()

export default function ProductsPage() {
  const { data: products, error, loading } = useResource(() => api.listProducts(), [])
  return (
    <div>
      <PageHeader title="Products" subtitle="The apps your company subscribes to." />
      <ErrorAlert error={error} />
      {loading && !products ? <Loading /> : (
        <Table
          columns={[{ label: 'Product' }, { label: 'Status' }, { label: 'Seats' }, { label: 'Ends' }]}
          footer={products?.length === 0 && <EmptyState>No subscriptions.</EmptyState>}
        >
          {products?.map(p => (
            <tr key={p.id}>
              <Cell>
                <span className="font-medium text-gray-900">{p.name}</span> <span className="text-xs text-gray-400">{p.key}</span>
                {p.description && <p className="text-xs text-gray-400">{p.description}</p>}
              </Cell>
              <Cell>{p.is_active ? <Badge tone="green">Active</Badge> : <Badge tone="red">Inactive</Badge>}</Cell>
              <Cell>{p.seat_limit ?? 'Unlimited'}</Cell>
              <Cell className="text-gray-500">{formatDate(p.ends_at)}</Cell>
            </tr>
          ))}
        </Table>
      )}
    </div>
  )
}
