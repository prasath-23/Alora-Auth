import { useState } from 'react'
import useResource from '../../hooks/useResource'
import { listProducts } from '../../services/companyApi'
import { useCompany } from './CompanyLayout'
import { formatDate } from '../../utils/format'
import { Badge, Cell, EmptyState, Loading, Table } from '../../components/ui/Layout'
import Button from '../../components/ui/Button'
import ErrorAlert from '../../components/ui/ErrorAlert'

// Which products the company subscribes to. A product is only ever usable by a
// company that subscribes to it — whatever any group or grant says.
export default function CompanySubscriptions() {
  const { api } = useCompany()
  const { data, error, loading, reload } = useResource(async () => {
    const [products, subs] = await Promise.all([listProducts(), api.listSubscriptions()])
    const byProduct = Object.fromEntries(subs.map(s => [s.product_id, s]))
    return products.map(p => ({ product: p, sub: byProduct[p.id] ?? null }))
  }, [api])
  const [actionError, setActionError] = useState(null)

  async function save(productId, body) {
    setActionError(null)
    try {
      await api.setSubscription(productId, body)
      await reload()
    } catch (err) {
      setActionError(err)
    }
  }

  if (loading && !data) return <Loading />
  return (
    <div className="space-y-4">
      <ErrorAlert error={error || actionError} onClose={() => setActionError(null)} />
      <Table
        columns={[{ label: 'Product' }, { label: 'Subscription' }, { label: 'Seats' }, { label: 'Since' }, { label: '', align: 'right' }]}
        footer={data?.length === 0 && <EmptyState>No products are registered yet.</EmptyState>}
      >
        {data?.map(({ product, sub }) => (
          <Row key={product.id} product={product} sub={sub} onSave={body => save(product.id, body)} />
        ))}
      </Table>
    </div>
  )
}

function Row({ product, sub, onSave }) {
  const [seats, setSeats] = useState(sub?.seat_limit ?? '')
  const seatLimit = seats === '' ? null : Number(seats)
  const active = !!sub?.is_active

  return (
    <tr data-testid={`subscription-${product.key}`}>
      <Cell>
        <span className="font-medium text-gray-900">{product.name}</span> <span className="text-xs text-gray-400">{product.key}</span>
        {!product.is_active && <span className="ml-2"><Badge tone="red">Product inactive</Badge></span>}
      </Cell>
      <Cell>{active ? <Badge tone="green">Subscribed</Badge> : sub ? <Badge tone="gray">Ended</Badge> : <Badge>None</Badge>}</Cell>
      <Cell>
        <input
          type="number" min={1} value={seats} placeholder="Unlimited" aria-label={`Seats for ${product.name}`}
          onChange={e => setSeats(e.target.value)}
          className="w-28 rounded-md border border-gray-300 px-2 py-1 text-sm"
        />
      </Cell>
      <Cell className="text-gray-500">{formatDate(sub?.starts_at)}</Cell>
      <Cell align="right">
        <div className="flex justify-end gap-1">
          {active ? (
            <>
              <Button variant="ghost" size="sm" onClick={() => onSave({ is_active: true, seat_limit: seatLimit })}>Save</Button>
              <Button variant="ghost" size="sm" onClick={() => onSave({ is_active: false, seat_limit: seatLimit })}>End</Button>
            </>
          ) : (
            <Button size="sm" onClick={() => onSave({ is_active: true, seat_limit: seatLimit })}>Subscribe</Button>
          )}
        </div>
      </Cell>
    </tr>
  )
}
