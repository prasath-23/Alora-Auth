import { useState } from 'react'
import useAuthStore from '../../store/authStore'
import useResource from '../../hooks/useResource'
import { adminApi } from '../../services/companyApi'
import { can } from '../../utils/scopes'
import { formatDate } from '../../utils/format'
import { Badge, Cell, EmptyState, Loading, PageHeader, Table } from '../../components/ui/Layout'
import Button from '../../components/ui/Button'
import ErrorAlert from '../../components/ui/ErrorAlert'

const api = adminApi()

const METHOD_LABELS = { EMAIL: 'Password', GOOGLE: 'Google', OIDC: 'Single sign-on' }

export default function SessionsPage() {
  const me = useAuthStore(s => s.me)
  const canRevoke = can(me, 'sessions:edit')
  const { data: sessions, error, loading, reload } = useResource(() => api.listSessions(), [])
  const [actionError, setActionError] = useState(null)
  const [revoking, setRevoking] = useState(null)

  async function revoke(id) {
    setActionError(null)
    setRevoking(id)
    try {
      await api.revokeSession(id)
      await reload()
    } catch (err) {
      setActionError(err)
    } finally {
      setRevoking(null)
    }
  }

  return (
    <div>
      <PageHeader
        title="Sessions"
        subtitle="Live sign-ins in your company. Revoking an App Central session also ends every app login opened from it."
      />
      <ErrorAlert error={error || actionError} onClose={() => setActionError(null)} />
      {loading && !sessions ? <Loading /> : (
        <Table
          columns={[{ label: 'User' }, { label: 'Kind' }, { label: 'Signed in with' }, { label: 'Device' }, { label: 'Last used' }, { label: '', align: 'right' }]}
          footer={sessions?.length === 0 && <EmptyState>No live sessions.</EmptyState>}
        >
          {sessions?.map(s => (
            <tr key={s.id} data-testid="session-row">
              <Cell className="text-gray-900">{s.email}</Cell>
              <Cell>{s.kind === 'CENTRAL' ? <Badge tone="brand">App Central</Badge> : <Badge>{s.product_key}</Badge>}</Cell>
              <Cell>{METHOD_LABELS[s.auth_method] ?? s.auth_method}</Cell>
              <Cell className="text-gray-500">{s.device_label || '—'} <span className="text-xs text-gray-400">{s.ip_address}</span></Cell>
              <Cell className="text-gray-500">{formatDate(s.last_seen_at)}</Cell>
              <Cell align="right">
                {canRevoke && <Button variant="ghost" size="sm" loading={revoking === s.id} onClick={() => revoke(s.id)}>Revoke</Button>}
              </Cell>
            </tr>
          ))}
        </Table>
      )}
    </div>
  )
}
