import { useParams } from 'react-router-dom'
import useAuthStore from '../../store/authStore'
import { adminApi } from '../../services/companyApi'
import { can } from '../../utils/scopes'
import { PageHeader } from '../../components/ui/Layout'
import APIClientsPanel from '../../components/company/APIClientsPanel'
import APIClientDetailPanel from '../../components/company/APIClientDetailPanel'

const api = adminApi()

export default function APIClientsPage() {
  const me = useAuthStore(s => s.me)
  return (
    <div>
      <PageHeader
        title="API clients"
        subtitle="Applications that call your products with no person present. Each has a client ID and secret, the products it may get a token for, and where that token may be used."
      />
      <APIClientsPanel api={api} canEdit={can(me, 'api-clients:edit')} detailPath={c => `/admin/api-clients/${c.id}`} />
    </div>
  )
}

export function APIClientDetailPage() {
  const me = useAuthStore(s => s.me)
  const { id } = useParams()
  return <APIClientDetailPanel api={api} clientId={id} backTo="/admin/api-clients" canEdit={can(me, 'api-clients:edit')} />
}
