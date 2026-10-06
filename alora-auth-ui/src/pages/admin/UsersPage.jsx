import { useParams } from 'react-router-dom'
import useAuthStore from '../../store/authStore'
import { adminApi } from '../../services/companyApi'
import { can } from '../../utils/scopes'
import { PageHeader } from '../../components/ui/Layout'
import UsersPanel from '../../components/company/UsersPanel'
import UserDetailPanel from '../../components/company/UserDetailPanel'

const api = adminApi()

export default function UsersPage() {
  const me = useAuthStore(s => s.me)
  return (
    <div>
      <PageHeader title="Users" subtitle="Everyone with an account in your company." />
      <UsersPanel
        api={api}
        canDeactivate={can(me, 'users:edit')}
        canReset={can(me, 'users:edit')}
        detailPath={u => `/admin/users/${u.id}`}
      />
    </div>
  )
}

export function UserDetailPage() {
  const me = useAuthStore(s => s.me)
  const { id } = useParams()
  return (
    <UserDetailPanel
      api={api} userId={id} backTo="/admin/users"
      canDeactivate={can(me, 'users:edit')}
      canReset={can(me, 'users:edit')}
      canEditAccess={can(me, 'users:edit')}
    />
  )
}
