import useAuthStore from '../../store/authStore'
import { adminApi } from '../../services/companyApi'
import { can } from '../../utils/scopes'
import { PageHeader } from '../../components/ui/Layout'
import InvitationsPanel from '../../components/company/InvitationsPanel'

const api = adminApi()

export default function InvitationsPage() {
  const me = useAuthStore(s => s.me)
  return (
    <div>
      <PageHeader title="Invitations" subtitle="Invite people into your company, straight into the groups they belong in." />
      <InvitationsPanel api={api} canEdit={can(me, 'invitations:edit')} canSeeGroups={can(me, 'groups:read')} />
    </div>
  )
}
