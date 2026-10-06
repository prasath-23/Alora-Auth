import { useParams } from 'react-router-dom'
import useAuthStore from '../../store/authStore'
import { adminApi } from '../../services/companyApi'
import { can } from '../../utils/scopes'
import { PageHeader } from '../../components/ui/Layout'
import GroupsPanel from '../../components/company/GroupsPanel'
import GroupDetailPanel from '../../components/company/GroupDetailPanel'

const api = adminApi()

export default function GroupsPage() {
  const me = useAuthStore(s => s.me)
  return (
    <div>
      <PageHeader
        title="Groups"
        subtitle="What each group lets its members do in App Central, and which apps it opens. Which apps a group opens is your platform Owner's to decide."
      />
      <GroupsPanel api={api} canDefine={can(me, 'groups:edit')} detailPath={g => `/admin/groups/${g.id}`} />
    </div>
  )
}

export function GroupDetailPage() {
  const me = useAuthStore(s => s.me)
  const { id } = useParams()
  return <GroupDetailPanel api={api} groupId={id} backTo="/admin/groups" canEdit={can(me, 'groups:edit')} />
}
