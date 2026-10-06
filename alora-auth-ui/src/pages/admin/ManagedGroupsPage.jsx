import { useParams } from 'react-router-dom'
import { managerApi } from '../../services/companyApi'
import { PageHeader } from '../../components/ui/Layout'
import GroupsPanel from '../../components/company/GroupsPanel'
import GroupDetailPanel from '../../components/company/GroupDetailPanel'

const api = managerApi()

// The groups the signed-in person runs as their manager: they add and remove
// the members, and nothing else. What each group gives is the company's Admins'
// to decide.
export default function ManagedGroupsPage() {
  return (
    <div>
      <PageHeader
        title="Groups you manage"
        subtitle="You add and remove the people in these groups. What each one gives — its access, the apps it opens, its sign-in policy — is set by your company's Admins."
      />
      <GroupsPanel api={api} canDefine={false} detailPath={g => `/admin/my-groups/${g.id}`} />
    </div>
  )
}

export function ManagedGroupPage() {
  const { id } = useParams()
  return <GroupDetailPanel api={api} groupId={id} backTo="/admin/my-groups" backLabel="Groups you manage" canEdit={false} />
}
