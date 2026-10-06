import { useParams } from 'react-router-dom'
import { useCatalog, useCompany } from './CompanyLayout'
import { Loading } from '../../components/ui/Layout'
import ErrorAlert from '../../components/ui/ErrorAlert'
import UsersPanel from '../../components/company/UsersPanel'
import UserDetailPanel from '../../components/company/UserDetailPanel'
import GroupsPanel from '../../components/company/GroupsPanel'
import GroupDetailPanel from '../../components/company/GroupDetailPanel'
import InvitationsPanel from '../../components/company/InvitationsPanel'

// The company's people, through the same panels its Admins use — with the
// Owner's extra powers switched on.

export function CompanyUsers() {
  const { api, base } = useCompany()
  return <UsersPanel api={api} canDeactivate canReset detailPath={u => `${base}/users/${u.id}`} />
}

export function CompanyUser() {
  const { api, base } = useCompany()
  const { uid } = useParams()
  const catalog = useCatalog(api)
  if (!catalog.data) return catalog.error ? <ErrorAlert error={catalog.error} /> : <Loading />
  return <UserDetailPanel api={api} userId={uid} backTo={`${base}/users`} canDeactivate canReset canEditAccess catalog={catalog.data} />
}

export function CompanyGroups() {
  const { api, base } = useCompany()
  return <GroupsPanel api={api} canDefine detailPath={g => `${base}/groups/${g.id}`} />
}

export function CompanyGroup() {
  const { api, base } = useCompany()
  const { gid } = useParams()
  const catalog = useCatalog(api)
  if (!catalog.data) return catalog.error ? <ErrorAlert error={catalog.error} /> : <Loading />
  return <GroupDetailPanel api={api} groupId={gid} backTo={`${base}/groups`} canEdit catalog={catalog.data} />
}

export function CompanyInvitations() {
  const { api } = useCompany()
  return <InvitationsPanel api={api} />
}
