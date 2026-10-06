import { useParams } from 'react-router-dom'
import { useCompany } from './CompanyLayout'
import APIClientsPanel from '../../components/company/APIClientsPanel'
import APIClientDetailPanel from '../../components/company/APIClientDetailPanel'

// The company's API clients, through the same panels its own people use.

export default function CompanyAPIClients() {
  const { api, base } = useCompany()
  return <APIClientsPanel api={api} canEdit detailPath={c => `${base}/api-clients/${c.id}`} />
}

export function CompanyAPIClient() {
  const { api, base } = useCompany()
  const { aid } = useParams()
  return <APIClientDetailPanel api={api} clientId={aid} backTo={`${base}/api-clients`} canEdit />
}
