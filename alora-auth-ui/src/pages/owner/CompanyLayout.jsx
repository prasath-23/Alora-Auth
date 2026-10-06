import { useMemo } from 'react'
import { Link, Outlet, useOutletContext, useParams } from 'react-router-dom'
import useResource from '../../hooks/useResource'
import { listProducts, ownerCompanyApi } from '../../services/companyApi'
import { Badge, Loading, PageHeader, Tabs } from '../../components/ui/Layout'
import ErrorAlert from '../../components/ui/ErrorAlert'

// One company, as the Owner sees it. Every tab talks to the API through the
// same ownerCompanyApi(cid), which repeats the company in the target header.
export default function CompanyLayout() {
  const { cid } = useParams()
  const api = useMemo(() => ownerCompanyApi(cid), [cid])
  const { data: company, error, loading, reload, setData } = useResource(() => api.getCompany(), [api])

  if (loading && !company) return <Loading />
  if (!company) return <ErrorAlert error={error} />

  const base = `/owner/companies/${cid}`
  return (
    <div>
      <Link to="/owner" className="text-sm text-gray-500 hover:text-gray-900">← All companies</Link>
      <PageHeader
        title={<>{company.name} {company.is_platform && <Badge tone="amber">Platform</Badge>}</>}
        subtitle={`${company.user_count} users · ${company.subscription_status}${company.is_active ? '' : ' · inactive'}`}
      />
      <Tabs
        items={[
          { to: base, label: 'Overview', end: true },
          { to: `${base}/subscriptions`, label: 'Subscriptions' },
          { to: `${base}/users`, label: 'Users' },
          { to: `${base}/groups`, label: 'Groups' },
          { to: `${base}/invitations`, label: 'Invitations' },
          { to: `${base}/policies`, label: 'Login policies' },
          { to: `${base}/sso`, label: 'SSO' },
          { to: `${base}/api-clients`, label: 'API clients' },
        ]}
      />
      <Outlet context={{ company, api, base, reloadCompany: reload, setCompany: setData }} />
    </div>
  )
}

export function useCompany() {
  return useOutletContext()
}

/**
 * What the Owner's pickers offer for a company: its active subscriptions (with
 * each product's role catalogue) and its login policies.
 */
export function useCatalog(api) {
  return useResource(async () => {
    const [subs, products, policies] = await Promise.all([api.listSubscriptions(), listProducts(), api.listPolicies()])
    const roles = Object.fromEntries(products.map(p => [p.id, p.roles]))
    const subscribed = subs
      .filter(s => s.is_active)
      .map(s => ({ id: s.product_id, key: s.product_key, name: s.product_name, roles: roles[s.product_id] ?? [] }))
    return { subscribed, policies }
  }, [api])
}
