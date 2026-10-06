import useAuthStore from '../../store/authStore'
import useResource from '../../hooks/useResource'
import { listApps } from '../../services/meService'
import { Badge, EmptyState, Loading, PageHeader } from '../../components/ui/Layout'
import ErrorAlert from '../../components/ui/ErrorAlert'

// My Apps. Opening one sends the browser to the product's own backend (its
// initiate_login_uri), which asks App Central for a token of its own; because
// the user already has a session here, that round trip shows no page. The
// launcher never hands a product anything itself.
export default function Launcher() {
  const me = useAuthStore(s => s.me)
  const { data: apps, error, loading } = useResource(listApps, [])

  return (
    <div>
      <PageHeader title="Your apps" subtitle={`Signed in to ${me.company.name} as ${me.email}`} />
      <ErrorAlert error={error} />
      {loading && !apps && <Loading />}
      {apps && apps.length === 0 && (
        <EmptyState>You don&apos;t have access to any app yet. Ask your administrator.</EmptyState>
      )}
      {apps && apps.length > 0 && (
        <ul className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3" aria-label="Apps">
          {apps.map(app => <AppCard key={app.product_id} app={app} />)}
        </ul>
      )}
    </div>
  )
}

function AppCard({ app }) {
  return (
    <li className="flex flex-col rounded-lg border border-gray-200 bg-white p-5" data-testid={`app-${app.key}`}>
      <div className="flex items-start justify-between gap-3">
        <h2 className="text-base font-semibold text-gray-900">{app.name}</h2>
        <span className="text-xs font-medium text-gray-400">{app.key}</span>
      </div>
      {app.description && <p className="mt-1 text-sm text-gray-500">{app.description}</p>}
      <div className="mt-3 flex flex-wrap gap-1">
        {app.roles.map(r => <Badge key={r} tone="brand">{r}</Badge>)}
      </div>
      <div className="mt-auto pt-4">
        {app.launch_url ? (
          <a
            href={app.launch_url}
            className="inline-flex items-center rounded-md bg-brand-500 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-brand-600"
          >
            Open {app.name}
          </a>
        ) : (
          <p className="text-xs text-gray-400">This app has no launch address yet.</p>
        )}
      </div>
    </li>
  )
}
