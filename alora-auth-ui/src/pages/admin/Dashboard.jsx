import useAuthStore from '../../store/authStore'
import { useFeature, ADMIN_FEATURES, FEATURE_GROUPS, FEATURE_LABELS } from '../../utils/features'

export default function Dashboard() {
  const user     = useAuthStore(s => s.user)
  const features = useAuthStore(s => s.features)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="mt-1 text-sm text-gray-500">Welcome back, {user?.email}</p>
      </div>

      <div className="rounded-lg border border-gray-200 bg-white p-6">
        <h2 className="text-sm font-semibold text-gray-700 mb-4">Your permissions</h2>
        {features.size === 0 ? (
          <p className="text-sm text-gray-400">No admin features assigned.</p>
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURE_GROUPS.map(group => {
              const active = group.keys.filter(k => features.has(k))
              if (active.length === 0) return null
              return (
                <div key={group.label} className="rounded-md border border-gray-100 p-3">
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">{group.label}</p>
                  <div className="flex flex-wrap gap-1">
                    {active.map(k => (
                      <span key={k} className="inline-block rounded bg-green-50 px-2 py-0.5 text-xs text-green-700 font-medium">
                        {FEATURE_LABELS[k]}
                      </span>
                    ))}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
