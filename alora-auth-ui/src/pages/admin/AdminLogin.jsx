// Rendered inline by ProtectedRoute when unauthenticated — not a routed page.
export default function AdminLogin({ loggedOut = false }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50 px-4">
      <div className="w-full max-w-md rounded-xl bg-white shadow-md px-8 py-10 space-y-5 text-center">

        <div className="space-y-1">
          <h1 className="text-2xl font-bold text-gray-900">Alora Auth</h1>
          <p className="text-sm text-gray-500">Admin portal</p>
        </div>

        {loggedOut && (
          <div className="rounded-md border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-800">
            You've been signed out successfully.
          </div>
        )}

        <div className="rounded-lg border border-blue-100 bg-blue-50 px-5 py-4 space-y-2">
          <p className="text-sm font-semibold text-blue-800">Access via your product</p>
          <p className="text-sm text-blue-700">
            Sign in through your product application to access the admin portal.
            Once logged in, navigate to <span className="font-mono text-xs bg-blue-100 px-1 py-0.5 rounded">/admin</span> from your product app.
          </p>
        </div>

      </div>
    </div>
  )
}
