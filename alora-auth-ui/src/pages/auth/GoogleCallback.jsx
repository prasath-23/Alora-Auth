import { useSearchParams } from 'react-router-dom'
import Spinner from '../../components/ui/Spinner'
import Alert   from '../../components/ui/Alert'

// This page is the UI-side catch for any Google OAuth errors.
// On success the API redirects straight to the product's redirect_url?code=...
// so this page is only reached when something goes wrong.
export default function GoogleCallback() {
  const [searchParams] = useSearchParams()
  const error = searchParams.get('error')

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-50 px-4">
        <div className="w-full max-w-md rounded-xl bg-white p-8 shadow-md space-y-4">
          <h1 className="text-xl font-bold text-gray-900 text-center">Alora Auth</h1>
          <Alert type="error">Google sign-in failed: {error}</Alert>
          <a href="/" className="block text-center text-sm text-indigo-600 hover:underline">
            Back to login
          </a>
        </div>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="text-center space-y-3">
        <Spinner size="lg" />
        <p className="text-sm text-gray-500">Completing Google sign-in…</p>
      </div>
    </div>
  )
}
