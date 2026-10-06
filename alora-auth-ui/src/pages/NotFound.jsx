import { Link } from 'react-router-dom'

export default function NotFound() {
  return (
    <div className="flex min-h-screen items-center justify-center px-4 text-center">
      <div className="space-y-4">
        <h1 className="text-6xl font-bold text-gray-200">404</h1>
        <p className="text-gray-500">Page not found</p>
        <Link to="/" className="text-sm text-brand-600 hover:underline">Back to your apps</Link>
      </div>
    </div>
  )
}
