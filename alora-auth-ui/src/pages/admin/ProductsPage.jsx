import { useState, useEffect } from 'react'
import useAuthStore from '../../store/authStore'
import { listProducts } from '../../services/adminService'
import Spinner from '../../components/ui/Spinner'
import Alert   from '../../components/ui/Alert'

export default function ProductsPage() {
  const token = useAuthStore(s => s.accessToken)

  const [products, setProducts] = useState([])
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState(null)

  useEffect(() => {
    listProducts(token)
      .then(setProducts)
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [token])

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Products</h1>
      <p className="text-sm text-gray-500">Products your workspace is subscribed to.</p>

      {error && <Alert type="error">{error}</Alert>}

      {loading ? (
        <div className="flex justify-center py-12"><Spinner /></div>
      ) : products.length === 0 ? (
        <p className="text-sm text-gray-400">No active product subscriptions.</p>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {products.map(p => (
            <div key={p.id} className="rounded-lg border border-gray-200 bg-white p-5 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-gray-900">{p.name}</span>
                <span className={`text-xs rounded-full px-2 py-0.5 font-medium ${
                  p.is_active ? 'bg-green-50 text-green-700' : 'bg-gray-100 text-gray-500'
                }`}>
                  {p.is_active ? 'Active' : 'Inactive'}
                </span>
              </div>
              {p.description && <p className="text-sm text-gray-500">{p.description}</p>}
              <div className="text-xs text-gray-400 space-y-0.5">
                <p>Key: <span className="font-mono">{p.key}</span></p>
                {p.seat_limit && <p>Seat limit: {p.seat_limit}</p>}
                {p.ends_at && <p>Expires: {new Date(p.ends_at).toLocaleDateString()}</p>}
              </div>
              {p.base_url && (
                <a href={p.base_url} target="_blank" rel="noopener noreferrer"
                  className="inline-block text-xs text-blue-600 hover:underline">
                  Open app →
                </a>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
