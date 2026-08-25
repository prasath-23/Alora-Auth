import { useState, useEffect, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import useAuthStore from '../../store/authStore'
import { useFeature, ADMIN_FEATURES } from '../../utils/features'
import {
  getUser, setUserActive, requestPasswordReset, listProducts,
  grantPermission, revokePermission,
} from '../../services/adminService'
import Button  from '../../components/ui/Button'
import Alert   from '../../components/ui/Alert'
import Spinner from '../../components/ui/Spinner'

const ROLES = ['Admin', 'Editor', 'Viewer']

export default function UserDetailPage() {
  const { id }   = useParams()
  const token    = useAuthStore(s => s.accessToken)
  const canEdit  = useFeature(ADMIN_FEATURES.USERS_EDIT)
  const canReset = useFeature(ADMIN_FEATURES.PASSWORDS_RESET)

  const [user,        setUser]        = useState(null)
  const [products,    setProducts]    = useState([])
  const [permissions, setPermissions] = useState([])
  const [loading,     setLoading]     = useState(true)
  const [error,       setError]       = useState(null)
  const [resetMsg,    setResetMsg]    = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [userData, prodsData] = await Promise.all([
        getUser(id, token),
        listProducts(token).catch(() => []),
      ])
      setUser(userData)
      setPermissions(userData.permissions ?? [])
      setProducts(Array.isArray(prodsData) ? prodsData : [])
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [id, token])

  useEffect(() => { load() }, [load])

  async function handleToggleActive() {
    try {
      await setUserActive(user.id, !user.is_active, token)
      setUser(prev => ({ ...prev, is_active: !prev.is_active }))
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleResetPassword() {
    try {
      await requestPasswordReset(user.id, token)
      setResetMsg(`Password reset email sent to ${user.email}.`)
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleRoleChange(productId, roleName) {
    setError(null)
    try {
      if (roleName) {
        await grantPermission(user.id, productId, roleName, token)
        setPermissions(prev => {
          const exists = prev.find(p => p.product_id === productId)
          const prod   = products.find(p => p.product_id === productId)
          const entry  = { product_id: productId, role_name: roleName, product: { key: prod?.key, name: prod?.name } }
          return exists
            ? prev.map(p => p.product_id === productId ? entry : p)
            : [...prev, entry]
        })
      } else {
        await revokePermission(user.id, productId, token)
        setPermissions(prev => prev.filter(p => p.product_id !== productId))
      }
    } catch (err) {
      setError(err.message)
    }
  }

  if (loading) return <div className="flex justify-center py-12"><Spinner /></div>
  if (!user)   return <Alert type="error">{error ?? 'User not found.'}</Alert>

  return (
    <div className="space-y-6 max-w-3xl">

      <div className="flex items-center gap-2 text-sm">
        <Link to="/admin/users" className="text-gray-400 hover:text-gray-700">← Users</Link>
        <span className="text-gray-300">/</span>
        <span className="text-gray-700 font-medium truncate">{user.email}</span>
      </div>

      {error && <Alert type="error" onClose={() => setError(null)}>{error}</Alert>}

      {resetMsg && <Alert type="success" onClose={() => setResetMsg(null)}>{resetMsg}</Alert>}

      {/* Account */}
      <section className="rounded-lg border border-gray-200 bg-white">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-900">Account</h2>
          <div className="flex gap-2">
            {canEdit && (
              <Button variant="secondary" onClick={handleToggleActive}>
                {user.is_active ? 'Deactivate' : 'Activate'}
              </Button>
            )}
            {canReset && user.account_type !== 'OAUTH_ONLY' && (
              <Button variant="secondary" onClick={handleResetPassword}>
                Reset password
              </Button>
            )}
          </div>
        </div>
        <dl className="px-5 py-4 grid grid-cols-2 gap-x-8 gap-y-4 text-sm">
          <InfoRow label="Email"        value={user.email} />
          <InfoRow label="Status" value={
            <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${
              user.is_active ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'
            }`}>
              {user.is_active ? 'Active' : 'Inactive'}
            </span>
          } />
          <InfoRow label="Account type" value={user.account_type} />
          <InfoRow label="Member since" value={new Date(user.created_at).toLocaleDateString()} />
        </dl>
      </section>

      {/* Product permissions */}
      <section className="rounded-lg border border-gray-200 bg-white">
        <div className="px-5 py-4 border-b border-gray-100">
          <h2 className="text-sm font-semibold text-gray-900">Product permissions</h2>
        </div>
        {products.length === 0 ? (
          <p className="px-5 py-4 text-sm text-gray-400">
            {permissions.length > 0
              ? 'Product list unavailable — requires the products:view feature to manage permissions.'
              : 'No product subscriptions.'}
          </p>
        ) : (
          <table className="min-w-full text-sm divide-y divide-gray-100">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wide">Product</th>
                <th className="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wide">Role</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {products.map(product => {
                const perm = permissions.find(p => p.product_id === product.product_id)
                return (
                  <tr key={product.id} className="hover:bg-gray-50">
                    <td className="px-5 py-3 font-medium text-gray-900">{product.name}</td>
                    <td className="px-5 py-3">
                      {canEdit ? (
                        <select
                          value={perm?.role_name ?? ''}
                          onChange={e => handleRoleChange(product.product_id, e.target.value)}
                          className="rounded border border-gray-300 px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400"
                        >
                          <option value="">— No access —</option>
                          {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                        </select>
                      ) : (
                        <span className={perm ? 'text-gray-900' : 'text-gray-400'}>
                          {perm?.role_name ?? '—'}
                        </span>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </section>

      {/* Groups */}
      <section className="rounded-lg border border-gray-200 bg-white">
        <div className="px-5 py-4 border-b border-gray-100">
          <h2 className="text-sm font-semibold text-gray-900">Groups</h2>
        </div>
        {user.groups?.length > 0 ? (
          <ul className="divide-y divide-gray-100">
            {user.groups.map(g => (
              <li key={g.id} className="px-5 py-3 text-sm text-gray-700">{g.name}</li>
            ))}
          </ul>
        ) : (
          <p className="px-5 py-4 text-sm text-gray-400">Not in any groups.</p>
        )}
      </section>

    </div>
  )
}

function InfoRow({ label, value }) {
  return (
    <div>
      <dt className="text-xs text-gray-500 uppercase tracking-wide mb-0.5">{label}</dt>
      <dd className="text-gray-900">{value}</dd>
    </div>
  )
}
