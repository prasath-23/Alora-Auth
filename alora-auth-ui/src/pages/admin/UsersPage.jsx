import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import useAuthStore from '../../store/authStore'
import { useFeature, ADMIN_FEATURES } from '../../utils/features'
import { listUsers, setUserActive, requestPasswordReset } from '../../services/adminService'
import Button  from '../../components/ui/Button'
import Alert   from '../../components/ui/Alert'
import Spinner from '../../components/ui/Spinner'

export default function UsersPage() {
  const token     = useAuthStore(s => s.accessToken)
  const canEdit   = useFeature(ADMIN_FEATURES.USERS_EDIT)
  const canReset  = useFeature(ADMIN_FEATURES.PASSWORDS_RESET)

  const [users,      setUsers]      = useState([])
  const [nextCursor, setNextCursor] = useState(null)
  const [search,     setSearch]     = useState('')
  const [loading,    setLoading]    = useState(true)
  const [error,      setError]      = useState(null)
  const [resetMsg,   setResetMsg]   = useState(null)

  const load = useCallback(async (cursor = null, q = search) => {
    setLoading(true)
    setError(null)
    try {
      const data = await listUsers({ cursor, search: q || undefined, take: 25 }, token)
      setUsers(prev => cursor ? [...prev, ...data.users] : data.users)
      setNextCursor(data.nextCursor)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [token, search])

  useEffect(() => { load() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  async function handleToggleActive(user) {
    try {
      await setUserActive(user.id, !user.is_active, token)
      setUsers(prev => prev.map(u => u.id === user.id ? { ...u, is_active: !u.is_active } : u))
    } catch (err) {
      setError(err.message)
    }
  }

  async function handleResetPassword(user) {
    try {
      await requestPasswordReset(user.id, token)
      setResetMsg(`Password reset email sent to ${user.email}.`)
    } catch (err) {
      setError(err.message)
    }
  }

  function handleSearch(e) {
    e.preventDefault()
    setUsers([])
    setNextCursor(null)
    load(null, search)
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Users</h1>

      {error && <Alert type="error" onClose={() => setError(null)}>{error}</Alert>}

      {resetMsg && <Alert type="success" onClose={() => setResetMsg(null)}>{resetMsg}</Alert>}

      <form onSubmit={handleSearch} className="flex gap-2">
        <input
          type="text" placeholder="Search by email…" value={search}
          onChange={e => setSearch(e.target.value)}
          className="flex-1 rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400"
        />
        <Button type="submit" variant="secondary">Search</Button>
      </form>

      {loading && users.length === 0 ? (
        <div className="flex justify-center py-12"><Spinner /></div>
      ) : (
        <div className="rounded-lg border border-gray-200 bg-white overflow-hidden">
          <table className="min-w-full text-sm divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left font-medium text-gray-500">Email</th>
                <th className="px-4 py-3 text-left font-medium text-gray-500">Groups</th>
                <th className="px-4 py-3 text-left font-medium text-gray-500">Status</th>
                <th className="px-4 py-3 text-right font-medium text-gray-500">Actions</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {users.map(user => (
                <tr key={user.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 text-gray-900">{user.email}</td>
                  <td className="px-4 py-3 text-gray-500">
                    {user.groups.length === 0 ? '—' : user.groups.map(g => g.name).join(', ')}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${
                      user.is_active ? 'bg-green-50 text-green-700' : 'bg-red-50 text-red-700'
                    }`}>
                      {user.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right space-x-2">
                    {canEdit && (
                      <button
                        onClick={() => handleToggleActive(user)}
                        className="text-xs text-gray-500 hover:text-gray-900 underline"
                      >
                        {user.is_active ? 'Deactivate' : 'Activate'}
                      </button>
                    )}
                    {canReset && (
                      <button
                        onClick={() => handleResetPassword(user)}
                        className="text-xs text-gray-500 hover:text-gray-900 underline"
                      >
                        Reset password
                      </button>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <Link to={`/admin/users/${user.id}`}
                      className="text-xs text-blue-600 hover:text-blue-800 underline">
                      Details →
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {nextCursor && (
            <div className="px-4 py-3 border-t border-gray-200 text-center">
              <button
                onClick={() => load(nextCursor)}
                disabled={loading}
                className="text-sm text-gray-500 hover:text-gray-900 underline disabled:opacity-50"
              >
                {loading ? 'Loading…' : 'Load more'}
              </button>
            </div>
          )}
          {users.length === 0 && !loading && (
            <p className="px-4 py-8 text-center text-sm text-gray-400">No users found.</p>
          )}
        </div>
      )}
    </div>
  )
}
