import { useState, useEffect } from 'react'
import useAuthStore from '../../store/authStore'
import { useFeature, ADMIN_FEATURES } from '../../utils/features'
import { listSessions, revokeSession } from '../../services/adminService'
import Button  from '../../components/ui/Button'
import Alert   from '../../components/ui/Alert'
import Spinner from '../../components/ui/Spinner'

export default function SessionsPage() {
  const token      = useAuthStore(s => s.accessToken)
  const currentId  = useAuthStore(s => s.user?.sub)
  const canRevoke  = useFeature(ADMIN_FEATURES.SESSIONS_REVOKE)

  const [sessions, setSessions] = useState([])
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState(null)

  useEffect(() => {
    listSessions(token)
      .then(setSessions)
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [token])

  async function handleRevoke(sessionId) {
    try {
      await revokeSession(sessionId, token)
      setSessions(prev => prev.filter(s => s.id !== sessionId))
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Active Sessions</h1>
        <span className="text-sm text-gray-400">{sessions.length} session{sessions.length !== 1 ? 's' : ''}</span>
      </div>

      {error && <Alert type="error" onClose={() => setError(null)}>{error}</Alert>}

      {loading ? (
        <div className="flex justify-center py-12"><Spinner /></div>
      ) : sessions.length === 0 ? (
        <p className="text-sm text-gray-400">No active sessions.</p>
      ) : (
        <div className="rounded-lg border border-gray-200 bg-white overflow-hidden">
          <table className="min-w-full text-sm divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left font-medium text-gray-500">User</th>
                <th className="px-4 py-3 text-left font-medium text-gray-500">Device</th>
                <th className="px-4 py-3 text-left font-medium text-gray-500">IP</th>
                <th className="px-4 py-3 text-left font-medium text-gray-500">Last seen</th>
                {canRevoke && <th className="px-4 py-3 text-right font-medium text-gray-500" />}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {sessions.map(s => (
                <tr key={s.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 text-gray-500 font-mono text-xs">{s.user_id?.slice(0, 8)}…</td>
                  <td className="px-4 py-3 text-gray-700">{s.device_label ?? '—'}</td>
                  <td className="px-4 py-3 text-gray-500 font-mono text-xs">{s.ip_address ?? '—'}</td>
                  <td className="px-4 py-3 text-gray-500">
                    {s.last_seen_at ? new Date(s.last_seen_at).toLocaleString() : '—'}
                  </td>
                  {canRevoke && (
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => handleRevoke(s.id)}
                        className="text-xs text-red-500 hover:text-red-700 underline"
                      >
                        Revoke
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
