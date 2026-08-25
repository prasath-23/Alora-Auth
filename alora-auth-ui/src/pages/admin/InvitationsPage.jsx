import { useState, useEffect } from 'react'
import useAuthStore from '../../store/authStore'
import {
  listInvitations, revokeInvitation, createInvitation, listProducts,
} from '../../services/adminService'
import Button  from '../../components/ui/Button'
import Input   from '../../components/ui/Input'
import Alert   from '../../components/ui/Alert'
import Spinner from '../../components/ui/Spinner'

const ROLES = ['Admin', 'Editor', 'Viewer']

const STATUS_STYLES = {
  PENDING:  'bg-amber-50 text-amber-700',
  ACCEPTED: 'bg-green-50 text-green-700',
  EXPIRED:  'bg-gray-100 text-gray-500',
  REVOKED:  'bg-red-50 text-red-600',
}

export default function InvitationsPage() {
  const token = useAuthStore(s => s.accessToken)

  const [invitations, setInvitations] = useState([])
  const [products,    setProducts]    = useState([])
  const [loading,     setLoading]     = useState(true)
  const [error,       setError]       = useState(null)
  const [showCreate,  setShowCreate]  = useState(false)

  async function load() {
    setLoading(true)
    setError(null)
    try {
      const [invs, prods] = await Promise.all([listInvitations(token), listProducts(token)])
      setInvitations(invs)
      setProducts(prods.filter(p => p.is_active))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  async function handleRevoke(id) {
    if (!confirm('Revoke this invitation? The link will no longer work.')) return
    try {
      await revokeInvitation(id, token)
      setInvitations(prev => prev.map(i => i.id === id ? { ...i, status: 'REVOKED' } : i))
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Invitations</h1>
        <Button onClick={() => setShowCreate(true)}>Invite user</Button>
      </div>

      {error && <Alert type="error" onClose={() => setError(null)}>{error}</Alert>}

      {loading ? (
        <div className="flex justify-center py-12"><Spinner /></div>
      ) : invitations.length === 0 ? (
        <p className="text-sm text-gray-400">No invitations yet.</p>
      ) : (
        <div className="rounded-lg border border-gray-200 bg-white overflow-hidden">
          <table className="min-w-full text-sm divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left font-medium text-gray-500">Email</th>
                <th className="px-4 py-3 text-left font-medium text-gray-500">Status</th>
                <th className="px-4 py-3 text-left font-medium text-gray-500">Expires</th>
                <th className="px-4 py-3 text-right font-medium text-gray-500" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {invitations.map(inv => (
                <tr key={inv.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3 text-gray-900">{inv.email}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${STATUS_STYLES[inv.status] ?? ''}`}>
                      {inv.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-500 text-xs">
                    {new Date(inv.expires_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {inv.status === 'PENDING' && (
                      <button
                        onClick={() => handleRevoke(inv.id)}
                        className="text-xs text-red-500 hover:text-red-700 underline"
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <CreateInvitationPanel
          products={products}
          token={token}
          onSave={() => { setShowCreate(false); load() }}
          onClose={() => setShowCreate(false)}
        />
      )}
    </div>
  )
}

function CreateInvitationPanel({ products, token, onSave, onClose }) {
  const [email,     setEmail]    = useState('')
  const [selected,  setSelected] = useState({})  // { productId: roleName }
  const [saving,    setSaving]   = useState(false)
  const [error,     setError]    = useState(null)
  const [inviteUrl, setInviteUrl] = useState(null)

  function toggleProduct(pid) {
    setSelected(prev => {
      const next = { ...prev }
      if (next[pid]) {
        delete next[pid]
      } else {
        next[pid] = 'Viewer'
      }
      return next
    })
  }

  function setRole(pid, role) {
    setSelected(prev => ({ ...prev, [pid]: role }))
  }

  const productList = Object.entries(selected).map(([productId, roleName]) => ({ productId, roleName }))
  const canSubmit   = email.trim() && productList.length > 0

  async function handleSubmit(e) {
    e.preventDefault()
    if (!canSubmit) return
    setSaving(true)
    setError(null)
    try {
      const result = await createInvitation({ email: email.trim(), products: productList }, token)
      if (result?.invite_url) setInviteUrl(result.invite_url)
      else onSave()
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-lg max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b">
          <h2 className="text-lg font-semibold text-gray-900">Invite user</h2>
        </div>

        <div className="overflow-y-auto flex-1 px-6 py-4 space-y-5">
          {error && <Alert type="error" onClose={() => setError(null)}>{error}</Alert>}

          <Input
            id="invite-email"
            label="Email address"
            type="email"
            required
            value={email}
            onChange={e => setEmail(e.target.value)}
            placeholder="user@example.com"
          />

          <div>
            <p className="text-sm font-medium text-gray-700 mb-2">
              Products <span className="text-xs font-normal text-gray-400">(select at least one)</span>
            </p>
            {products.length === 0 ? (
              <p className="text-sm text-gray-400">No active products found.</p>
            ) : (
              <div className="space-y-3">
                {products.map(p => {
                  const isChecked = !!selected[p.product_id]
                  return (
                    <div key={p.product_id} className="flex items-center gap-3">
                      <input
                        type="checkbox"
                        id={`prod-${p.product_id}`}
                        checked={isChecked}
                        onChange={() => toggleProduct(p.product_id)}
                        className="rounded border-gray-300 text-brand-500"
                      />
                      <label htmlFor={`prod-${p.product_id}`} className="flex-1 text-sm text-gray-700 cursor-pointer">
                        {p.name}
                        <span className="ml-1 font-mono text-xs text-gray-400">({p.key})</span>
                      </label>
                      {isChecked && (
                        <select
                          value={selected[p.product_id]}
                          onChange={e => setRole(p.product_id, e.target.value)}
                          className="rounded border border-gray-300 text-sm px-2 py-1 focus:outline-none focus:ring-2 focus:ring-brand-500"
                        >
                          {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                        </select>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {productList.length > 0 && (
            <div className="rounded-md bg-blue-50 border border-blue-100 px-3 py-2 text-xs text-blue-700 space-y-0.5">
              <p className="font-medium">Invitation summary</p>
              {productList.map(({ productId, roleName }) => {
                const p = products.find(x => x.product_id === productId)
                return <p key={productId}>{p?.name ?? productId}: <strong>{roleName}</strong></p>
              })}
              <p className="text-blue-500 mt-1">Link expires in 7 days.</p>
            </div>
          )}
        </div>

        {inviteUrl && (
          <div className="px-6 pb-4 space-y-3">
            <Alert type="success">
              Invitation created!{' '}
              {saving === false && 'An email was sent if email is configured.'}
            </Alert>
            <div className="space-y-1">
              <p className="text-xs font-medium text-gray-500">Share this link with the user:</p>
              <div className="flex items-center gap-2">
                <input
                  readOnly
                  value={inviteUrl}
                  className="flex-1 rounded border border-gray-300 px-3 py-1.5 text-xs font-mono text-gray-700 bg-gray-50 truncate"
                  onFocus={e => e.target.select()}
                />
                <button
                  type="button"
                  onClick={() => { navigator.clipboard.writeText(inviteUrl); }}
                  className="shrink-0 rounded border border-gray-300 px-3 py-1.5 text-xs text-gray-600 hover:bg-gray-100"
                >
                  Copy
                </button>
              </div>
            </div>
            <div className="flex justify-end">
              <Button onClick={onSave}>Done</Button>
            </div>
          </div>
        )}

        {!inviteUrl && (
        <div className="flex justify-end gap-3 px-6 py-4 border-t">
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button onClick={handleSubmit} loading={saving} disabled={!canSubmit}>
            Send invitation
          </Button>
        </div>
        )}
      </div>
    </div>
  )
}
