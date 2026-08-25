import { useState, useEffect } from 'react'
import useAuthStore from '../../store/authStore'
import { useFeature, ADMIN_FEATURES, FEATURE_GROUPS, FEATURE_LABELS } from '../../utils/features'
import {
  listGroups, createGroup, updateGroup, deleteGroup, getGroup,
  addGroupMemberByEmail, removeGroupMember,
} from '../../services/adminService'
import Button  from '../../components/ui/Button'
import Input   from '../../components/ui/Input'
import Alert   from '../../components/ui/Alert'
import Spinner from '../../components/ui/Spinner'

export default function GroupsPage() {
  const token    = useAuthStore(s => s.accessToken)
  const canManage = useFeature(ADMIN_FEATURES.GROUPS_MANAGE)

  const [groups,  setGroups]  = useState([])
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)
  const [panel,   setPanel]   = useState(null)  // null | { mode: 'create' | 'edit', group? }

  useEffect(() => { loadGroups() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  async function loadGroups() {
    setLoading(true)
    try {
      setGroups(await listGroups(token))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  async function handleDelete(id) {
    if (!confirm('Delete this group? Members will lose access.')) return
    try {
      await deleteGroup(id, token)
      setGroups(prev => prev.filter(g => g.id !== id))
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Groups</h1>
        {canManage && (
          <Button onClick={() => setPanel({ mode: 'create' })}>New group</Button>
        )}
      </div>

      {error && <Alert type="error" onClose={() => setError(null)}>{error}</Alert>}

      {loading ? (
        <div className="flex justify-center py-12"><Spinner /></div>
      ) : groups.length === 0 ? (
        <p className="text-sm text-gray-400">No groups yet.</p>
      ) : (
        <div className="space-y-3">
          {groups.map(group => (
            <div key={group.id} className="rounded-lg border border-gray-200 bg-white p-4">
              <div className="flex items-start justify-between">
                <div>
                  <p className="font-medium text-gray-900">{group.name}</p>
                  {group.description && <p className="text-sm text-gray-500 mt-0.5">{group.description}</p>}
                  <p className="text-xs text-gray-400 mt-1">{group.member_count} member{group.member_count !== 1 ? 's' : ''}</p>
                  <div className="flex flex-wrap gap-1 mt-2">
                    {group.features.map(k => (
                      <span key={k} className="inline-block rounded bg-blue-50 px-1.5 py-0.5 text-xs text-blue-700">
                        {k}
                      </span>
                    ))}
                  </div>
                </div>
                {canManage && (
                  <div className="flex gap-2 ml-4 shrink-0">
                    <button onClick={() => setPanel({ mode: 'edit', group })}
                      className="text-xs text-gray-500 hover:text-gray-900 underline">Edit</button>
                    <button onClick={() => handleDelete(group.id)}
                      className="text-xs text-red-500 hover:text-red-700 underline">Delete</button>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {panel && (
        <GroupPanel
          mode={panel.mode}
          initialGroup={panel.group}
          token={token}
          onSave={() => { setPanel(null); loadGroups() }}
          onClose={() => setPanel(null)}
        />
      )}
    </div>
  )
}

// ── Group create/edit panel ────────────────────────────────────────────────────
function GroupPanel({ mode, initialGroup, token, onSave, onClose }) {
  const [name,        setName]        = useState(initialGroup?.name ?? '')
  const [description, setDescription] = useState(initialGroup?.description ?? '')
  const [features,    setFeatures]    = useState(new Set(initialGroup?.features ?? []))
  const [pending,     setPending]     = useState(false)  // unsaved changes indicator
  const [saving,      setSaving]      = useState(false)
  const [error,       setError]       = useState(null)
  const [tab,         setTab]         = useState('features')  // 'features' | 'members'

  // Track unsaved changes (Copilot: diff bar before save)
  useEffect(() => {
    const origFeatures = new Set(initialGroup?.features ?? [])
    const changed = name !== (initialGroup?.name ?? '')
      || description !== (initialGroup?.description ?? '')
      || [...features].some(k => !origFeatures.has(k))
      || [...origFeatures].some(k => !features.has(k))
    setPending(changed)
  }, [name, description, features]) // eslint-disable-line react-hooks/exhaustive-deps

  function toggleFeature(key) {
    setFeatures(prev => {
      const next = new Set(prev)
      next.has(key) ? next.delete(key) : next.add(key)
      return next
    })
  }

  async function handleSave() {
    setSaving(true)
    setError(null)
    try {
      const data = { name, description: description || undefined, features: [...features] }
      if (mode === 'create') {
        await createGroup(data, token)
      } else {
        await updateGroup(initialGroup.id, data, token)
      }
      onSave()
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
          <h2 className="text-lg font-semibold text-gray-900">
            {mode === 'create' ? 'New group' : 'Edit group'}
          </h2>
          {pending && (
            <span className="text-xs bg-amber-100 text-amber-700 px-2 py-0.5 rounded font-medium">
              Unsaved changes
            </span>
          )}
        </div>

        <div className="overflow-y-auto flex-1 px-6 py-4 space-y-4">
          {error && <Alert type="error">{error}</Alert>}
          <Input id="group-name" label="Group name" required value={name}
            onChange={e => setName(e.target.value)} />
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              rows={2}
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400"
            />
          </div>

          <div>
            <div className="flex gap-4 border-b border-gray-200 mb-3">
              {['features', mode === 'edit' && 'members'].filter(Boolean).map(t => (
                <button key={t} onClick={() => setTab(t)}
                  className={`pb-2 text-sm capitalize border-b-2 transition-colors ${
                    tab === t ? 'border-gray-900 text-gray-900 font-medium' : 'border-transparent text-gray-500'
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>

            {tab === 'features' && (
              <FeatureCheckboxes features={features} onToggle={toggleFeature} />
            )}
            {tab === 'members' && mode === 'edit' && (
              <MembersTab groupId={initialGroup.id} token={token} />
            )}
          </div>
        </div>

        <div className="flex justify-end gap-3 px-6 py-4 border-t">
          <Button variant="secondary" onClick={onClose}>Cancel</Button>
          <Button onClick={handleSave} loading={saving} disabled={!name.trim()}>
            {mode === 'create' ? 'Create' : 'Save changes'}
          </Button>
        </div>
      </div>
    </div>
  )
}

// Grouped checkboxes (Copilot: group by domain, not a flat wall of 12)
function FeatureCheckboxes({ features, onToggle }) {
  return (
    <div className="space-y-4">
      {FEATURE_GROUPS.map(group => (
        <div key={group.label}>
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1.5">{group.label}</p>
          <div className="flex flex-wrap gap-x-4 gap-y-1.5">
            {group.keys.map(k => (
              <label key={k} className="flex items-center gap-1.5 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={features.has(k)}
                  onChange={() => onToggle(k)}
                  className="rounded border-gray-300 text-gray-900"
                />
                <span className="text-sm text-gray-700">{FEATURE_LABELS[k]}</span>
              </label>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

// Requires only groups:manage — no users:view needed.
// Sends email directly to the API; server resolves to userId within the tenant.
function MembersTab({ groupId, token }) {
  const [members,  setMembers]  = useState(null)
  const [addEmail, setAddEmail] = useState('')
  const [adding,   setAdding]   = useState(false)
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState(null)

  useEffect(() => {
    getGroup(groupId, token)
      .then(g => setMembers(g.members))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [groupId, token])

  async function handleAdd(e) {
    e.preventDefault()
    if (!addEmail.trim()) return
    setAdding(true)
    setError(null)
    try {
      await addGroupMemberByEmail(groupId, addEmail.trim(), token)
      setMembers(prev => [...(prev ?? []), { user_id: crypto.randomUUID(), email: addEmail.trim(), assigned_at: new Date().toISOString() }])
      // Refresh from server to get the real user_id
      const updated = await getGroup(groupId, token)
      setMembers(updated.members)
      setAddEmail('')
    } catch (err) {
      setError(err.message)
    } finally {
      setAdding(false)
    }
  }

  async function handleRemove(userId) {
    try {
      await removeGroupMember(groupId, userId, token)
      setMembers(prev => prev.filter(m => m.user_id !== userId))
    } catch (err) {
      setError(err.message)
    }
  }

  if (loading) return <div className="flex justify-center py-4"><Spinner /></div>

  return (
    <div className="space-y-4">
      {error && <Alert type="error" onClose={() => setError(null)}>{error}</Alert>}
      <form onSubmit={handleAdd} className="flex gap-2">
        <input type="email" placeholder="Add by email…" value={addEmail}
          onChange={e => setAddEmail(e.target.value)}
          className="flex-1 rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400"
        />
        <Button type="submit" loading={adding} disabled={!addEmail.trim()}>Add</Button>
      </form>
      {!members || members.length === 0 ? (
        <p className="text-sm text-gray-400">No members yet.</p>
      ) : (
        <ul className="divide-y divide-gray-100">
          {members.map(m => (
            <li key={m.user_id} className="flex items-center justify-between py-2">
              <span className="text-sm text-gray-700">{m.email}</span>
              <button onClick={() => handleRemove(m.user_id)}
                className="text-xs text-red-500 hover:text-red-700 underline">Remove</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
