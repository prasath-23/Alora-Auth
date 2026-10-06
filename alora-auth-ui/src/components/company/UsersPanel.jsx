import { useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import useResource from '../../hooks/useResource'
import { Badge, Cell, EmptyState, Loading, Table } from '../ui/Layout'
import Button from '../ui/Button'
import ErrorAlert from '../ui/ErrorAlert'
import ResetIssued from './ResetIssued'

// A company's users, one keyset page at a time. `api` is the door (adminApi or
// ownerCompanyApi); the same table serves a company's Admins and the Owner.
export default function UsersPanel({ api, canDeactivate, canReset, detailPath }) {
  const [search, setSearch] = useState('')
  const [applied, setApplied] = useState('')
  const [more, setMore] = useState({ users: [], cursor: undefined, loading: false })
  const [actionError, setActionError] = useState(null)
  const [reset, setReset] = useState(null)

  const first = useResource(() => api.listUsers({ search: applied || undefined }), [api, applied])
  const users = [...(first.data?.users ?? []), ...more.users]
  const cursor = more.cursor === undefined ? first.data?.nextCursor : more.cursor
  // Each search starts a new list. A page asked for under an earlier one that
  // answers late belongs to that list, and is dropped.
  const list = useRef(0)

  function applySearch(e) {
    e.preventDefault()
    list.current++
    setMore({ users: [], cursor: undefined, loading: false })
    setApplied(search.trim())
  }

  async function loadMore() {
    const mine = list.current
    setMore(m => ({ ...m, loading: true }))
    try {
      const page = await api.listUsers({ cursor, search: applied || undefined })
      if (mine !== list.current) return
      setMore(m => ({ users: [...m.users, ...page.users], cursor: page.nextCursor, loading: false }))
    } catch (err) {
      if (mine !== list.current) return
      setActionError(err)
      setMore(m => ({ ...m, loading: false }))
    }
  }

  function patch(id, changes) {
    first.setData(d => d && { ...d, users: d.users.map(u => (u.id === id ? { ...u, ...changes } : u)) })
    setMore(m => ({ ...m, users: m.users.map(u => (u.id === id ? { ...u, ...changes } : u)) }))
  }

  async function toggleActive(user) {
    setActionError(null)
    try {
      const res = await api.setUserActive(user.id, !user.is_active)
      patch(user.id, { is_active: res.is_active })
    } catch (err) {
      setActionError(err)
    }
  }

  const [resetting, setResetting] = useState(null) // the user whose reset is being issued
  async function issueReset(user) {
    setActionError(null)
    setReset(null)
    setResetting(user.id)
    try {
      setReset({ email: user.email, ...(await api.issueReset(user.id)) })
    } catch (err) {
      setActionError(err)
    } finally {
      setResetting(null)
    }
  }

  return (
    <div className="space-y-4">
      <ErrorAlert error={first.error || actionError} onClose={() => setActionError(null)} />
      {reset && <ResetIssued reset={reset} onClose={() => setReset(null)} />}

      <form onSubmit={applySearch} className="flex gap-2" role="search">
        <input
          type="search" placeholder="Search by email…" aria-label="Search users" value={search}
          onChange={e => setSearch(e.target.value)}
          className="flex-1 rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-brand-500"
        />
        <Button type="submit" variant="secondary">Search</Button>
      </form>

      {first.loading && !first.data ? <Loading /> : (
        <Table
          columns={[{ label: 'Email' }, { label: 'Groups' }, { label: 'Status' }, { label: '', align: 'right' }]}
          footer={
            <>
              {users.length === 0 && <EmptyState>No users found.</EmptyState>}
              {cursor && (
                <div className="border-t border-gray-100 px-4 py-3 text-center">
                  <Button variant="ghost" size="sm" loading={more.loading} onClick={loadMore}>Load more</Button>
                </div>
              )}
            </>
          }
        >
          {users.map(user => (
            <tr key={user.id} data-testid="user-row">
              <Cell>
                <Link to={detailPath(user)} className="font-medium text-gray-900 hover:text-brand-600">{user.email}</Link>
                <span className="ml-2 inline-flex gap-1 align-middle">
                  {user.is_owner && <Badge tone="amber">Owner</Badge>}
                  {user.is_admin && <Badge tone="brand">Admin</Badge>}
                </span>
              </Cell>
              <Cell className="text-gray-500">{user.groups.length ? user.groups.map(g => g.name).join(', ') : '—'}</Cell>
              <Cell>{user.is_active ? <Badge tone="green">Active</Badge> : <Badge tone="red">Inactive</Badge>}</Cell>
              <Cell align="right">
                <div className="flex justify-end gap-1">
                  {canDeactivate && (
                    <Button variant="ghost" size="sm" onClick={() => toggleActive(user)}>
                      {user.is_active ? 'Deactivate' : 'Activate'}
                    </Button>
                  )}
                  {canReset && user.is_active && (
                    <Button variant="ghost" size="sm" loading={resetting === user.id} onClick={() => issueReset(user)}>Reset password</Button>
                  )}
                </div>
              </Cell>
            </tr>
          ))}
        </Table>
      )}
    </div>
  )
}
