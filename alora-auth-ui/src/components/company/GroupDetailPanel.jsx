import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import useAuthStore from '../../store/authStore'
import useResource from '../../hooks/useResource'
import { rulesFor, sameScopes } from '../../utils/scopes'
import { formatDate } from '../../utils/format'
import { Badge, Card, Cell, EmptyState, Loading, PageHeader, Table } from '../ui/Layout'
import Input, { Select } from '../ui/Input'
import Button from '../ui/Button'
import ErrorAlert from '../ui/ErrorAlert'
import ScopeGrid from './ScopeGrid'
import { LIMITS } from '../../utils/limits'

// One group. With groups:edit (`canEdit`) — or as the Owner — its name, its App
// Central access, its members and its managers can be changed, under rule 1:
// nobody gives or takes away access they do not hold themselves, and joining or
// leaving a group, or running it, gives or takes away all of its access. Which
// apps it opens and its login policy are the Owner's (`catalog` given). The
// Admins group holds every scope and cannot be changed, only joined and left.
//
// Through the manager's door (api.kind 'manager') the page is the group's
// manager's: they add and remove its members — never its managers, themselves
// included — and see everything else without changing it.
export default function GroupDetailPanel({ api, groupId, backTo, backLabel = 'All groups', canEdit, catalog }) {
  const me = useAuthStore(s => s.me)
  const { canGive } = rulesFor(me, api.kind)
  const managing = api.kind === 'manager'
  const navigate = useNavigate()
  const { data: group, error, loading, reload } = useResource(() => api.getGroup(groupId), [api, groupId])
  const [actionError, setActionError] = useState(null)

  async function run(fn) {
    setActionError(null)
    try {
      await fn()
      await reload()
      return true
    } catch (err) {
      setActionError(err)
      return false
    }
  }

  async function remove() {
    if (!window.confirm(`Delete the group “${group.name}”? Its members keep their accounts but lose what it grants.`)) return
    setActionError(null)
    try {
      await api.deleteGroup(group.id)
      navigate(backTo)
    } catch (err) {
      setActionError(err)
    }
  }

  if (loading && !group) return <Loading />
  if (!group) return <ErrorAlert error={error} />

  const system = !!group.system_key
  // Rule 1: joining, leaving, running and deleting give or take away the whole
  // group's access; a group that opens apps is the Owner's to delete.
  const holdsAll = canGive(group.scopes)
  const canDelete = canEdit && !system && holdsAll && (api.kind === 'owner' || group.product_grants.length === 0)
  const managerIds = new Set(group.managers.map(m => m.user_id))
  return (
    <div className="space-y-6">
      <Link to={backTo} className="text-sm text-gray-500 hover:text-gray-900">← {backLabel}</Link>
      <PageHeader
        title={<>{group.name} {system && <Badge tone="brand">System</Badge>}</>}
        subtitle={group.description || null}
        actions={canDelete && <Button variant="danger" onClick={remove}>Delete group</Button>}
      />
      {managing && (
        <p className="rounded-md bg-brand-50 px-4 py-3 text-sm text-gray-700" data-testid="manager-note">
          You manage this group: you add and remove its members. What it gives, the apps it opens, its sign-in
          policy and its managers are set by your company&apos;s Admins — and a group&apos;s managers, you included,
          are added and removed by them too.
        </p>
      )}
      <ErrorAlert error={error || actionError} onClose={() => setActionError(null)} />

      <Members
        group={group} canManage={managing || (canEdit && holdsAll)} lacksAccess={!managing && canEdit && !holdsAll}
        untouchable={managing ? managerIds : new Set()}
        onAdd={email => run(() => api.addMember(group.id, email))}
        onRemove={userId => run(() => api.removeMember(group.id, userId))}
      />

      <Managers
        group={group} editable={!managing && canEdit && holdsAll && !system}
        onAdd={email => run(() => api.addManager(group.id, email))}
        onRemove={userId => run(() => api.removeManager(group.id, userId))}
      />

      {canEdit && !system && (
        <Details key={`${group.name}|${group.description}`} group={group} onSave={body => run(() => api.updateGroup(group.id, body))} />
      )}

      <Access
        key={group.scopes.join()} group={group} editable={canEdit && !system} canGive={canGive}
        onSave={scopes => run(() => api.setGroupScopes(group.id, scopes))}
      />

      {catalog ? (
        <Grants
          key={JSON.stringify(group.product_grants)} group={group} products={catalog.subscribed}
          onSave={grants => run(() => api.setGroupGrants(group.id, grants))}
        />
      ) : (
        <Card title="Opens these apps">
          {group.product_grants.length === 0 ? <EmptyState>No apps.</EmptyState>
            : <p className="text-sm text-gray-700">{group.product_grants.map(p => `${p.product_key}: ${p.role_name}`).join(', ')}</p>}
        </Card>
      )}

      {catalog ? (
        <GroupPolicy
          key={group.login_policy_id ?? 'none'} group={group} policies={catalog.policies}
          onSave={policyId => run(() => api.assignGroupPolicy(group.id, policyId))}
        />
      ) : (
        <Card title="Sign-in">
          <p className="text-sm text-gray-700" data-testid="group-policy">
            {group.login_policy_name
              ? <>Members sign in as the policy <strong>{group.login_policy_name}</strong> allows, unless a policy of their own or a higher-priority group&apos;s applies.</>
              : 'Members follow the company’s default sign-in policy, unless another of their groups sets one.'}
          </p>
        </Card>
      )}
    </div>
  )
}

function Members({ group, canManage, lacksAccess, untouchable, onAdd, onRemove }) {
  const [email, setEmail] = useState('')
  const [adding, setAdding] = useState(false)

  async function add(e) {
    e.preventDefault()
    setAdding(true)
    try {
      if (await onAdd(email.trim())) setEmail('')
    } finally {
      setAdding(false)
    }
  }

  return (
    <Card title={`Members (${group.members.length})`}>
      {group.members.length === 0 ? <EmptyState>No members.</EmptyState> : (
        <Table columns={[{ label: 'Email' }, { label: 'Since' }, { label: '', align: 'right' }]}>
          {group.members.map(m => (
            <tr key={m.user_id} data-testid="member-row">
              <Cell>{m.email}</Cell>
              <Cell className="text-gray-500">{formatDate(m.assigned_at)}</Cell>
              <Cell align="right">
                {canManage && !untouchable.has(m.user_id) && (
                  <Button variant="ghost" size="sm" onClick={() => onRemove(m.user_id)}>Remove</Button>
                )}
              </Cell>
            </tr>
          ))}
        </Table>
      )}
      {lacksAccess && (
        <p className="mt-4 border-t border-gray-100 pt-4 text-xs text-gray-500">
          Joining or leaving this group gives or takes away all of its access. You can change its members once you hold all of that access yourself.
        </p>
      )}
      {canManage && (
        <form onSubmit={add} className="mt-4 flex items-end gap-2 border-t border-gray-100 pt-4">
          <div className="flex-1">
            <Input id="member-email" maxLength={LIMITS.email} label="Add a member by email" type="email" required value={email} onChange={e => setEmail(e.target.value)} />
          </div>
          <Button type="submit" loading={adding} disabled={!email.trim()}>Add</Button>
        </form>
      )}
    </Card>
  )
}

// Who runs the group: people who add and remove its members and nothing else.
function Managers({ group, editable, onAdd, onRemove }) {
  const [email, setEmail] = useState('')
  const [adding, setAdding] = useState(false)

  async function add(e) {
    e.preventDefault()
    setAdding(true)
    try {
      if (await onAdd(email.trim())) setEmail('')
    } finally {
      setAdding(false)
    }
  }

  if (group.system_key === 'ADMINS') {
    return (
      <Card title="Managers">
        <p className="text-sm text-gray-700">The Admins group can&apos;t have managers: only Admins decide who is an Admin.</p>
      </Card>
    )
  }
  return (
    <Card title={`Managers (${group.managers.length})`}>
      {group.managers.length === 0 ? (
        <EmptyState>No managers. A manager adds and removes this group&apos;s members, and nothing else.</EmptyState>
      ) : (
        <Table columns={[{ label: 'Email' }, { label: 'Appointed by' }, { label: 'Since' }, { label: '', align: 'right' }]}>
          {group.managers.map(m => (
            <tr key={m.user_id} data-testid="manager-row">
              <Cell>{m.email}</Cell>
              <Cell className="text-gray-500">{m.appointed_by_owner ? `${m.appointed_by_email} (Owner)` : m.appointed_by_email}</Cell>
              <Cell className="text-gray-500">{formatDate(m.appointed_at)}</Cell>
              <Cell align="right">
                {editable && <Button variant="ghost" size="sm" onClick={() => onRemove(m.user_id)}>Remove</Button>}
              </Cell>
            </tr>
          ))}
        </Table>
      )}
      {editable && (
        <form onSubmit={add} className="mt-4 border-t border-gray-100 pt-4">
          <div className="flex items-end gap-2">
            <div className="flex-1">
              <Input id="manager-email" maxLength={LIMITS.email} label="Add a manager by email" type="email" required value={email} onChange={e => setEmail(e.target.value)} />
            </div>
            <Button type="submit" variant="secondary" loading={adding} disabled={!email.trim()}>Add manager</Button>
          </div>
          <p className="mt-2 text-xs text-gray-500">
            They will add and remove this group&apos;s members without needing Groups: Edit — so they can hand out everything
            it gives. Nobody can make themselves a manager.
          </p>
        </form>
      )}
    </Card>
  )
}

function Details({ group, onSave }) {
  const [name, setName] = useState(group.name)
  const [description, setDescription] = useState(group.description)
  const changed = name !== group.name || description !== group.description
  return (
    <Card title="Name and description">
      <div className="grid gap-3 sm:grid-cols-2">
        <Input id="edit-group-name" maxLength={LIMITS.groupName} label="Name" value={name} onChange={e => setName(e.target.value)} />
        <Input id="edit-group-description" maxLength={LIMITS.groupDescription} label="Description" value={description} onChange={e => setDescription(e.target.value)} />
      </div>
      <Button className="mt-3" variant="secondary" disabled={!changed || !name.trim()}
        onClick={() => onSave({ name: name.trim(), description: description.trim() })}>Save</Button>
    </Card>
  )
}

// What the group lets its members do in App Central.
function Access({ group, editable, canGive, onSave }) {
  const [scopes, setScopes] = useState(group.scopes)
  return (
    <Card title="Can do in App Central">
      {group.system_key === 'ADMINS' && (
        <p className="mb-3 text-sm text-gray-700">Everything: the Admins group holds every scope, and that cannot be changed.</p>
      )}
      <ScopeGrid value={scopes} saved={group.scopes} onChange={editable ? setScopes : undefined} canGive={canGive} name="group-scope" />
      {editable && group.managers.length > 0 && (
        <p className="mt-3 text-xs text-gray-500" data-testid="access-managers-note">
          This group has managers: whatever it gives, they can hand out.
        </p>
      )}
      {editable && (
        <Button className="mt-4" variant="secondary" disabled={sameScopes(scopes, group.scopes)} onClick={() => onSave(scopes)}>
          Save access
        </Button>
      )}
    </Card>
  )
}

function Grants({ group, products, onSave }) {
  const [rows, setRows] = useState(group.product_grants.map(g => ({ product_id: g.product_id, role_name: g.role_name })))
  const [productId, setProductId] = useState('')
  const [role, setRole] = useState('')
  const name = id => products.find(p => p.id === id)?.name ?? group.product_grants.find(g => g.product_id === id)?.product_key ?? id
  const roles = products.find(p => p.id === productId)?.roles ?? []
  const changed = JSON.stringify(rows) !== JSON.stringify(group.product_grants.map(g => ({ product_id: g.product_id, role_name: g.role_name })))

  function add() {
    setRows(rs => [...rs.filter(r => r.product_id !== productId), { product_id: productId, role_name: role }])
    setProductId('')
    setRole('')
  }

  return (
    <Card title="Opens these apps">
      {rows.length === 0 ? <EmptyState>No apps.</EmptyState> : (
        <ul className="space-y-2">
          {rows.map(r => (
            <li key={r.product_id} className="flex items-center justify-between rounded-md bg-gray-50 px-3 py-2 text-sm" data-testid="grant-row">
              <span>{name(r.product_id)} — <strong>{r.role_name}</strong></span>
              <Button variant="ghost" size="sm" onClick={() => setRows(rs => rs.filter(x => x.product_id !== r.product_id))}>Remove</Button>
            </li>
          ))}
        </ul>
      )}
      <div className="mt-4 flex flex-wrap items-end gap-2 border-t border-gray-100 pt-4">
        <div className="min-w-40 flex-1">
          <Select id="group-grant-product" label="App" value={productId} onChange={e => { setProductId(e.target.value); setRole('') }}>
            <option value="">Choose a subscribed app…</option>
            {products.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </Select>
        </div>
        <div className="min-w-40 flex-1">
          <Select id="group-grant-role" label="Role" value={role} onChange={e => setRole(e.target.value)} disabled={!productId}>
            <option value="">Choose a role…</option>
            {roles.map(r => <option key={r} value={r}>{r}</option>)}
          </Select>
        </div>
        <Button variant="secondary" onClick={add} disabled={!productId || !role}>Add</Button>
      </div>
      <Button className="mt-4" disabled={!changed} onClick={() => onSave(rows)}>Save apps</Button>
    </Card>
  )
}

function GroupPolicy({ group, policies, onSave }) {
  const [value, setValue] = useState(group.login_policy_id ?? '')
  return (
    <Card title="Sign-in">
      <div className="flex items-end gap-2">
        <div className="flex-1">
          <Select id="group-policy" label="Login policy for members" value={value} onChange={e => setValue(e.target.value)}>
            <option value="">None — members follow the company default</option>
            {policies.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </Select>
        </div>
        <Button variant="secondary" disabled={value === (group.login_policy_id ?? '')} onClick={() => onSave(value)}>Save</Button>
      </div>
      <p className="mt-2 text-xs text-gray-400">A user&apos;s own policy wins; otherwise the highest-priority policy among their groups; otherwise the company default.</p>
    </Card>
  )
}
