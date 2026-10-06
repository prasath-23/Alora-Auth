import { useState } from 'react'
import { Link } from 'react-router-dom'
import useAuthStore from '../../store/authStore'
import useResource from '../../hooks/useResource'
import { rulesFor, sameScopes } from '../../utils/scopes'
import { formatDate } from '../../utils/format'
import { Badge, Card, Cell, EmptyState, Loading, PageHeader, Table } from '../ui/Layout'
import { Select } from '../ui/Input'
import Button from '../ui/Button'
import ErrorAlert from '../ui/ErrorAlert'
import ResetIssued from './ResetIssued'
import ScopeGrid from './ScopeGrid'

const SOURCE_LABELS = { USER: 'set on the user', GROUP: 'from a group', DEFAULT: 'company default' }

// One user of a company: their App Central access (what their groups give, and
// extras given to them alone), their app access and how they sign in. With
// users:edit — or as the Owner — their extras can be changed, and they can be
// deactivated or sent a password reset, under rule 2: nobody acts on someone
// with more access than they have. The Owner additionally manages the user's
// direct product grants and own login policy (pass `catalog`: the company's
// subscribed products with their roles, and its login policies).
export default function UserDetailPanel({ api, userId, backTo, canDeactivate, canReset, canEditAccess, catalog }) {
  const me = useAuthStore(s => s.me)
  const rules = rulesFor(me, api.kind)
  const { data: user, error, loading, reload } = useResource(() => api.getUser(userId), [api, userId])
  const [actionError, setActionError] = useState(null)
  const [reset, setReset] = useState(null)

  async function run(fn) {
    setActionError(null)
    try {
      await fn()
      await reload()
    } catch (err) {
      setActionError(err)
    }
  }

  const [resetting, setResetting] = useState(false)
  async function issueReset() {
    setActionError(null)
    setResetting(true)
    try {
      setReset({ email: user.email, ...(await api.issueReset(user.id)) })
    } catch (err) {
      setActionError(err)
    } finally {
      setResetting(false)
    }
  }

  if (loading && !user) return <Loading />
  if (!user) return <ErrorAlert error={error} />

  const self = user.id === me.id
  const manageable = rules.canManage([...new Set(user.scopes.map(s => s.scope))], user.is_owner)
  return (
    <div className="space-y-6">
      <Link to={backTo} className="text-sm text-gray-500 hover:text-gray-900">← All users</Link>
      <PageHeader
        title={user.email}
        subtitle={`Account created ${formatDate(user.created_at)}`}
        actions={
          <>
            {canReset && manageable && user.is_active && <Button variant="secondary" loading={resetting} onClick={issueReset}>Reset password</Button>}
            {canDeactivate && manageable && !self && (
              <Button variant={user.is_active ? 'danger' : 'primary'} onClick={() => run(() => api.setUserActive(user.id, !user.is_active))}>
                {user.is_active ? 'Deactivate' : 'Activate'}
              </Button>
            )}
          </>
        }
      />
      <div className="flex flex-wrap gap-1">
        {user.is_active ? <Badge tone="green">Active</Badge> : <Badge tone="red">Inactive</Badge>}
        {user.is_owner && <Badge tone="amber">Owner</Badge>}
        {user.is_admin && <Badge tone="brand">Admin</Badge>}
        <Badge>{user.account_type}</Badge>
      </div>

      <ErrorAlert error={error || actionError} onClose={() => setActionError(null)} />
      {reset && <ResetIssued reset={reset} onClose={() => setReset(null)} />}

      <Card title="Groups">
        {user.groups.length === 0 ? <EmptyState>Not in any group.</EmptyState> : (
          <ul className="flex flex-wrap gap-2">
            {user.groups.map(g => (
              <li key={g.id}><Badge tone={g.system_key ? 'brand' : 'gray'}>{g.name}</Badge></li>
            ))}
          </ul>
        )}
      </Card>

      <AppCentralAccess
        key={user.extra_scopes.join()} user={user}
        editable={canEditAccess && manageable && !self}
        why={canEditAccess && (self ? 'Nobody changes their own access.'
          : !manageable ? 'They have access you don’t hold, so you can’t change theirs.' : null)}
        canGive={rules.canGive}
        onSave={scopes => run(() => api.setUserScopes(user.id, scopes))}
      />

      <Card title="App access">
        {user.access.length === 0 ? <EmptyState>No access to any app.</EmptyState> : (
          <Table columns={[{ label: 'App' }, { label: 'Role' }, { label: 'Granted' }]}>
            {user.access.map(a => (
              <tr key={`${a.product_id}-${a.role_name}-${a.group_id ?? 'direct'}`}>
                <Cell>{a.product_name} <span className="text-xs text-gray-400">{a.product_key}</span></Cell>
                <Cell>{a.role_name}</Cell>
                <Cell className="text-gray-500">{a.source === 'DIRECT' ? 'Directly' : 'Through a group'}</Cell>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Card title="Sign-in">
        {user.login_policy ? (
          <p className="text-sm text-gray-700">
            <strong>{user.login_policy.name}</strong>{' '}
            <span className="text-gray-400">({SOURCE_LABELS[user.login_policy.source] ?? user.login_policy.source})</span>
            {' — '}
            {[user.login_policy.allow_password && 'password', user.login_policy.allow_google && 'Google',
              user.login_policy.sso_connection_id && 'single sign-on'].filter(Boolean).join(', ') || 'no method'}
          </p>
        ) : <EmptyState>No login policy applies.</EmptyState>}
        {catalog && (
          <PolicyPicker
            key={user.own_policy_id ?? 'none'}
            policies={catalog.policies} current={user.own_policy_id}
            onSave={policyId => run(() => api.assignUserPolicy(user.id, policyId))}
          />
        )}
      </Card>

      {catalog && (
        <DirectGrants
          grants={user.direct_grants} products={catalog.subscribed}
          onGrant={(productId, role) => run(() => api.grant(user.id, productId, role))}
          onRevoke={productId => run(() => api.revokeGrant(user.id, productId))}
        />
      )}
    </div>
  )
}

// What the person may do in App Central: their groups' scopes, and the extras
// given to them alone — the part that can be changed here.
function AppCentralAccess({ user, editable, why, canGive, onSave }) {
  const fromGroups = user.scopes.filter(s => s.source === 'GROUP').map(s => s.scope)
  const [extras, setExtras] = useState(user.extra_scopes)
  return (
    <Card title="App Central access">
      {user.is_admin && <p className="mb-3 text-sm text-gray-700">A member of Admins: holds every scope.</p>}
      <ScopeGrid
        value={extras} saved={user.extra_scopes} inherited={fromGroups}
        onChange={editable ? setExtras : undefined} canGive={canGive} name="user-scope"
      />
      {user.manages.length > 0 && (
        <p className="mt-3 text-sm text-gray-700" data-testid="user-manages">
          Manages {user.manages.map(g => g.name).join(', ')}. They add and remove those groups&apos; members — and so
          count as holding what the groups give: only someone holding that too can act on them.
        </p>
      )}
      {why && <p className="mt-3 text-xs text-gray-500">{why}</p>}
      {editable && (
        <Button className="mt-4" variant="secondary" disabled={sameScopes(extras, user.extra_scopes)} onClick={() => onSave(extras)}>
          Save extra access
        </Button>
      )}
    </Card>
  )
}

function PolicyPicker({ policies, current, onSave }) {
  const [value, setValue] = useState(current ?? '')
  return (
    <div className="mt-4 flex items-end gap-2 border-t border-gray-100 pt-4">
      <div className="flex-1">
        <Select id="user-policy" label="The user's own policy" value={value} onChange={e => setValue(e.target.value)}>
          <option value="">None — follow the groups and the company default</option>
          {policies.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
        </Select>
      </div>
      <Button variant="secondary" onClick={() => onSave(value)} disabled={value === (current ?? '')}>Save</Button>
    </div>
  )
}

function DirectGrants({ grants, products, onGrant, onRevoke }) {
  const [productId, setProductId] = useState('')
  const [role, setRole] = useState('')
  const roles = products.find(p => p.id === productId)?.roles ?? []

  return (
    <Card title="Direct grants">
      {grants.length === 0 ? <EmptyState>No direct grants. Access through groups is shown above.</EmptyState> : (
        <Table columns={[{ label: 'App' }, { label: 'Role' }, { label: '', align: 'right' }]}>
          {grants.map(g => (
            <tr key={g.product_id}>
              <Cell>{g.product_name}</Cell>
              <Cell>{g.role_name}</Cell>
              <Cell align="right"><Button variant="ghost" size="sm" onClick={() => onRevoke(g.product_id)}>Revoke</Button></Cell>
            </tr>
          ))}
        </Table>
      )}
      <div className="mt-4 flex flex-wrap items-end gap-2 border-t border-gray-100 pt-4">
        <div className="min-w-40 flex-1">
          <Select id="grant-product" label="App" value={productId} onChange={e => { setProductId(e.target.value); setRole('') }}>
            <option value="">Choose a subscribed app…</option>
            {products.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </Select>
        </div>
        <div className="min-w-40 flex-1">
          <Select id="grant-role" label="Role" value={role} onChange={e => setRole(e.target.value)} disabled={!productId}>
            <option value="">Choose a role…</option>
            {roles.map(r => <option key={r} value={r}>{r}</option>)}
          </Select>
        </div>
        <Button onClick={() => onGrant(productId, role)} disabled={!productId || !role}>Grant</Button>
      </div>
    </Card>
  )
}
