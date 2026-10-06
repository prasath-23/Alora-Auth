import { useState } from 'react'
import useResource from '../../hooks/useResource'
import { useCompany } from './CompanyLayout'
import { Badge, Card, Cell, EmptyState, Loading, Table } from '../../components/ui/Layout'
import Input, { Checkbox, Select } from '../../components/ui/Input'
import Button from '../../components/ui/Button'
import ErrorAlert from '../../components/ui/ErrorAlert'
import { LIMITS } from '../../utils/limits'

// How the company's people may sign in. A user's own policy wins; otherwise the
// highest-priority policy among their groups; otherwise the company default.
// The API enforces the result at the end of every sign-in and at every
// refresh, so tightening a policy ends the sessions it no longer allows.
export default function CompanyPolicies() {
  const { api } = useCompany()
  const { data, error, loading, reload } = useResource(async () => {
    const [policies, connections] = await Promise.all([api.listPolicies(), api.listConnections()])
    return { policies, connections }
  }, [api])
  const [editing, setEditing] = useState(null) // a policy id, or 'new'
  const [actionError, setActionError] = useState(null)

  async function run(fn) {
    setActionError(null)
    try {
      await fn()
      setEditing(null)
      await reload()
    } catch (err) {
      setActionError(err)
    }
  }

  if (loading && !data) return <Loading />
  if (!data) return <ErrorAlert error={error} />

  const connectionName = id => data.connections.find(c => c.id === id)?.name ?? 'SSO'
  return (
    <div className="space-y-6">
      <ErrorAlert error={error || actionError} onClose={() => setActionError(null)} />
      <Table
        columns={[{ label: 'Policy' }, { label: 'Priority' }, { label: 'Allows' }, { label: '', align: 'right' }]}
        footer={data.policies.length === 0 && <EmptyState>No policies.</EmptyState>}
      >
        {data.policies.map(p => (
          <tr key={p.id} data-testid="policy-row">
            <Cell>
              <span className="font-medium text-gray-900">{p.name}</span>
              {p.is_default && <span className="ml-2"><Badge tone="brand">Default</Badge></span>}
            </Cell>
            <Cell>{p.priority}</Cell>
            <Cell className="text-gray-500">
              {[p.allow_password && 'Password', p.allow_google && 'Google', p.sso_connection_id && connectionName(p.sso_connection_id)]
                .filter(Boolean).join(', ') || 'Nothing'}
            </Cell>
            <Cell align="right">
              <div className="flex justify-end gap-1">
                <Button variant="ghost" size="sm" onClick={() => setEditing(p.id)}>Edit</Button>
                {!p.is_default && <Button variant="ghost" size="sm" onClick={() => run(() => api.setDefaultPolicy(p.id))}>Make default</Button>}
                {!p.is_default && <Button variant="ghost" size="sm" onClick={() => run(() => api.deletePolicy(p.id))}>Delete</Button>}
              </div>
            </Cell>
          </tr>
        ))}
      </Table>

      {editing === null && <Button onClick={() => setEditing('new')}>New policy</Button>}
      {editing !== null && (
        <PolicyForm
          key={editing}
          policy={data.policies.find(p => p.id === editing)}
          connections={data.connections}
          onCancel={() => setEditing(null)}
          onSave={body => run(() => (editing === 'new' ? api.createPolicy(body) : api.updatePolicy(editing, body)))}
        />
      )}
    </div>
  )
}

function PolicyForm({ policy, connections, onSave, onCancel }) {
  const [name, setName] = useState(policy?.name ?? '')
  const [allowPassword, setAllowPassword] = useState(policy?.allow_password ?? true)
  const [allowGoogle, setAllowGoogle] = useState(policy?.allow_google ?? false)
  const [sso, setSSO] = useState(policy?.sso_connection_id ?? '')
  const [priority, setPriority] = useState(policy?.priority ?? 0)
  const [saving, setSaving] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setSaving(true)
    try {
      await onSave({
        name: name.trim(),
        allow_password: allowPassword,
        allow_google: allowGoogle,
        sso_connection_id: sso || null,
        priority: Number(priority),
      })
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card title={policy ? `Edit “${policy.name}”` : 'New policy'}>
      <form onSubmit={submit} className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Input id="policy-name" maxLength={LIMITS.policyName} label="Name" required value={name} onChange={e => setName(e.target.value)} />
          <Input id="policy-priority" label="Priority" hint="(higher wins among a user's groups)" type="number"
            min={-1000} max={1000} value={priority} onChange={e => setPriority(e.target.value)} />
        </div>
        <div className="space-y-2">
          <Checkbox id="policy-password" label="Password" checked={allowPassword} onChange={e => setAllowPassword(e.target.checked)} />
          <Checkbox id="policy-google" label="Google" checked={allowGoogle} onChange={e => setAllowGoogle(e.target.checked)} />
        </div>
        <Select id="policy-sso" label="Single sign-on" value={sso} onChange={e => setSSO(e.target.value)}>
          <option value="">None</option>
          {connections.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
        </Select>
        <div className="flex gap-2">
          <Button type="submit" loading={saving} disabled={!name.trim()}>Save policy</Button>
          <Button variant="secondary" onClick={onCancel}>Cancel</Button>
        </div>
      </form>
    </Card>
  )
}
