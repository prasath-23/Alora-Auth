import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import useResource from '../../hooks/useResource'
import { describe } from '../../utils/scopes'
import { Badge, Card, Cell, EmptyState, Loading, Table } from '../ui/Layout'
import Input from '../ui/Input'
import Button from '../ui/Button'
import ErrorAlert from '../ui/ErrorAlert'
import { LIMITS } from '../../utils/limits'

// A company's groups: what each lets its members do in App Central (scopes)
// and which apps it opens (product grants). Creating one needs groups:edit
// (`canDefine`); which apps a group opens is the Owner's to choose.
export default function GroupsPanel({ api, canDefine, detailPath }) {
  const { data: groups, error, loading } = useResource(() => api.listGroups(), [api])

  return (
    <div className="space-y-4">
      <ErrorAlert error={error} />
      {canDefine && <NewGroup api={api} detailPath={detailPath} />}
      {loading && !groups ? <Loading /> : (
        <Table
          columns={[{ label: 'Group' }, { label: 'Members' }, { label: 'Can do in App Central' }, { label: 'Opens' }]}
          footer={groups?.length === 0 && <EmptyState>No groups yet.</EmptyState>}
        >
          {groups?.map(g => (
            <tr key={g.id} data-testid="group-row">
              <Cell>
                <Link to={detailPath(g)} className="font-medium text-gray-900 hover:text-brand-600">{g.name}</Link>
                {g.system_key && <span className="ml-2"><Badge tone="brand">System</Badge></span>}
                {g.description && <p className="text-xs text-gray-400">{g.description}</p>}
              </Cell>
              <Cell>{g.member_count}</Cell>
              <Cell className="text-gray-500">
                {g.system_key === 'ADMINS' ? 'Everything in App Central' : describe(g.scopes) || '—'}
              </Cell>
              <Cell className="text-gray-500">
                {g.product_grants.length ? g.product_grants.map(p => `${p.product_key}: ${p.role_name}`).join(', ') : '—'}
              </Cell>
            </tr>
          ))}
        </Table>
      )}
    </div>
  )
}

function NewGroup({ api, detailPath }) {
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)

  async function submit(e) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    try {
      // What it may do and open is chosen on the group's own page.
      const g = await api.createGroup({ name: name.trim(), description: description.trim(), scopes: [] })
      navigate(detailPath(g))
    } catch (err) {
      setError(err)
      setSaving(false)
    }
  }

  return (
    <Card title="New group">
      <form onSubmit={submit} className="space-y-3">
        <ErrorAlert error={error} onClose={() => setError(null)} />
        <div className="grid gap-3 sm:grid-cols-2">
          <Input id="group-name" maxLength={LIMITS.groupName} label="Name" required value={name} onChange={e => setName(e.target.value)} />
          <Input id="group-description" maxLength={LIMITS.groupDescription} label="Description" hint="(optional)" value={description} onChange={e => setDescription(e.target.value)} />
        </div>
        <Button type="submit" loading={saving} disabled={!name.trim()}>Create group</Button>
      </form>
    </Card>
  )
}
