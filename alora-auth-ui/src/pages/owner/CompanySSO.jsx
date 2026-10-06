import { useState } from 'react'
import useResource from '../../hooks/useResource'
import { useCompany } from './CompanyLayout'
import { Badge, Card, Cell, EmptyState, Loading, Table } from '../../components/ui/Layout'
import Input, { Checkbox, Textarea } from '../../components/ui/Input'
import Button from '../../components/ui/Button'
import Alert from '../../components/ui/Alert'
import ErrorAlert from '../../components/ui/ErrorAlert'
import { LIMITS, LIST_LIMITS, domainProblem, listProblem, urlProblem } from '../../utils/limits'

// The company's OpenID Connect identity providers (Okta, Entra ID, Google
// Workspace…). The client secret is sealed at rest and never shown again. A
// domain on a connection is what lets its users be found from their address
// and linked on their first sign-in.
export default function CompanySSO() {
  const { api } = useCompany()
  const { data: connections, error, loading, reload } = useResource(() => api.listConnections(), [api])
  const [editing, setEditing] = useState(null) // a connection id, or 'new'
  // A new connection is saved before its domains are. When the domains are
  // refused, the connection already exists, and saving again must update it
  // rather than make a second one.
  const [created, setCreated] = useState(null)
  const [tested, setTested] = useState(null)
  const [actionError, setActionError] = useState(null)

  async function run(fn) {
    setActionError(null)
    try {
      await fn()
      setEditing(null)
      setCreated(null)
      await reload()
    } catch (err) {
      setActionError(err)
    }
  }

  function cancel() {
    setEditing(null)
    setActionError(null)
    if (created) {
      setCreated(null)
      reload()
    }
  }

  async function test(c) {
    setActionError(null)
    setTested(null)
    try {
      setTested({ name: c.name, ...(await api.testConnection(c.id)) })
    } catch (err) {
      setActionError(err)
    }
  }

  if (loading && !connections) return <Loading />
  if (!connections) return <ErrorAlert error={error} />

  return (
    <div className="space-y-6">
      <ErrorAlert error={error || actionError} onClose={() => setActionError(null)} />
      {tested && (
        <Alert type="success" onClose={() => setTested(null)}>
          {tested.name} answered: issuer {tested.issuer}, keys at {tested.jwks_uri}.
        </Alert>
      )}
      <Table
        columns={[{ label: 'Connection' }, { label: 'Domains' }, { label: 'Status' }, { label: '', align: 'right' }]}
        footer={connections.length === 0 && <EmptyState>No SSO connections.</EmptyState>}
      >
        {connections.map(c => (
          <tr key={c.id} data-testid="sso-row">
            <Cell>
              <span className="font-medium text-gray-900">{c.name}</span>
              <p className="text-xs text-gray-400">{c.issuer}</p>
            </Cell>
            <Cell className="text-gray-500">{c.domains.length ? c.domains.join(', ') : '—'}</Cell>
            <Cell>
              <div className="flex flex-wrap gap-1">
                {c.is_active ? <Badge tone="green">Active</Badge> : <Badge tone="red">Inactive</Badge>}
                {!c.has_secret && <Badge tone="amber">No secret</Badge>}
                {c.trust_unverified_email && <Badge tone="amber">Trusts unverified email</Badge>}
              </div>
            </Cell>
            <Cell align="right">
              <div className="flex justify-end gap-1">
                <Button variant="ghost" size="sm" onClick={() => test(c)}>Test</Button>
                <Button variant="ghost" size="sm" onClick={() => setEditing(c.id)}>Edit</Button>
              </div>
            </Cell>
          </tr>
        ))}
      </Table>

      {editing === null && <Button onClick={() => setEditing('new')}>New connection</Button>}
      {editing !== null && (
        <ConnectionForm
          key={editing}
          connection={connections.find(c => c.id === editing)}
          onCancel={cancel}
          onSave={(body, domains) => run(async () => {
            // Checked before anything is saved: the API refuses these with a bare
            // "Invalid request".
            const problem = urlProblem('The issuer', body.issuer, { query: false }) ??
              listProblem(domains, LIST_LIMITS.domains) ?? domains.map(domainProblem).find(Boolean)
            if (problem) throw new Error(problem)
            const id = editing === 'new' ? created : editing
            const saved = id ? await api.updateConnection(id, body) : await api.createConnection(body)
            if (editing === 'new') setCreated(saved.id)
            await api.setConnectionDomains(saved.id, domains)
          })}
        />
      )}
    </div>
  )
}

function ConnectionForm({ connection, onSave, onCancel }) {
  const [name, setName] = useState(connection?.name ?? '')
  const [issuer, setIssuer] = useState(connection?.issuer ?? '')
  const [clientId, setClientId] = useState(connection?.client_id ?? '')
  const [secret, setSecret] = useState('')
  const [scopes, setScopes] = useState(connection?.scopes ?? 'openid email profile')
  const [trust, setTrust] = useState(connection?.trust_unverified_email ?? false)
  const [active, setActive] = useState(connection?.is_active ?? true)
  const [domains, setDomains] = useState((connection?.domains ?? []).join('\n'))
  const [saving, setSaving] = useState(false)

  async function submit(e) {
    e.preventDefault()
    const body = {
      name: name.trim(), issuer: issuer.trim(), client_id: clientId.trim(), scopes: scopes.trim(),
      trust_unverified_email: trust, is_active: active,
      // Left empty on an edit, the stored secret is kept.
      ...(secret ? { client_secret: secret } : {}),
    }
    const list = domains.split(/[\s,]+/).map(d => d.trim().toLowerCase()).filter(Boolean)
    setSaving(true)
    try {
      await onSave(body, list)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card title={connection ? `Edit “${connection.name}”` : 'New connection'}>
      <form onSubmit={submit} className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Input id="sso-name" maxLength={LIMITS.ssoName} label="Name" required value={name} onChange={e => setName(e.target.value)} />
          <Input id="sso-issuer" maxLength={LIMITS.ssoIssuer} label="Issuer" placeholder="https://acme.okta.com" required value={issuer} onChange={e => setIssuer(e.target.value)} />
          <Input id="sso-client-id" maxLength={LIMITS.ssoClientID} label="Client ID" required value={clientId} onChange={e => setClientId(e.target.value)} />
          <Input id="sso-client-secret" maxLength={LIMITS.ssoClientSecret} label="Client secret" type="password" autoComplete="off"
            hint={connection?.has_secret ? '(leave empty to keep the stored one)' : undefined}
            required={!connection} value={secret} onChange={e => setSecret(e.target.value)} />
          <Input id="sso-scopes" maxLength={LIMITS.ssoScopes} label="Scopes" value={scopes} onChange={e => setScopes(e.target.value)} />
        </div>
        <Textarea id="sso-domains" label="Domains" hint="(one per line)" rows={3} value={domains} onChange={e => setDomains(e.target.value)} />
        <div className="space-y-2">
          <Checkbox id="sso-active" label="Active" checked={active} onChange={e => setActive(e.target.checked)} />
          <Checkbox id="sso-trust" label="Trust unverified email addresses"
            description="Only for a provider that never lets users choose their own address."
            checked={trust} onChange={e => setTrust(e.target.checked)} />
        </div>
        <div className="flex gap-2">
          <Button type="submit" loading={saving} disabled={!name.trim() || !issuer.trim() || !clientId.trim()}>Save connection</Button>
          <Button variant="secondary" onClick={onCancel}>Cancel</Button>
        </div>
      </form>
    </Card>
  )
}
