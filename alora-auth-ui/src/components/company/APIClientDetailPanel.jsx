import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import useResource from '../../hooks/useResource'
import { CLIENT_FEATURES, LEVEL_LABELS, levelOf, sameScopes, withLevel } from '../../utils/scopes'
import { formatDate } from '../../utils/format'
import { Badge, Card, Cell, EmptyState, Loading, PageHeader, Table } from '../ui/Layout'
import Input, { Checkbox, Select } from '../ui/Input'
import Button from '../ui/Button'
import Alert from '../ui/Alert'
import ErrorAlert from '../ui/ErrorAlert'
import { LIMITS } from '../../utils/limits'

const EXPIRY = [
  { days: 0, label: 'Never expires' },
  { days: 30, label: '30 days' },
  { days: 90, label: '90 days' },
  { days: 365, label: '1 year' },
]

// One API client: its client ID, its secrets (never their values, except once),
// the products it may get a token for and where that token may be used. With
// api-clients:edit (`canEdit`) — or as the Owner — all of it can be changed.
export default function APIClientDetailPanel({ api, clientId, backTo, canEdit }) {
  const navigate = useNavigate()
  const { data: client, error, loading, reload } = useResource(() => api.getAPIClient(clientId), [api, clientId])
  const [actionError, setActionError] = useState(null)

  async function run(fn) {
    setActionError(null)
    try {
      const out = await fn()
      await reload()
      return out ?? true
    } catch (err) {
      setActionError(err)
      return null
    }
  }

  async function remove() {
    if (!window.confirm(`Delete the API client “${client.name}”? Its secrets stop working at once.`)) return
    setActionError(null)
    try {
      await api.deleteAPIClient(client.id)
      navigate(backTo)
    } catch (err) {
      setActionError(err)
    }
  }

  if (loading && !client) return <Loading />
  if (!client) return <ErrorAlert error={error} />

  return (
    <div className="max-w-4xl space-y-6">
      <Link to={backTo} className="text-sm text-gray-500 hover:text-gray-900">← All API clients</Link>
      <PageHeader
        title={<>{client.name} {client.is_active ? <Badge tone="green">On</Badge> : <Badge tone="red">Off</Badge>}</>}
        subtitle={client.description || null}
        actions={canEdit && <Button variant="danger" onClick={remove}>Delete API client</Button>}
      />
      <ErrorAlert error={error || actionError} onClose={() => setActionError(null)} />

      <Card title="Client ID">
        <code className="break-all text-sm" data-testid="api-client-id">{client.id}</code>
        <p className="mt-2 text-xs text-gray-500">
          With a secret below, the application asks App Central for a token for one product on its list.
        </p>
      </Card>

      <Secrets client={client} canEdit={canEdit} api={api} run={run} />
      <Products key={`p-${client.products.map(p => p.product_id).join()}`} client={client} canEdit={canEdit}
        onSave={ids => run(() => api.setAPIClientProducts(client.id, ids))} />
      <Scope key={`s-${client.scopes.join()}`} client={client} canEdit={canEdit}
        onSave={scopes => run(() => api.setAPIClientScopes(client.id, scopes))} />
      <TryIt client={client} />
      {canEdit && (
        <Details key={`d-${client.updated_at}`} client={client}
          onSave={body => run(() => api.updateAPIClient(client.id, body))} />
      )}
    </div>
  )
}

// A secret's value is shown once, in the response that made it: App Central
// keeps only its hash. Two may be live, so a secret rotates without downtime.
function Secrets({ client, canEdit, api, run }) {
  const [days, setDays] = useState(0)
  const [made, setMade] = useState(null)
  const [copied, setCopied] = useState(false)
  // A second press while one secret is being made would make another, live
  // and never shown.
  const [making, setMaking] = useState(false)

  async function make() {
    setCopied(false)
    setMaking(true)
    try {
      const s = await run(() => api.createAPIClientSecret(client.id, days || undefined))
      if (s && s !== true) setMade(s)
    } finally {
      setMaking(false)
    }
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(made.client_secret)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }

  const status = s => (s.is_live ? <Badge tone="green">Live</Badge>
    : s.revoked_at ? <Badge tone="red">Revoked</Badge> : <Badge>Expired</Badge>)

  return (
    <Card title="Secrets">
      <div className="space-y-4">
        {made && (
          <Alert type="warning" onClose={() => setMade(null)}>
            <p className="font-medium">Copy this secret now. It will not be shown again.</p>
            <code className="mt-2 block break-all rounded bg-white px-2 py-1 font-mono text-xs" data-testid="api-client-secret">{made.client_secret}</code>
            <Button className="mt-2" size="sm" variant="secondary" onClick={copy}>{copied ? 'Copied' : 'Copy'}</Button>
          </Alert>
        )}
        {client.secrets.length === 0 ? <EmptyState>No secret yet: the application cannot sign in.</EmptyState> : (
          <Table columns={[{ label: 'Secret' }, { label: 'Made' }, { label: 'Expires' }, { label: 'Last used' }, { label: 'Status' }, { label: '', align: 'right' }]}>
            {client.secrets.map(s => (
              <tr key={s.id} data-testid="secret-row">
                <Cell><code className="text-xs">{s.prefix}…</code></Cell>
                <Cell className="text-gray-500">{formatDate(s.created_at)}</Cell>
                <Cell className="text-gray-500">{s.expires_at ? formatDate(s.expires_at) : 'Never'}</Cell>
                <Cell className="text-gray-500"><span data-testid="secret-last-used">{s.last_used_at ? formatDate(s.last_used_at) : 'Never'}</span></Cell>
                <Cell>{status(s)}</Cell>
                <Cell align="right">
                  {canEdit && s.is_live && (
                    <Button variant="ghost" size="sm" onClick={() => {
                      if (window.confirm(`Revoke ${s.prefix}…? It stops working at once.`)) run(() => api.revokeAPIClientSecret(client.id, s.id))
                    }}>Revoke</Button>
                  )}
                </Cell>
              </tr>
            ))}
          </Table>
        )}
        {canEdit && (
          client.live_secrets >= 2 ? (
            <p className="text-xs text-gray-500">Two secrets are live, the most there can be. Revoke one to make another.</p>
          ) : (
            <div className="flex flex-wrap items-end gap-2 border-t border-gray-100 pt-4">
              <div className="min-w-40">
                <Select id="secret-expiry" label="New secret" value={days} onChange={e => setDays(Number(e.target.value))}>
                  {EXPIRY.map(x => <option key={x.days} value={x.days}>{x.label}</option>)}
                </Select>
              </div>
              <Button loading={making} onClick={make}>New secret</Button>
              {client.live_secrets === 1 && (
                <p className="w-full text-xs text-gray-500">To rotate: make a second secret, deploy it, then revoke the first.</p>
              )}
            </div>
          )
        )}
      </div>
    </Card>
  )
}

// What it may get a token for: only products the company subscribes to and the
// Owner lets accept API clients can be added. An entry that is no longer usable
// can stay, and earns no token until it is usable again.
function Products({ client, canEdit, onSave }) {
  const [ids, setIds] = useState(client.products.map(p => p.product_id))
  const current = Object.fromEntries(client.products.map(p => [p.product_id, p]))
  const offered = [
    ...client.products.map(p => ({ id: p.product_id, key: p.product_key, name: p.product_name, usable: p.usable })),
    ...client.product_choices.filter(c => !current[c.product_id])
      .map(c => ({ id: c.product_id, key: c.product_key, name: c.product_name, usable: true })),
  ].sort((a, b) => a.name.localeCompare(b.name))
  const toggle = id => setIds(xs => (xs.includes(id) ? xs.filter(x => x !== id) : [...xs, id]))

  return (
    <Card title="Products it may get a token for">
      {offered.length === 0 ? (
        <EmptyState>No product accepts API clients yet. The Owner switches that on for each product.</EmptyState>
      ) : (
        <div className="grid gap-2 sm:grid-cols-2">
          {offered.map(p => (
            <Checkbox key={p.id} id={`api-product-${p.key}`} label={`${p.name} (${p.key})`}
              description={p.usable ? null : 'No longer accepts API clients, or is not subscribed: earns no token'}
              checked={ids.includes(p.id)} disabled={!canEdit || (!p.usable && !ids.includes(p.id))}
              onChange={() => toggle(p.id)} />
          ))}
        </div>
      )}
      {canEdit && offered.length > 0 && (
        <Button className="mt-4" variant="secondary" disabled={sameScopes(ids, client.products.map(p => p.product_id))}
          onClick={() => onSave(ids)}>Save products</Button>
      )}
    </Card>
  )
}

// Where its token may be used. Edit includes Read.
function Scope({ client, canEdit, onSave }) {
  const [scopes, setScopes] = useState(client.scopes)
  const edits = CLIENT_FEATURES.filter(f => levelOf(scopes, f) === 'edit')
  const mcp = scopes.includes('mcp:tools')

  return (
    <Card title="Scope: where its token may be used">
      <div className="space-y-3" data-testid="client-scope">
        {CLIENT_FEATURES.map(f => {
          const level = levelOf(scopes, f)
          const options = f.edit ? ['none', 'read', 'edit'] : ['none', 'read']
          return (
            <fieldset key={f.key} className="flex flex-wrap items-center gap-4" data-testid={`client-scope-${f.key}`} data-level={level}>
              <legend className="sr-only">{f.label}</legend>
              <div className="w-48">
                <div className="text-sm font-medium text-gray-900">{f.label}</div>
                <div className="text-xs text-gray-400">{f.lets}</div>
              </div>
              {options.map(l => (
                <label key={l} className="flex items-center gap-1.5 text-sm text-gray-700">
                  <input type="radio" name={`client-scope-${f.key}`} aria-label={`${f.label}: ${f.edit ? LEVEL_LABELS[l] : (l === 'none' ? 'Off' : 'On')}`}
                    className="h-4 w-4 border-gray-300 text-brand-500 focus:ring-brand-500"
                    checked={level === l} disabled={!canEdit} onChange={() => setScopes(s => withLevel(s, f, l))} />
                  {f.edit ? (l === 'edit' ? 'Read and edit' : LEVEL_LABELS[l]) : (l === 'none' ? 'Off' : 'On')}
                </label>
              ))}
            </fieldset>
          )
        })}
        {edits.length > 0 && (
          <Alert type="warning">Edit lets this application change data through {edits.map(f => f.label).join(' and ')}.</Alert>
        )}
        {mcp && <Alert type="warning">MCP tools let an AI agent act through the product with this credential.</Alert>}
        {canEdit && (
          <Button variant="secondary" disabled={sameScopes(scopes, client.scopes)} onClick={() => onSave(scopes)}>Save scope</Button>
        )}
      </div>
    </Card>
  )
}

function Details({ client, onSave }) {
  const [name, setName] = useState(client.name)
  const [description, setDescription] = useState(client.description)
  const [active, setActive] = useState(client.is_active)
  const changed = name !== client.name || description !== client.description || active !== client.is_active
  return (
    <Card title="Details">
      <div className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <Input id="edit-api-client-name" maxLength={LIMITS.apiClientName} label="Name" value={name} onChange={e => setName(e.target.value)} />
          <Input id="edit-api-client-description" maxLength={LIMITS.apiClientDescription} label="Description" value={description} onChange={e => setDescription(e.target.value)} />
        </div>
        <Checkbox id="edit-api-client-active" label="On" description="Switched off, it gets no token, whatever its secrets."
          checked={active} onChange={e => setActive(e.target.checked)} />
        <Button variant="secondary" disabled={!changed || !name.trim()}
          onClick={() => onSave({ name: name.trim(), description: description.trim(), is_active: active })}>Save</Button>
      </div>
    </Card>
  )
}

// How the application gets a token: the token endpoint, with its client ID and
// one of its secrets — shown as a placeholder, since the value is the
// application's alone — for one product on its list.
function TryIt({ client }) {
  const usable = client.products.filter(p => p.usable)
  // The product picked, while it is still on the list; otherwise the first.
  const [picked, setKey] = useState(null)
  const key = usable.some(p => p.product_key === picked) ? picked : (usable[0]?.product_key ?? '')
  const ready = usable.length > 0 && client.scopes.length > 0 && client.live_secrets > 0 && client.is_active
  const origin = window.location.origin
  const curl = [
    `curl -s ${origin}/oauth/token \\`,
    `  -u '${client.id}:'"$CLIENT_SECRET" \\`,
    '  -d grant_type=client_credentials \\',
    `  -d resource=product:${key || '<KEY>'}`,
  ].join('\n')
  // The same over gRPC: TokenService on App Central's gRPC port (add
  // -plaintext where it runs without TLS, as in development).
  const grpcurl = [
    `grpcurl -H "authorization: Basic $(printf '%s:%s' '${client.id}' "$CLIENT_SECRET" | base64 | tr -d '\\n')" \\`,
    `  -d '{"resource": "product:${key || '<KEY>'}"}' \\`,
    `  ${window.location.hostname}:<GRPC_PORT> alora.auth.v1.TokenService/GetToken`,
  ].join('\n')

  return (
    <Card title="Try it">
      <div className="space-y-3 text-sm text-gray-700">
        {!ready && (
          <p className="text-gray-500">
            Once it is on, holds a scope, has a live secret and a usable product on its list, the application can get a token.
          </p>
        )}
        {usable.length > 1 && (
          <div className="max-w-xs">
            <Select id="try-it-product" label="Product" value={key} onChange={e => setKey(e.target.value)}>
              {usable.map(p => <option key={p.product_id} value={p.product_key}>{p.product_name}</option>)}
            </Select>
          </div>
        )}
        <p>The application asks App Central for a token, with its client ID and a secret:</p>
        <pre className="overflow-x-auto rounded-md bg-gray-50 px-3 py-2 text-xs" data-testid="try-it-curl">{curl}</pre>
        <p>Or over gRPC, with the same credentials in the call&apos;s metadata:</p>
        <pre className="overflow-x-auto rounded-md bg-gray-50 px-3 py-2 text-xs" data-testid="try-it-grpc">{grpcurl}</pre>
        <p>
          The answer is a token for that product alone, carrying the scope (add <code>-d scope=&quot;…&quot;</code> to ask for less).
          It lasts fifteen minutes: the application asks again for another, and sends it to the product
          as <code>Authorization: Bearer …</code>.
        </p>
      </div>
    </Card>
  )
}
