import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import useResource from '../../hooks/useResource'
import { getProduct, rotateSecret, setRedirectURIs, setRoles, updateProduct } from '../../services/companyApi'
import { formatDate } from '../../utils/format'
import { Badge, Card, Loading, PageHeader } from '../../components/ui/Layout'
import Input, { Checkbox, Textarea } from '../../components/ui/Input'
import Button from '../../components/ui/Button'
import Alert from '../../components/ui/Alert'
import ErrorAlert from '../../components/ui/ErrorAlert'
import { LIMITS, LIST_LIMITS, listProblem, urlProblem } from '../../utils/limits'

const lines = text => text.split(/\r?\n/).map(s => s.trim()).filter(Boolean)

export default function ProductPage() {
  const { pid } = useParams()
  const { data: product, error, loading, setData } = useResource(() => getProduct(pid), [pid])

  if (loading && !product) return <Loading />
  if (!product) return <ErrorAlert error={error} />

  return (
    <div className="max-w-3xl space-y-6">
      <Link to="/owner/products" className="text-sm text-gray-500 hover:text-gray-900">← All products</Link>
      <PageHeader title={product.name} subtitle={<>Key <code>{product.key}</code> · audience <code>product:{product.key}</code></>} />
      <Credentials product={product} onRotated={rotatedAt => setData(p => ({ ...p, has_secret: true, secret_rotated_at: rotatedAt }))} />
      <Details key={product.updated_at} product={product} onSaved={setData} />
      <RedirectURIs key={`uris-${product.redirect_uris.join()}`} product={product} onSaved={setData} />
      <Roles key={`roles-${product.roles.join()}`} product={product} onSaved={setData} />
    </div>
  )
}

// The secret is shown exactly once, in the response that created it: the API
// stores only its hash. Rotating makes the old one stop working at once.
function Credentials({ product, onRotated }) {
  const [secret, setSecret] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  async function rotate() {
    if (product.has_secret && !window.confirm('Rotate the client secret? The current one stops working immediately.')) return
    setBusy(true)
    setError(null)
    try {
      const res = await rotateSecret(product.id)
      setSecret(res)
      onRotated(res.rotated_at)
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card title="Client credentials">
      <div className="space-y-3 text-sm">
        <ErrorAlert error={error} onClose={() => setError(null)} />
        <p><span className="text-gray-500">Client ID</span> <code className="ml-2 break-all" data-testid="client-id">{product.id}</code></p>
        <p>
          <span className="text-gray-500">Client secret</span>{' '}
          {product.has_secret ? <Badge tone="green">Set {formatDate(product.secret_rotated_at)}</Badge> : <Badge tone="amber">Not issued</Badge>}
        </p>
        {secret && (
          <Alert type="warning" onClose={() => setSecret(null)}>
            <p className="font-medium">Copy this secret now. It will not be shown again.</p>
            <code className="mt-2 block break-all rounded bg-white px-2 py-1 font-mono text-xs" data-testid="client-secret">{secret.client_secret}</code>
          </Alert>
        )}
        <Button variant={product.has_secret ? 'secondary' : 'primary'} loading={busy} onClick={rotate}>
          {product.has_secret ? 'Rotate secret' : 'Issue secret'}
        </Button>
      </div>
    </Card>
  )
}

function Details({ product, onSaved }) {
  const [form, setForm] = useState({
    name: product.name,
    description: product.description ?? '',
    base_url: product.base_url ?? '',
    initiate_login_uri: product.initiate_login_uri ?? '',
    is_active: product.is_active,
    accepts_api_clients: product.accepts_api_clients,
  })
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)
  const field = name => ({ value: form[name], onChange: e => setForm(f => ({ ...f, [name]: e.target.value })) })

  async function submit(e) {
    e.preventDefault()
    const baseURL = form.base_url.trim()
    const initiate = form.initiate_login_uri.trim()
    const problem = [
      baseURL && urlProblem('The base URL', baseURL),
      initiate && urlProblem('The launch URI', initiate),
    ].find(Boolean)
    if (problem) return setError(new Error(problem))
    setSaving(true)
    setError(null)
    try {
      onSaved(await updateProduct(product.id, {
        name: form.name.trim(), description: form.description.trim(), base_url: baseURL,
        initiate_login_uri: initiate, is_active: form.is_active,
        accepts_api_clients: form.accepts_api_clients,
      }))
    } catch (err) {
      setError(err)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card title="Registration">
      <form onSubmit={submit} className="space-y-4">
        <ErrorAlert error={error} onClose={() => setError(null)} />
        <div className="grid gap-4 sm:grid-cols-2">
          <Input id="edit-product-name" maxLength={LIMITS.productName} label="Name" required {...field('name')} />
          <Input id="edit-product-base-url" maxLength={LIMITS.url} label="Base URL" {...field('base_url')} />
          <Input id="edit-product-initiate" maxLength={LIMITS.url} label="Launch (initiate login) URI" {...field('initiate_login_uri')} />
          <Input id="edit-product-description" maxLength={LIMITS.productDescription} label="Description" {...field('description')} />
        </div>
        <Checkbox id="edit-product-active" label="Active" description="An inactive product signs nobody in and renews no login."
          checked={form.is_active} onChange={e => setForm(f => ({ ...f, is_active: e.target.checked }))} />
        <Checkbox id="edit-product-api-clients" label="Accepts API clients"
          description="Companies' API clients may get tokens for this product, for the scopes they hold. Off, no application token is issued for it."
          checked={form.accepts_api_clients} onChange={e => setForm(f => ({ ...f, accepts_api_clients: e.target.checked }))} />
        <Button type="submit" loading={saving} disabled={!form.name.trim()}>Save</Button>
      </form>
    </Card>
  )
}

function RedirectURIs({ product, onSaved }) {
  const [text, setText] = useState(product.redirect_uris.join('\n'))
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)

  async function save() {
    setError(null)
    const uris = lines(text)
    const problem = listProblem(uris, LIST_LIMITS.redirectURIs) ?? uris.map(u => urlProblem('A redirect URI', u)).find(Boolean)
    if (problem) return setError(new Error(problem))
    setSaving(true)
    try {
      await setRedirectURIs(product.id, uris)
      onSaved(await getProduct(product.id))
    } catch (err) {
      setError(err)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card title="Redirect URIs">
      <div className="space-y-3">
        <ErrorAlert error={error} onClose={() => setError(null)} />
        <p className="text-sm text-gray-500">Matched exactly — scheme, host, port, path and query. One per line.</p>
        <Textarea id="redirect-uris" rows={3} value={text} onChange={e => setText(e.target.value)} />
        <Button variant="secondary" loading={saving} onClick={save}>Save redirect URIs</Button>
      </div>
    </Card>
  )
}

function Roles({ product, onSaved }) {
  const [text, setText] = useState(product.roles.join('\n'))
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)

  async function save() {
    setError(null)
    const roles = lines(text)
    const problem = listProblem(roles, LIST_LIMITS.roles)
    if (problem) return setError(new Error(problem))
    setSaving(true)
    try {
      await setRoles(product.id, roles)
      onSaved(await getProduct(product.id))
    } catch (err) {
      setError(err)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card title="Roles">
      <div className="space-y-3">
        <ErrorAlert error={error} onClose={() => setError(null)} />
        <p className="text-sm text-gray-500">
          The role names grants may use. A product token carries the user&apos;s roles for this product only. One per line.
        </p>
        <Textarea id="product-roles" rows={3} value={text} onChange={e => setText(e.target.value)} />
        <Button variant="secondary" loading={saving} onClick={save}>Save roles</Button>
      </div>
    </Card>
  )
}
