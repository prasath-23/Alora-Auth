import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import useResource from '../../hooks/useResource'
import { createProduct, listProducts } from '../../services/companyApi'
import { Badge, Card, Cell, EmptyState, Loading, PageHeader, Table } from '../../components/ui/Layout'
import Input from '../../components/ui/Input'
import Button from '../../components/ui/Button'
import ErrorAlert from '../../components/ui/ErrorAlert'
import { LIMITS, keyProblem, urlProblem } from '../../utils/limits'

// Every product is a confidential OAuth client with its own backend: it is
// registered here with its exact redirect URIs, its launch address and its
// role catalogue, and authenticates to the token endpoint with a secret.
export default function ProductsPage() {
  const { data: products, error, loading } = useResource(listProducts, [])
  return (
    <div className="space-y-6">
      <PageHeader title="Products" subtitle="The apps App Central signs people in to." />
      <NewProduct />
      <ErrorAlert error={error} />
      {loading && !products ? <Loading /> : (
        <Table
          columns={[{ label: 'Product' }, { label: 'Roles' }, { label: 'Redirect URIs' }, { label: 'Status' }]}
          footer={products?.length === 0 && <EmptyState>No products yet.</EmptyState>}
        >
          {products?.map(p => (
            <tr key={p.id} data-testid="product-row">
              <Cell>
                <Link to={`/owner/products/${p.id}`} className="font-medium text-gray-900 hover:text-brand-600">{p.name}</Link>
                <span className="ml-2 text-xs text-gray-400">{p.key}</span>
              </Cell>
              <Cell className="text-gray-500">{p.roles.join(', ') || '—'}</Cell>
              <Cell>{p.redirect_uris.length}</Cell>
              <Cell>
                <div className="flex flex-wrap gap-1">
                  {p.is_active ? <Badge tone="green">Active</Badge> : <Badge tone="red">Inactive</Badge>}
                  {!p.has_secret && <Badge tone="amber">No secret</Badge>}
                </div>
              </Cell>
            </tr>
          ))}
        </Table>
      )}
    </div>
  )
}

function NewProduct() {
  const navigate = useNavigate()
  const [form, setForm] = useState({ key: '', name: '', description: '', base_url: '', initiate_login_uri: '' })
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)
  const field = name => ({ value: form[name], onChange: e => setForm(f => ({ ...f, [name]: e.target.value })) })

  async function submit(e) {
    e.preventDefault()
    const body = Object.fromEntries(Object.entries(form).map(([k, v]) => [k, v.trim()]).filter(([, v]) => v !== ''))
    const problem = [
      keyProblem(body.key ?? ''),
      body.base_url && urlProblem('The base URL', body.base_url),
      body.initiate_login_uri && urlProblem('The launch URI', body.initiate_login_uri),
    ].find(Boolean)
    if (problem) return setError(new Error(problem))
    setSaving(true)
    setError(null)
    try {
      const p = await createProduct(body)
      navigate(`/owner/products/${p.id}`)
    } catch (err) {
      setError(err)
      setSaving(false)
    }
  }

  return (
    <Card title="Register a product">
      <form onSubmit={submit} className="space-y-3">
        <ErrorAlert error={error} onClose={() => setError(null)} />
        <div className="grid gap-3 sm:grid-cols-2">
          <Input id="product-key" maxLength={LIMITS.productKey} label="Key" hint="(permanent; tokens carry aud product:<key>)" required {...field('key')} />
          <Input id="product-name" maxLength={LIMITS.productName} label="Name" required {...field('name')} />
          <Input id="product-base-url" maxLength={LIMITS.url} label="Base URL" placeholder="https://crm.example.com/" {...field('base_url')} />
          <Input id="product-initiate" maxLength={LIMITS.url} label="Launch (initiate login) URI" placeholder="https://crm.example.com/login/initiate" {...field('initiate_login_uri')} />
        </div>
        <Input id="product-description" maxLength={LIMITS.productDescription} label="Description" hint="(optional)" {...field('description')} />
        <Button type="submit" loading={saving} disabled={!form.key.trim() || !form.name.trim()}>Register product</Button>
      </form>
    </Card>
  )
}
