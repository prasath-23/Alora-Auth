import { Link, Outlet, useLocation } from 'react-router-dom'
import { Badge } from '../../components/ui/Layout'

// The Owner console: every company, every product, and every credential that
// can get a token. The API admits it only for a platform Owner who signed in
// recently (twelve hours), and refuses any company write whose
// X-Alora-Target-Company header does not repeat the company in the path.
export default function OwnerLayout() {
  const { pathname } = useLocation()
  const inProducts = pathname.startsWith('/owner/products')
  const inCredentials = pathname.startsWith('/owner/credentials')
  const tab = active =>
    `-mb-px border-b-2 px-3 py-2 text-sm ${active ? 'border-brand-500 font-medium text-gray-900' : 'border-transparent text-gray-500 hover:text-gray-900'}`

  return (
    <div>
      <div className="mb-6 flex items-center gap-4 border-b border-gray-200">
        <Badge tone="amber">Owner console</Badge>
        <nav className="flex gap-1" aria-label="Owner">
          <Link to="/owner" className={tab(!inProducts && !inCredentials)}>Companies</Link>
          <Link to="/owner/products" className={tab(inProducts)}>Products</Link>
          <Link to="/owner/credentials" className={tab(inCredentials)}>Client credentials</Link>
        </nav>
      </div>
      <Outlet />
    </div>
  )
}
