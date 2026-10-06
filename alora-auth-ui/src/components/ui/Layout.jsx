import { NavLink } from 'react-router-dom'
import Spinner from './Spinner'

export function PageHeader({ title, subtitle, actions }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-gray-500">{subtitle}</p>}
      </div>
      {actions && <div className="flex gap-2">{actions}</div>}
    </div>
  )
}

export function Card({ title, actions, children, className = '' }) {
  return (
    <section
      aria-label={typeof title === 'string' ? title : undefined}
      className={`rounded-lg border border-gray-200 bg-white ${className}`}
    >
      {(title || actions) && (
        <header className="flex items-center justify-between gap-4 border-b border-gray-100 px-5 py-3">
          {title && <h2 className="text-sm font-semibold text-gray-900">{title}</h2>}
          {actions}
        </header>
      )}
      <div className="px-5 py-4">{children}</div>
    </section>
  )
}

export function Badge({ tone = 'gray', children }) {
  const tones = {
    gray:  'bg-gray-100 text-gray-700',
    green: 'bg-green-50 text-green-700',
    red:   'bg-red-50 text-red-700',
    blue:  'bg-blue-50 text-blue-700',
    amber: 'bg-amber-50 text-amber-800',
    brand: 'bg-brand-50 text-brand-700',
  }
  return <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${tones[tone]}`}>{children}</span>
}

export function EmptyState({ children }) {
  return <p className="py-8 text-center text-sm text-gray-400">{children}</p>
}

export function Loading() {
  return <div className="flex justify-center py-12"><Spinner /></div>
}

export function FullPageSpinner() {
  return <div className="flex min-h-screen items-center justify-center"><Spinner size="lg" /></div>
}

/** Sub-navigation rendered as tabs; each tab is a route. */
export function Tabs({ items }) {
  return (
    <nav className="mb-6 flex flex-wrap gap-1 border-b border-gray-200" aria-label="Sections">
      {items.map(item => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          className={({ isActive }) =>
            `-mb-px border-b-2 px-3 py-2 text-sm transition-colors ${
              isActive ? 'border-brand-500 font-medium text-gray-900' : 'border-transparent text-gray-500 hover:text-gray-900'
            }`}
        >
          {item.label}
        </NavLink>
      ))}
    </nav>
  )
}

export function Table({ columns, children, footer }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
      <table className="min-w-full divide-y divide-gray-200 text-sm">
        <thead className="bg-gray-50">
          <tr>
            {columns.map((c, i) => (
              <th key={i} className={`px-4 py-3 font-medium text-gray-500 ${c.align === 'right' ? 'text-right' : 'text-left'}`}>
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">{children}</tbody>
      </table>
      {footer}
    </div>
  )
}

export function Cell({ children, align, className = '' }) {
  return <td className={`px-4 py-3 ${align === 'right' ? 'text-right' : ''} ${className}`}>{children}</td>
}
