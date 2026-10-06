const control = `block w-full rounded-md border px-3 py-2 text-sm shadow-sm
  focus:outline-none focus:ring-2 focus:ring-brand-500 disabled:bg-gray-50 disabled:text-gray-500`

function Label({ id, children, hint }) {
  if (!children) return null
  return (
    <label htmlFor={id} className="text-sm font-medium text-gray-700">
      {children}
      {hint && <span className="ml-1 font-normal text-gray-400">{hint}</span>}
    </label>
  )
}

export default function Input({ label, hint, id, error, className = '', ...props }) {
  return (
    <div className="flex flex-col gap-1">
      <Label id={id} hint={hint}>{label}</Label>
      <input
        id={id}
        aria-invalid={error ? true : undefined}
        className={`${control} ${error ? 'border-red-400 focus:ring-red-400' : 'border-gray-300 focus:border-brand-500'} ${className}`}
        {...props}
      />
      {error && <p className="text-xs text-red-600">{error}</p>}
    </div>
  )
}

export function Select({ label, hint, id, children, className = '', ...props }) {
  return (
    <div className="flex flex-col gap-1">
      <Label id={id} hint={hint}>{label}</Label>
      <select id={id} className={`${control} border-gray-300 bg-white ${className}`} {...props}>
        {children}
      </select>
    </div>
  )
}

export function Textarea({ label, hint, id, className = '', ...props }) {
  return (
    <div className="flex flex-col gap-1">
      <Label id={id} hint={hint}>{label}</Label>
      <textarea id={id} className={`${control} border-gray-300 font-mono ${className}`} {...props} />
    </div>
  )
}

export function Checkbox({ label, id, description, ...props }) {
  return (
    <label htmlFor={id} className="flex items-start gap-2 text-sm text-gray-700">
      <input id={id} type="checkbox" className="mt-0.5 h-4 w-4 rounded border-gray-300 text-brand-500 focus:ring-brand-500" {...props} />
      <span>
        {label}
        {description && <span className="block text-xs text-gray-400">{description}</span>}
      </span>
    </label>
  )
}
