export default function Input({ label, id, error, className = '', ...props }) {
  return (
    <div className="flex flex-col gap-1">
      {label && (
        <label htmlFor={id} className="text-sm font-medium text-gray-700">
          {label}
        </label>
      )}
      <input
        id={id}
        className={`
          block w-full rounded-md border px-3 py-2 text-sm shadow-sm
          focus:outline-none focus:ring-2 focus:ring-brand-500
          ${error
            ? 'border-red-400 focus:ring-red-400'
            : 'border-gray-300 focus:border-brand-500'
          }
          ${className}
        `}
        {...props}
      />
      {error && <p className="text-xs text-red-600">{error}</p>}
    </div>
  )
}
