const styles = {
  error:   'bg-red-50 border-red-300 text-red-800',
  success: 'bg-green-50 border-green-300 text-green-800',
  info:    'bg-blue-50 border-blue-300 text-blue-800',
  warning: 'bg-amber-50 border-amber-300 text-amber-900',
}

export default function Alert({ type = 'error', onClose, children, className = '' }) {
  return (
    <div
      role={type === 'error' ? 'alert' : 'status'}
      className={`flex items-start justify-between gap-3 rounded-md border px-4 py-3 text-sm ${styles[type]} ${className}`}
    >
      <div className="min-w-0 flex-1">{children}</div>
      {onClose && (
        <button type="button" onClick={onClose} aria-label="Dismiss" className="shrink-0 opacity-60 hover:opacity-100">
          ✕
        </button>
      )}
    </div>
  )
}
