const styles = {
  error:   'bg-red-50 border-red-400 text-red-800',
  success: 'bg-green-50 border-green-400 text-green-800',
  info:    'bg-blue-50 border-blue-400 text-blue-800',
}

export default function Alert({ type = 'error', onClose, children }) {
  return (
    <div className={`flex items-start justify-between rounded-md border px-4 py-3 text-sm ${styles[type]}`}>
      <span>{children}</span>
      {onClose && (
        <button onClick={onClose} className="ml-3 shrink-0 opacity-60 hover:opacity-100">✕</button>
      )}
    </div>
  )
}
