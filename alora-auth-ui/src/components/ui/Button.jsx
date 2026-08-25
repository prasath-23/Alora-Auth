const variants = {
  primary:   'bg-brand-500 hover:bg-brand-600 text-white',
  secondary: 'bg-white hover:bg-gray-50 text-gray-700 border border-gray-300',
  danger:    'bg-red-600 hover:bg-red-700 text-white',
}

export default function Button({
  children, variant = 'primary', loading = false, className = '', ...props
}) {
  return (
    <button
      disabled={loading || props.disabled}
      className={`
        inline-flex items-center justify-center gap-2 rounded-md px-4 py-2
        text-sm font-medium shadow-sm transition-colors
        focus:outline-none focus:ring-2 focus:ring-brand-500 focus:ring-offset-2
        disabled:opacity-50 disabled:cursor-not-allowed
        ${variants[variant]}
        ${className}
      `}
      {...props}
    >
      {loading && (
        <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
        </svg>
      )}
      {children}
    </button>
  )
}
