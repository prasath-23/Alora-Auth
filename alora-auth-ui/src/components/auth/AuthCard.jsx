// The frame of every signed-out page: sign-in, invitations, password resets.
export default function AuthCard({ title, subtitle, children }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-50 px-4 py-12">
      <div className="w-full max-w-md">
        <p className="mb-6 text-center text-sm font-semibold tracking-wide text-brand-600">ALORA · APP CENTRAL</p>
        <div className="space-y-6 rounded-xl bg-white px-8 py-10 shadow-md">
          {title && (
            <div className="text-center">
              <h1 className="text-2xl font-bold text-gray-900">{title}</h1>
              {subtitle && <p className="mt-1 text-sm text-gray-500">{subtitle}</p>}
            </div>
          )}
          {children}
        </div>
      </div>
    </div>
  )
}
