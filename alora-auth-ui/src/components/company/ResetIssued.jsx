import Alert from '../ui/Alert'
import { formatDate } from '../../utils/format'

// The outcome of issuing a password reset. With mail configured the link goes
// by email only. Outside production without mail, the API returns the link so
// a developer can follow it — never in production.
export default function ResetIssued({ reset, onClose }) {
  return (
    <Alert type="success" onClose={onClose}>
      {reset.reset_url ? (
        <>
          Reset link for {reset.email} (valid until {formatDate(reset.expires_at)}):{' '}
          <a href={reset.reset_url} className="break-all font-mono text-xs underline" data-testid="reset-url">{reset.reset_url}</a>
        </>
      ) : (
        <>A password reset link was emailed to {reset.email}.</>
      )}
    </Alert>
  )
}
