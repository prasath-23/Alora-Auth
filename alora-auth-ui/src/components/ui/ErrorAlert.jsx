import { Link, useLocation } from 'react-router-dom'
import Alert from './Alert'
import { query } from '../../utils/format'

// Renders an API failure. The one failure a user can fix on the spot is the
// Owner console's recent-sign-in requirement, so that one offers the way out.
export default function ErrorAlert({ error, onClose }) {
  const location = useLocation()
  if (!error) return null

  if (error.status === 403 && /recent sign-in/i.test(error.message)) {
    const back = location.pathname + location.search
    return (
      <Alert type="warning" onClose={onClose}>
        For your security, sign in again to continue.{' '}
        <Link className="font-medium underline" to={`/login${query({ return_to: back })}`}>Sign in again</Link>
      </Alert>
    )
  }

  return (
    <Alert type="error" onClose={onClose}>
      {error.message}
      {error.reqId && <span className="ml-2 text-xs opacity-60">(ref {error.reqId})</span>}
    </Alert>
  )
}
