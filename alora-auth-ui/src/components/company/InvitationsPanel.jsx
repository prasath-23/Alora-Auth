import { useState } from 'react'
import useAuthStore from '../../store/authStore'
import useResource from '../../hooks/useResource'
import { rulesFor } from '../../utils/scopes'
import { formatDate } from '../../utils/format'
import { Badge, Card, Cell, EmptyState, Loading, Table } from '../ui/Layout'
import Input, { Checkbox } from '../ui/Input'
import Button from '../ui/Button'
import Alert from '../ui/Alert'
import ErrorAlert from '../ui/ErrorAlert'
import { LIMITS } from '../../utils/limits'

const STATUS_TONES = { PENDING: 'blue', ACCEPTED: 'green', EXPIRED: 'gray', REVOKED: 'red' }

// Invitations into a company. An invitation names the groups the new account
// joins, and through them what it may do and open; how the invitee signs in
// follows from the login policy those groups (or the company default) set.
// Inviting and revoking need invitations:edit (`canEdit`), and an invitation
// can only name groups whose access the inviter holds all of. Offering groups
// at all needs groups:read (`canSeeGroups`): without it the groups are not
// asked for — the API would refuse — and the invitation joins no group.
export default function InvitationsPanel({ api, canEdit = true, canSeeGroups = true }) {
  const invitations = useResource(() => api.listInvitations(), [api])
  const offerGroups = canEdit && canSeeGroups
  const groups = useResource(() => (offerGroups ? api.listGroups() : Promise.resolve([])), [api, offerGroups])
  const [actionError, setActionError] = useState(null)
  const [revoking, setRevoking] = useState(null)

  async function revoke(id) {
    setActionError(null)
    setRevoking(id)
    try {
      await api.revokeInvitation(id)
      await invitations.reload()
    } catch (err) {
      setActionError(err)
    } finally {
      setRevoking(null)
    }
  }

  return (
    <div className="space-y-6">
      {canEdit && <NewInvitation api={api} groups={groups.data ?? []} canSeeGroups={canSeeGroups} onCreated={invitations.reload} />}
      <ErrorAlert error={invitations.error || groups.error || actionError} onClose={() => setActionError(null)} />
      {invitations.loading && !invitations.data ? <Loading /> : (
        <Table
          columns={[{ label: 'Email' }, { label: 'Status' }, { label: 'Sent' }, { label: 'Expires' }, { label: '', align: 'right' }]}
          footer={invitations.data?.length === 0 && <EmptyState>No invitations yet.</EmptyState>}
        >
          {invitations.data?.map(inv => (
            <tr key={inv.id} data-testid="invitation-row">
              <Cell>{inv.email}</Cell>
              <Cell><Badge tone={STATUS_TONES[inv.status]}>{inv.status}</Badge></Cell>
              <Cell className="text-gray-500">{formatDate(inv.created_at)}</Cell>
              <Cell className="text-gray-500">{formatDate(inv.expires_at)}</Cell>
              <Cell align="right">
                {canEdit && inv.status === 'PENDING' && <Button variant="ghost" size="sm" loading={revoking === inv.id} onClick={() => revoke(inv.id)}>Revoke</Button>}
              </Cell>
            </tr>
          ))}
        </Table>
      )}
    </div>
  )
}

function NewInvitation({ api, groups, canSeeGroups, onCreated }) {
  const me = useAuthStore(s => s.me)
  const { canGive } = rulesFor(me, api.kind)
  const [email, setEmail] = useState('')
  const [groupIds, setGroupIds] = useState([])
  const [error, setError] = useState(null)
  const [sent, setSent] = useState(null)
  const [saving, setSaving] = useState(false)

  const toggle = id => setGroupIds(ids => (ids.includes(id) ? ids.filter(x => x !== id) : [...ids, id]))

  async function submit(e) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    setSent(null)
    try {
      setSent(await api.createInvitation(email.trim(), groupIds))
      setEmail('')
      setGroupIds([])
      onCreated()
    } catch (err) {
      setError(err)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Card title="Invite someone">
      <form onSubmit={submit} className="space-y-4">
        <ErrorAlert error={error} onClose={() => setError(null)} />
        {sent && (
          <Alert type="success" onClose={() => setSent(null)}>
            Invitation created for {sent.email}.
            {sent.invite_url && (
              <> Invite link (shown because email is not configured):{' '}
                <a href={sent.invite_url} className="break-all font-mono text-xs underline" data-testid="invite-url">{sent.invite_url}</a>
              </>
            )}
          </Alert>
        )}
        <Input id="invite-email" maxLength={LIMITS.email} label="Email" type="email" required value={email} onChange={e => setEmail(e.target.value)} />
        {!canSeeGroups && (
          <p className="text-xs text-gray-500" data-testid="invite-no-groups">
            The invitation joins no group. Inviting someone straight into groups needs Groups: Read.
          </p>
        )}
        {groups.length > 0 && (
          <fieldset>
            <legend className="mb-2 text-sm font-medium text-gray-700">Groups to join</legend>
            <div className="grid gap-2 sm:grid-cols-2">
              {groups.map(g => {
                const allowed = canGive(g.scopes)
                return (
                  <Checkbox key={g.id} id={`invite-group-${g.id}`} label={g.name}
                    description={allowed ? (g.description || null) : 'Gives access you don’t hold yourself'}
                    checked={groupIds.includes(g.id)} disabled={!allowed} onChange={() => toggle(g.id)} />
                )
              })}
            </div>
          </fieldset>
        )}
        <Button type="submit" loading={saving} disabled={!email.trim()}>Send invitation</Button>
      </form>
    </Card>
  )
}
