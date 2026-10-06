// Mirrors the API's scope registry (internal/core/shared/scopes.go): what a
// person may do in App Central, feature by feature — Read to look, Edit to
// change. Edit includes Read, and a token lists both. A company's Admins hold
// every scope; everyone signed in holds apps:read.
export const FEATURES = [
  { key: 'users',       label: 'Users',       read: 'users:read',       edit: 'users:edit',
    lets: 'See people and their access', editLets: 'Activate and deactivate people, send password resets, give extra access' },
  { key: 'groups',      label: 'Groups',      read: 'groups:read',      edit: 'groups:edit',
    lets: 'See groups and their members', editLets: 'Create, rename and delete groups, choose their access, add and remove members' },
  { key: 'invitations', label: 'Invitations', read: 'invitations:read', edit: 'invitations:edit',
    lets: 'See invitations', editLets: 'Invite people into groups, revoke invitations' },
  { key: 'sessions',    label: 'Sessions',    read: 'sessions:read',    edit: 'sessions:edit',
    lets: 'See who is signed in', editLets: 'Revoke sessions' },
  { key: 'products',    label: 'Products',    read: 'products:read',    edit: null,
    lets: 'See the company’s subscriptions (the Owner decides them)' },
  { key: 'company',     label: 'Company',     read: 'company:read',     edit: 'company:edit',
    lets: 'See the company’s settings', editLets: 'Rename the company' },
  { key: 'api-clients', label: 'API clients', read: 'api-clients:read', edit: 'api-clients:edit',
    lets: 'See API clients', editLets: 'Create API clients, rotate their secrets, choose their products and scope' },
]

// Mirrors the application scopes: where an API client's credential may be
// used. They are given to API clients only, never to people, and edit includes
// read here too.
export const CLIENT_FEATURES = [
  { key: 'api',  label: 'REST API',  read: 'api:read',  edit: 'api:edit',
    lets: 'Read through the product’s REST API', editLets: 'Change data through it' },
  { key: 'grpc', label: 'gRPC',      read: 'grpc:read', edit: 'grpc:edit',
    lets: 'Read through the product’s gRPC services', editLets: 'Change data through them' },
  { key: 'mcp',  label: 'MCP tools', read: 'mcp:tools', edit: null,
    lets: 'Use the product’s MCP tools, as an AI agent does' },
]

export const LEVELS = ['none', 'read', 'edit']
export const LEVEL_LABELS = { none: 'None', read: 'Read', edit: 'Edit' }

/** Every scope a group or an extra can give. */
export const GRANTABLE = FEATURES.flatMap(f => (f.edit ? [f.read, f.edit] : [f.read]))

/** Whether `me` holds a scope. Rendering only: the API checks again. */
export function can(me, scope) {
  return !!me && me.scopes.includes(scope)
}

/** Whether `me` should see the admin area at all. */
export function seesAdmin(me) {
  return !!me && (me.scopes.some(s => GRANTABLE.includes(s)) || manages(me))
}

/** Whether the person runs at least one group as its manager. */
export function manages(me) {
  return (me?.manages?.length ?? 0) > 0
}

/** The level a set of scopes gives in one feature. */
export function levelOf(scopes, feature) {
  if (feature.edit && scopes.includes(feature.edit)) return 'edit'
  return scopes.includes(feature.read) ? 'read' : 'none'
}

/** The scopes one level of a feature consists of. */
export function scopesAt(feature, level) {
  if (level === 'edit' && feature.edit) return [feature.read, feature.edit]
  return level === 'none' ? [] : [feature.read]
}

/** `scopes` with one feature set to `level`, sorted as the API stores them. */
export function withLevel(scopes, feature, level) {
  const rest = scopes.filter(s => s !== feature.read && s !== feature.edit)
  return [...rest, ...scopesAt(feature, level)].sort()
}

/** Every scope in one list and not the other: what a change gives or takes away. */
export function changed(before, after) {
  const b = new Set(before)
  const a = new Set(after)
  return [...before.filter(s => !a.has(s)), ...after.filter(s => !b.has(s))]
}

export const sameScopes = (a, b) => [...a].sort().join() === [...b].sort().join()

/** "Users (edit), Sessions (read)", for a table cell. */
export function describe(scopes) {
  return FEATURES
    .map(f => ({ f, level: levelOf(scopes, f) }))
    .filter(x => x.level !== 'none')
    .map(x => `${x.f.label} (${x.level})`)
    .join(', ')
}

/**
 * The two rules, as the API applies them to the signed-in person, for one door:
 * nobody gives or takes away a scope they do not hold (canGive), and nobody acts
 * on someone with more access than they have (canManage). The Owner console is
 * bound by neither. Rendering only: the API decides.
 */
export function rulesFor(me, door) {
  if (door === 'owner') return { canGive: () => true, canManage: () => true }
  // A manager changes only who is in their groups, and the API measures each
  // person against their reach; nothing on their page gives a scope.
  if (door === 'manager') return { canGive: () => false, canManage: () => false }
  const held = new Set(me?.scopes ?? [])
  return {
    canGive: scopes => scopes.every(s => held.has(s)),
    canManage: (scopes, isOwner) => !isOwner && scopes.every(s => held.has(s)),
  }
}
