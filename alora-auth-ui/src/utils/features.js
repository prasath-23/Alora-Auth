import useAuthStore from '../store/authStore'

// Mirrors server-side ADMIN_FEATURES registry in src/lib/features.js.
export const ADMIN_FEATURES = Object.freeze({
  USERS_VIEW:       'users:view',
  USERS_ADD:        'users:add',
  USERS_EDIT:       'users:edit',
  USERS_DEACTIVATE: 'users:deactivate',
  PASSWORDS_RESET:  'passwords:reset',
  PRODUCTS_VIEW:    'products:view',
  SESSIONS_VIEW:    'sessions:view',
  SESSIONS_REVOKE:  'sessions:revoke',
  GROUPS_VIEW:      'groups:view',
  GROUPS_MANAGE:    'groups:manage',
  CLIENT_VIEW:      'client:view',
  CLIENT_EDIT:      'client:edit',
})

// Grouped for the checkbox UI (Copilot: grouped checkboxes beat a wall of 12)
export const FEATURE_GROUPS = [
  { label: 'Users',     keys: ['users:view', 'users:add', 'users:edit', 'users:deactivate'] },
  { label: 'Passwords', keys: ['passwords:reset'] },
  { label: 'Products',  keys: ['products:view'] },
  { label: 'Sessions',  keys: ['sessions:view', 'sessions:revoke'] },
  { label: 'Groups',    keys: ['groups:view', 'groups:manage'] },
  { label: 'Client',    keys: ['client:view', 'client:edit'] },
]

export const FEATURE_LABELS = {
  'users:view':        'View',
  'users:add':         'Add',
  'users:edit':        'Edit',
  'users:deactivate':  'Deactivate',
  'passwords:reset':   'Reset Password',
  'products:view':     'View',
  'sessions:view':     'View',
  'sessions:revoke':   'Revoke',
  'groups:view':       'View',
  'groups:manage':     'Manage',
  'client:view':       'View',
  'client:edit':       'Edit',
}

// Hook: true if the current user has this feature in their Zustand features Set.
export function useFeature(featureKey) {
  return useAuthStore(s => s.features.has(featureKey))
}
