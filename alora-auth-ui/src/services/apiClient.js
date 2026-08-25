const API_BASE = ''

// Paths that must NOT trigger a refresh+retry — would cause loops or make no sense.
const NO_RETRY_PATHS = new Set([
  '/auth/refresh',
  '/auth/logout',
  '/auth/session',
  '/auth/reset-password',
])

// Single-flight refresh: if concurrent requests all get 401, only ONE refresh call
// goes out. All callers share the same promise and get the new token together.
let refreshPromise = null

// Callback registered by AuthBootstrap to sync the new token into Zustand after refresh.
let _onTokenRefreshed = null
export function setOnTokenRefreshed(fn) { _onTokenRefreshed = fn }

async function doRefresh() {
  if (!refreshPromise) {
    refreshPromise = fetch('/auth/refresh', { method: 'POST', credentials: 'include' })
      .then(async (res) => {
        if (!res.ok) throw new Error('refresh_failed')
        const { access_token } = await res.json()
        if (_onTokenRefreshed) _onTokenRefreshed(access_token)
        return access_token
      })
      .finally(() => { refreshPromise = null })
  }
  return refreshPromise
}

function buildRequest(method, path, { body, token } = {}) {
  const headers = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (token) headers['Authorization'] = `Bearer ${token}`
  return fetch(`${API_BASE}${path}`, {
    method,
    credentials: 'include',
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
}

async function request(method, path, opts = {}) {
  let res = await buildRequest(method, path, opts)

  // Not a 401, or a path that should never retry — return as-is.
  if (res.status !== 401 || NO_RETRY_PATHS.has(path)) return res

  // 401 on a retryable path — attempt one silent refresh then retry once.
  try {
    const newToken = await doRefresh()
    res = await buildRequest(method, path, { ...opts, token: newToken })
  } catch {
    // Refresh failed — return the original 401 so the caller handles sign-out.
  }

  return res
}

export const api = {
  get:    (path, token)       => request('GET',    path, { token }),
  post:   (path, body, token) => request('POST',   path, { body, token }),
  patch:  (path, body, token) => request('PATCH',  path, { body, token }),
  put:    (path, body, token) => request('PUT',    path, { body, token }),
  delete: (path, token)       => request('DELETE', path, { token }),
}
