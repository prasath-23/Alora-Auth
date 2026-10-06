// Every call the SPA makes goes through here.
//
// App Central's access token lives in this module's memory and nowhere else: not
// in a cookie, not in storage, not in React state. Its refresh token is the
// HttpOnly session cookie, which script never sees. So a page reload starts with
// no token, and AuthBootstrap gets one by refreshing the session.
//
// A 401 from /api triggers ONE shared refresh (however many requests failed at
// once) and a single retry with the new token. /auth calls are never retried:
// they are the sign-in steps themselves.
//
// The token also carries a snapshot of the person's access (its scope and
// product list). App Central decides every request from the database, and says
// so when the snapshot is out of date: X-Alora-Token-Stale: 1. The first such
// response starts ONE renewal — a refresh, then `me` again — so the page shows
// the access the person has now.

export const STALE_HEADER = 'X-Alora-Token-Stale'
const RENEW_EVERY_MS = 10_000 // however many stale responses arrive meanwhile

let accessToken = null
let sessionListener = null
let staleListener = null
let refreshing = null
let renewing = null
let lastRenewal = 0

/** Called by the session module whenever the token changes (null = signed out). */
export function onSessionChange(fn) { sessionListener = fn }

/** Called by the session module when a response says the token is out of date. */
export function onTokenStale(fn) { staleListener = fn }

function noticeStale(res) {
  if (res.headers.get(STALE_HEADER) !== '1' || !staleListener || renewing) return
  if (Date.now() - lastRenewal < RENEW_EVERY_MS) return
  lastRenewal = Date.now()
  renewing = Promise.resolve()
    .then(() => staleListener())
    .catch(() => {}) // the next stale response tries again
    .finally(() => { renewing = null })
}

export function setAccessToken(token) { accessToken = token }

export function hasAccessToken() { return accessToken !== null }

export class ApiError extends Error {
  constructor(status, message, reqId) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.reqId = reqId
  }
}

const sleep = ms => new Promise(r => setTimeout(r, ms))

/**
 * Rotates the session cookie and returns a fresh access token, or null when
 * there is no usable session. Throws when App Central cannot answer (the
 * session may be perfectly fine). Concurrent callers share one request.
 */
export function refreshSession() {
  if (!refreshing) {
    refreshing = (async () => {
      // 409 is a benign race: another tab (or a request of ours that crossed
      // this one) rotated the cookie first, and the winner's cookie is the one
      // the browser now holds. Asking again with it succeeds.
      //
      // keepalive: a refresh must never be abandoned half-way. If the page
      // reloads or navigates while one is in flight, the server has already
      // rotated the session, and a browser that drops the response keeps the
      // superseded cookie — every later refresh is then a replay, and the user
      // is signed out. A keepalive request completes regardless, so its new
      // cookie is stored and the next page's retry picks it up.
      //
      // Only a 401 means the session is over. A 409 (the race above), a 429, a
      // 5xx or a network failure says nothing about the session — its cookie is
      // intact — so they are retried, and if they persist the refresh FAILS
      // (throws) rather than reporting "signed out": a busy server must never
      // sign anybody out.
      for (let attempt = 0; attempt < 5; attempt++) {
        let res
        try {
          res = await fetch('/auth/central/refresh', { method: 'POST', credentials: 'same-origin', keepalive: true })
        } catch {
          res = null
        }
        if (res?.ok) {
          const body = await res.json().catch(() => null)
          return body?.access_token ?? null
        }
        if (res?.status === 401) return null
        await sleep(200 * (attempt + 1))
      }
      throw new Error('App Central is not answering. Try again in a moment.')
    })()
      .then(token => {
        accessToken = token
        sessionListener?.(token)
        return token
      })
      .finally(() => { refreshing = null })
  }
  return refreshing
}

function send(method, path, { body, headers, token }) {
  const h = { ...headers }
  if (body !== undefined) h['Content-Type'] = 'application/json'
  if (token) h.Authorization = `Bearer ${token}`
  return fetch(path, {
    method,
    credentials: 'same-origin',
    headers: h,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
}

async function request(method, path, { body, headers } = {}) {
  let res = await send(method, path, { body, headers, token: accessToken })
  if (res.status === 401 && path.startsWith('/api/')) {
    const token = await refreshSession()
    if (token) res = await send(method, path, { body, headers, token })
  }
  noticeStale(res)
  return res
}

async function parse(res) {
  if (res.status === 204) return null
  const body = await res.json().catch(() => null)
  if (!res.ok) {
    throw new ApiError(res.status, body?.error ?? `Request failed (${res.status})`, body?.reqId)
  }
  return body
}

export const api = {
  get:    (path, opts)       => request('GET', path, opts).then(parse),
  post:   (path, body, opts) => request('POST', path, { ...opts, body }).then(parse),
  put:    (path, body, opts) => request('PUT', path, { ...opts, body }).then(parse),
  patch:  (path, body, opts) => request('PATCH', path, { ...opts, body }).then(parse),
  delete: (path, opts)       => request('DELETE', path, opts).then(parse),
}
