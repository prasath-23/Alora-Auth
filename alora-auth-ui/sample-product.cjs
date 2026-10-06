'use strict'
// A sample Alora product: the smallest complete integration with App Central,
// written the way every product backend should do it. No dependencies — Node's
// own http and crypto modules only — so each step is visible.
//
//   1. Launch.   App Central opens GET /login/initiate?iss=…&target_link_uri=…
//                (OpenID Connect "third-party initiated login"). The product
//                checks the issuer, then starts an ORDINARY authorization
//                request of its own. App Central never hands it a code it did
//                not ask for, so nobody can plant one.
//   2. Request.  state, nonce and a PKCE verifier are created and kept HERE, on
//                the server, bound to this browser by an HttpOnly cookie.
//   3. Callback. GET /callback?code&state&iss: state must match the browser's
//                cookie, iss must be App Central (RFC 9207), and the code is
//                exchanged at the token endpoint with client_secret_basic.
//   4. Verify.   Both tokens are verified against App Central's JWKS: RS256,
//                issuer, audience (product:<key> for the access token, the
//                client id for the ID token), expiry, the typ header, and the
//                nonce. Tokens never reach the browser.
//   5. Renew.    POST /renew uses the refresh token (rotated every time).
//   6. Logout.   POST /logout revokes the refresh token at App Central.
//
// It also serves applications: GET /api/items answers an API client's token —
// one App Central issued with client credentials, for this product, to an API
// client whose scope includes api:read. Such a token names no person and has
// no roles; `principal` says which kind a token is, and each kind is checked
// for what it carries: roles for a person, scope for an application.
//
// Configuration (environment):
//   ALORA_ISSUER         App Central's issuer, e.g. http://localhost:5173
//   ALORA_CLIENT_ID      the product's client id (its product id)
//   ALORA_CLIENT_SECRET  the product's client secret (acs_…)
//   ALORA_PRODUCT_KEY    the product's key: its tokens' audience is product:<key>
//   PRODUCT_HOST         default 127.0.0.1
//   PRODUCT_PORT         default 4100
//
//   node sample-product.cjs

const http = require('node:http')
const crypto = require('node:crypto')

function required(name) {
  const v = process.env[name]
  if (!v) {
    console.error(`sample-product: ${name} is required`)
    process.exit(2)
  }
  return v
}

const cfg = {
  issuer:       required('ALORA_ISSUER').replace(/\/+$/, ''),
  clientId:     required('ALORA_CLIENT_ID'),
  clientSecret: required('ALORA_CLIENT_SECRET'),
  productKey:   required('ALORA_PRODUCT_KEY'),
  host:         process.env.PRODUCT_HOST || '127.0.0.1',
  port:         Number(process.env.PRODUCT_PORT || 4100),
}
cfg.origin = `http://${cfg.host}:${cfg.port}`
cfg.redirectURI = `${cfg.origin}/callback`
cfg.audience = `product:${cfg.productKey}`

const CLOCK_SKEW_S = 60
const PENDING_TTL_MS = 10 * 60 * 1000

// ── App Central's metadata and keys ───────────────────────────────────────────

let discovery = null
async function provider() {
  if (!discovery) {
    const res = await fetch(`${cfg.issuer}/.well-known/openid-configuration`)
    if (!res.ok) throw new Error(`discovery failed: ${res.status}`)
    const doc = await res.json()
    // The document must describe the issuer we were configured with, or every
    // endpoint in it is somebody else's.
    if (doc.issuer !== cfg.issuer) throw new Error(`discovery names issuer ${doc.issuer}, expected ${cfg.issuer}`)
    discovery = doc
  }
  return discovery
}

let keys = new Map()
let keysFetchedAt = 0
async function keyFor(kid) {
  if (!keys.has(kid) && Date.now() - keysFetchedAt > 10_000) {
    // An unknown kid may be a key App Central just started signing with.
    // Re-fetch — but not more than every ten seconds, so junk tokens cannot
    // turn this server into a JWKS hammer.
    const res = await fetch((await provider()).jwks_uri)
    if (!res.ok) throw new Error(`jwks fetch failed: ${res.status}`)
    const { keys: list } = await res.json()
    keys = new Map(list.filter(k => k.kty === 'RSA' && k.kid).map(k => [k.kid, crypto.createPublicKey({ key: k, format: 'jwk' })]))
    keysFetchedAt = Date.now()
  }
  const key = keys.get(kid)
  if (!key) throw new Error(`unknown signing key ${kid}`)
  return key
}

// ── Token verification ───────────────────────────────────────────────────────

const decode = s => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'))
const typOf = h => String(h.typ ?? '').toLowerCase().replace(/^application\//, '')

async function verifyJWT(token, { typ, audience, nonce }) {
  const parts = String(token).split('.')
  if (parts.length !== 3) throw new Error('malformed token')
  const header = decode(parts[0])
  // Pin the algorithm: never let the token choose how it is verified.
  if (header.alg !== 'RS256') throw new Error(`unexpected alg ${header.alg}`)
  if (typOf(header) !== typ) throw new Error(`unexpected typ ${header.typ}`)
  const key = await keyFor(header.kid)
  const signed = Buffer.from(`${parts[0]}.${parts[1]}`)
  if (!crypto.verify('RSA-SHA256', signed, key, Buffer.from(parts[2], 'base64url'))) {
    throw new Error('bad signature')
  }
  const claims = decode(parts[1])
  const now = Math.floor(Date.now() / 1000)
  if (claims.iss !== cfg.issuer) throw new Error(`unexpected iss ${claims.iss}`)
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud]
  if (!aud.includes(audience)) throw new Error(`token is not for ${audience}`)
  if (typeof claims.exp !== 'number' || claims.exp + CLOCK_SKEW_S < now) throw new Error('token expired')
  if (typeof claims.iat === 'number' && claims.iat - CLOCK_SKEW_S > now) throw new Error('token issued in the future')
  if (!claims.sub) throw new Error('token has no subject')
  if (nonce !== undefined && claims.nonce !== nonce) throw new Error('nonce mismatch')
  return claims
}

async function verifyAccessToken(token) {
  const claims = await verifyJWT(token, { typ: 'at+jwt', audience: cfg.audience })
  // A person's token, from this product's own sign-in: never an application's.
  if (claims.principal !== 'user') throw new Error('not a person\'s token')
  // RFC 9068: client_id names the client the token was issued to.
  if (claims.client_id !== cfg.clientId) throw new Error('access token was issued to another client')
  if (!Array.isArray(claims.roles)) throw new Error('access token has no roles')
  return claims
}

// An application's token: issued to an API client (client_id "aci_…", also its
// subject) with client credentials, for this product. What it may do is its
// scope, never roles.
async function verifyApplicationToken(token) {
  const claims = await verifyJWT(token, { typ: 'at+jwt', audience: cfg.audience })
  if (claims.principal !== 'client') throw new Error('not an application\'s token')
  if (typeof claims.client_id !== 'string' || !claims.client_id.startsWith('aci_') || claims.client_id !== claims.sub) {
    throw new Error('application token names no API client')
  }
  return { ...claims, scopes: String(claims.scope ?? '').split(' ').filter(Boolean) }
}

// GET /api/items — the product's REST API, for applications holding api:read.
// RFC 6750 §3: a missing or bad token is 401 invalid_token, a token without the
// scope 403 insufficient_scope.
async function items(req, res) {
  const [scheme, token] = String(req.headers.authorization ?? '').split(' ')
  const refuse = (status, error, scope) => {
    const challenge = `Bearer error="${error}"${scope ? `, scope="${scope}"` : ''}`
    res.writeHead(status, { 'Content-Type': 'application/json', 'WWW-Authenticate': challenge, 'Cache-Control': 'no-store' })
    res.end(JSON.stringify({ error }))
  }
  if (scheme !== 'Bearer' || !token) return refuse(401, 'invalid_token')
  let claims
  try {
    claims = await verifyApplicationToken(token)
  } catch {
    return refuse(401, 'invalid_token')
  }
  if (!claims.scopes.includes('api:read')) return refuse(403, 'insufficient_scope', 'api:read')
  res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
  res.end(JSON.stringify({
    items: [{ id: 1, name: 'First item' }, { id: 2, name: 'Second item' }],
    client_id: claims.client_id,
    tenant_id: claims.tenant_id,
    scopes: claims.scopes,
  }))
}

// ── App Central's endpoints ──────────────────────────────────────────────────

// RFC 6749 §2.3.1: the id and secret are form-encoded before the Basic encoding.
const basic = () =>
  'Basic ' + Buffer.from(`${encodeURIComponent(cfg.clientId)}:${encodeURIComponent(cfg.clientSecret)}`).toString('base64')

async function tokenRequest(params) {
  const res = await fetch((await provider()).token_endpoint, {
    method: 'POST',
    headers: { Authorization: basic(), 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: new URLSearchParams(params),
  })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) {
    const err = new Error(body.error_description || body.error || `token endpoint answered ${res.status}`)
    err.code = body.error || 'server_error'
    throw err
  }
  return body
}

async function revoke(refreshToken) {
  await fetch((await provider()).revocation_endpoint, {
    method: 'POST',
    headers: { Authorization: basic(), 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token: refreshToken, token_type_hint: 'refresh_token' }),
  })
}

// ── Server-side state ────────────────────────────────────────────────────────

const pending = new Map()  // state -> { verifier, nonce, returnTo, at }
const sessions = new Map() // session id -> { access, accessClaims, idClaims, refresh, renewals }

const random = (n = 32) => crypto.randomBytes(n).toString('base64url')

function cookies(req) {
  const out = {}
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=')
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim())
  }
  return out
}

const cookie = (name, value, maxAge) =>
  `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`

function sessionOf(req) {
  const id = cookies(req).sp_session
  return id ? sessions.get(id) : undefined
}

// Only a path on this product: target_link_uri comes from the query string.
function localPath(target) {
  try {
    const u = new URL(target, cfg.origin)
    return u.origin === cfg.origin ? u.pathname + u.search : '/'
  } catch {
    return '/'
  }
}

// ── Pages ─────────────────────────────────────────────────────────────────────

const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])

function page(res, status, title, body) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
    'X-Content-Type-Options': 'nosniff',
  })
  res.end(`<!doctype html><html><head><meta charset="utf-8"><title>${esc(title)}</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;color:#1f2937}
dt{color:#6b7280;font-size:.85rem}dd{margin:0 0 .6rem}button,a.btn{padding:.4rem .9rem;margin-right:.4rem}</style>
</head><body><h1>${esc(title)}</h1>${body}</body></html>`)
}

function signedInPage(res, s, note = '') {
  const c = s.accessClaims
  page(res, 200, `Sample product · ${cfg.productKey}`, `
${note}
<p data-testid="signed-in">Signed in through App Central.</p>
<dl>
  <dt>Email</dt><dd data-testid="who">${esc(c.email)}</dd>
  <dt>Roles in this product</dt><dd data-testid="roles">${esc(c.roles.join(','))}</dd>
  <dt>Audience</dt><dd data-testid="aud">${esc([].concat(c.aud).join(','))}</dd>
  <dt>Company (tenant_id)</dt><dd data-testid="tenant">${esc(c.tenant_id)}</dd>
  <dt>User (sub)</dt><dd data-testid="sub">${esc(c.sub)}</dd>
  <dt>ID token nonce verified for</dt><dd data-testid="id-aud">${esc([].concat(s.idClaims.aud).join(','))}</dd>
  <dt>Renewals</dt><dd data-testid="renewals">${s.renewals}</dd>
</dl>
<form method="post" action="/renew" style="display:inline"><button type="submit">Renew token</button></form>
<form method="post" action="/logout" style="display:inline"><button type="submit">Sign out of this product</button></form>`)
}

function signedOutPage(res, status, message, code) {
  page(res, status, `Sample product · ${cfg.productKey}`, `
${message ? `<p data-testid="product-message">${esc(message)}</p>` : ''}
${code ? `<p>Code: <code data-testid="product-error">${esc(code)}</code></p>` : ''}
<p data-testid="signed-out">You are not signed in to this product.</p>
<p><a class="btn" href="/login">Sign in with Alora</a></p>`)
}

// ── Routes ────────────────────────────────────────────────────────────────────

async function startLogin(res, returnTo) {
  const state = random()
  const nonce = random()
  const verifier = random(48)
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url')
  pending.set(state, { verifier, nonce, returnTo, at: Date.now() })

  const u = new URL((await provider()).authorization_endpoint)
  u.search = new URLSearchParams({
    response_type: 'code',
    client_id: cfg.clientId,
    redirect_uri: cfg.redirectURI,
    scope: 'openid email',
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString()
  res.writeHead(302, { Location: u.href, 'Set-Cookie': cookie('sp_login', state, 600), 'Cache-Control': 'no-store' })
  res.end()
}

async function callback(req, res, q) {
  const state = q.get('state') || ''
  const bound = cookies(req).sp_login
  const clear = cookie('sp_login', '', 0)
  const p = pending.get(state)
  pending.delete(state) // single use, whatever happens next
  if (!state || !bound || bound !== state || !p || Date.now() - p.at > PENDING_TTL_MS) {
    res.setHeader('Set-Cookie', clear)
    return signedOutPage(res, 400, 'That sign-in did not start in this browser, or took too long.', 'state_mismatch')
  }
  if (q.get('error')) {
    res.setHeader('Set-Cookie', clear)
    return signedOutPage(res, 403, 'App Central did not sign you in.', q.get('error'))
  }
  // RFC 9207: the response must come from the issuer we sent the user to.
  if (q.get('iss') !== cfg.issuer) {
    res.setHeader('Set-Cookie', clear)
    return signedOutPage(res, 400, 'The sign-in response came from an unexpected issuer.', 'iss_mismatch')
  }
  try {
    const t = await tokenRequest({
      grant_type: 'authorization_code', code: q.get('code') || '', redirect_uri: cfg.redirectURI, code_verifier: p.verifier,
    })
    const accessClaims = await verifyAccessToken(t.access_token)
    const idClaims = await verifyJWT(t.id_token, { typ: 'jwt', audience: cfg.clientId, nonce: p.nonce })
    if (idClaims.sub !== accessClaims.sub) throw new Error('the ID token and the access token name different users')
    const id = random()
    sessions.set(id, { access: t.access_token, accessClaims, idClaims, refresh: t.refresh_token, renewals: 0 })
    res.writeHead(302, {
      Location: p.returnTo || '/',
      'Set-Cookie': [clear, cookie('sp_session', id, 12 * 3600)],
      'Cache-Control': 'no-store',
    })
    res.end()
  } catch (err) {
    res.setHeader('Set-Cookie', clear)
    signedOutPage(res, 502, `Sign-in failed: ${err.message}`, err.code || 'verification_failed')
  }
}

async function renew(req, res) {
  const id = cookies(req).sp_session
  const s = id && sessions.get(id)
  if (!s) return signedOutPage(res, 401, 'There is no session to renew.', 'no_session')
  try {
    const t = await tokenRequest({ grant_type: 'refresh_token', refresh_token: s.refresh })
    s.accessClaims = await verifyAccessToken(t.access_token)
    s.access = t.access_token
    s.refresh = t.refresh_token // rotated: the old one is spent
    s.renewals += 1
    res.writeHead(303, { Location: '/', 'Cache-Control': 'no-store' })
    res.end()
  } catch (err) {
    // App Central refused: the user signed out there, lost access, or an
    // administrator ended the session. The product's session ends with it.
    sessions.delete(id)
    res.setHeader('Set-Cookie', cookie('sp_session', '', 0))
    signedOutPage(res, 401, 'Your Alora session has ended.', err.code || 'renewal_failed')
  }
}

async function logout(req, res) {
  const id = cookies(req).sp_session
  const s = id && sessions.get(id)
  if (s) {
    sessions.delete(id)
    await revoke(s.refresh).catch(() => {})
  }
  res.writeHead(303, { Location: '/', 'Set-Cookie': cookie('sp_session', '', 0), 'Cache-Control': 'no-store' })
  res.end()
}

// A state-changing POST must come from this product's own pages.
function sameOrigin(req) {
  const site = req.headers['sec-fetch-site']
  if (site) return site === 'same-origin' || site === 'none'
  const origin = req.headers.origin
  return !origin || origin === cfg.origin
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, cfg.origin)
  const q = url.searchParams
  try {
    if (req.method === 'GET' && url.pathname === '/health') {
      res.writeHead(200, { 'Content-Type': 'text/plain' })
      return res.end('ok')
    }
    if (req.method === 'GET' && url.pathname === '/login/initiate') {
      // Only App Central may launch this product: an unknown iss is refused
      // rather than followed to wherever it points.
      if (q.get('iss') !== cfg.issuer) return signedOutPage(res, 400, 'Unknown issuer.', 'invalid_issuer')
      return await startLogin(res, localPath(q.get('target_link_uri') || '/'))
    }
    if (req.method === 'GET' && url.pathname === '/login') return await startLogin(res, '/')
    if (req.method === 'GET' && url.pathname === '/callback') return await callback(req, res, q)
    if (req.method === 'POST' && (url.pathname === '/renew' || url.pathname === '/logout')) {
      if (!sameOrigin(req)) return signedOutPage(res, 403, 'Cross-site request refused.', 'forbidden')
      return url.pathname === '/renew' ? await renew(req, res) : await logout(req, res)
    }
    if (req.method === 'GET' && url.pathname === '/api/items') return await items(req, res)
    if (req.method === 'GET' && url.pathname === '/api/session') {
      // What the page shows, as JSON — the verified claims, never the tokens.
      const s = sessionOf(req)
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
      return res.end(JSON.stringify(s
        ? { signed_in: true, claims: s.accessClaims, id_token: s.idClaims, renewals: s.renewals }
        : { signed_in: false }))
    }
    if (req.method === 'GET' && url.pathname === '/') {
      const s = sessionOf(req)
      return s ? signedInPage(res, s) : signedOutPage(res, 200)
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' })
    res.end('not found')
  } catch (err) {
    console.error('sample-product:', err)
    if (!res.headersSent) signedOutPage(res, 500, `Something went wrong: ${err.message}`, 'server_error')
  }
})

server.listen(cfg.port, cfg.host, () => {
  console.log(`sample product ${cfg.productKey} on ${cfg.origin} (issuer ${cfg.issuer})`)
})
