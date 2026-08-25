'use strict'

// Dummy product server — simulates a product (CRM) doing the full PKCE flow.
// Run: node dummy-product.js
// Then open: http://localhost:4001

const http   = require('node:http')
const crypto = require('node:crypto')

const PORT         = 4001
const PRODUCT_ID   = '71cc6ca1-2cfb-4457-b82b-361e0d5170e2'
const REDIRECT_URL = 'http://prod1.alora.test:4001'
const AUTH_UI      = 'http://auth.alora.test:5173'
const AUTH_API     = 'http://127.0.0.1:3001'

let pendingVerifier = null
let pendingState    = null

// Node 18+ fetch Headers has getSetCookie(); fall back to get() for older runtimes.
function getSetCookies(response) {
  if (typeof response.headers.getSetCookie === 'function') {
    return response.headers.getSetCookie()
  }
  const raw = response.headers.get('set-cookie')
  return raw ? [raw] : []
}

function generatePkce() {
  const verifier  = crypto.randomBytes(32).toString('base64url')
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url')
  return { verifier, challenge }
}

const server = http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url, `http://localhost:${PORT}`)
  const path   = reqUrl.pathname
  const code   = reqUrl.searchParams.get('code')

  // ── /login — generate PKCE + state (with next URL encoded) ─────────────────
  // state = base64url(JSON{ csrf, next }) — csrf prevents CSRF, next restores routing
  if (path === '/login') {
    const next            = reqUrl.searchParams.get('next') || '/'
    const { verifier, challenge } = generatePkce()
    const statePayload    = { csrf: crypto.randomBytes(16).toString('hex'), next }
    const state           = Buffer.from(JSON.stringify(statePayload)).toString('base64url')
    pendingVerifier       = verifier
    pendingState          = state
    const dest = new URL(AUTH_UI)
    dest.searchParams.set('product_id',           PRODUCT_ID)
    dest.searchParams.set('redirect_url',          REDIRECT_URL)
    dest.searchParams.set('code_challenge',        challenge)
    dest.searchParams.set('code_challenge_method', 'S256')
    dest.searchParams.set('state',                 state)
    res.writeHead(302, { Location: dest.toString() })
    return res.end()
  }

  // ── /auth/refresh — proxy to auth API (browser calls this directly) ───────
  if (path === '/auth/refresh' && req.method === 'POST') {
    let apiRes, apiBody, apiStatus
    try {
      apiRes    = await fetch(`${AUTH_API}/auth/refresh`, {
        method:  'POST',
        headers: { Cookie: req.headers.cookie || '' },
      })
      apiStatus = apiRes.status
      apiBody   = await apiRes.text()
      const newCookies = getSetCookies(apiRes)
      if (newCookies.length) res.setHeader('Set-Cookie', newCookies)
    } catch (err) {
      res.writeHead(502, { 'Content-Type': 'application/json' })
      return res.end(JSON.stringify({ error: err.message }))
    }
    res.writeHead(apiStatus, { 'Content-Type': 'application/json' })
    return res.end(apiBody)
  }

  // ── /clear — wipe refresh cookie + signal browser to clear sessionStorage ─
  if (path === '/clear') {
    try {
      await fetch(`${AUTH_API}/auth/logout`, {
        method:  'POST',
        headers: { Cookie: req.headers.cookie || '' },
      })
    } catch { /* best-effort — still clear cookies */ }
    res.writeHead(200, {
      'Set-Cookie': [
        `alora_rt=; Path=/; HttpOnly; SameSite=Lax; Domain=.alora.test; Max-Age=0`,
        `alora_at=; Path=/; SameSite=Lax; Domain=.alora.test; Max-Age=0`,
        `alora_at_readable=; Path=/; SameSite=Lax; Domain=.alora.test; Max-Age=0`,
      ],
      'Content-Type': 'text/html; charset=utf-8',
    })
    return res.end(`<script>sessionStorage.clear(); location.href='/'</script>`)
  }

  // ── Callback: auth UI redirected back with ?code=&state= ─────────────────
  if (code) {
    const verifier      = pendingVerifier
    const expectedState = pendingState
    pendingVerifier     = null
    pendingState        = null

    if (!verifier) {
      return html(res, 400, `<h2>Error</h2><p>No pending login session. <a href="/">Go home</a></p>`)
    }

    const returnedState = reqUrl.searchParams.get('state')
    if (!returnedState || returnedState !== expectedState) {
      return html(res, 400, `<h2>&#128683; State mismatch — possible CSRF</h2><p>Expected state does not match returned state. Login rejected.</p><p><a href="/">Go home</a></p>`)
    }

    // Decode next URL from verified state payload
    let nextUrl = '/'
    try {
      const decoded = JSON.parse(Buffer.from(returnedState, 'base64url').toString('utf8'))
      if (typeof decoded.next === 'string' && decoded.next.startsWith('/')) nextUrl = decoded.next
    } catch { /* fall back to / */ }

    let tokenData, tokenStatus, setCookies
    const requestBody = {
      code,
      code_verifier: verifier,
      product_id:    PRODUCT_ID,
      redirect_url:  REDIRECT_URL,
    }

    try {
      const r = await fetch(`${AUTH_API}/auth/token`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(requestBody),
      })
      tokenStatus = r.status
      tokenData   = await r.json()
      setCookies  = getSetCookies(r)
    } catch (err) {
      return html(res, 500, `<h2>Fetch error</h2><pre>${err.message}</pre>`)
    }

    if (tokenStatus === 200 && setCookies.length) {
      // Forward both alora_rt and alora_at cookies to the browser.
      const logEntry = JSON.stringify({
        label:    'POST /auth/token (code exchange)',
        request:  { product_id: requestBody.product_id, redirect_url: requestBody.redirect_url, code: '[REDACTED]', code_verifier: '[REDACTED]' },
        status:   tokenStatus,
        response: tokenData,
        cookies:  { 'Set-Cookie': setCookies },
      })
      // Also set access token in a non-HttpOnly cookie so JS can read it across reloads
      const extraCookies = [
        ...setCookies,
        `alora_at_readable=; Path=/; SameSite=Lax; Domain=.alora.test; Max-Age=0`,
      ]
      res.writeHead(200, {
        'Set-Cookie':   extraCookies,
        'Content-Type': 'text/html; charset=utf-8',
      })
      const token = JSON.stringify(tokenData.access_token)
      return res.end(`<script>
        const tokenValue = ${token};
        sessionStorage.setItem('dummy_access_token', tokenValue);
        document.cookie = 'alora_at_readable=' + encodeURIComponent(tokenValue) + '; Path=/; SameSite=Lax; Domain=.alora.test; Max-Age=2592000';
        sessionStorage.setItem('dummy_api_log', JSON.stringify([${logEntry}]));
        location.href = ${JSON.stringify(nextUrl)};
      </script>`)
    }

    return html(res, tokenStatus, `
      <h2>&#10060; Token exchange failed (HTTP ${tokenStatus})</h2>
      <pre>${JSON.stringify(tokenData, null, 2)}</pre>
      <p><a href="/">Go home</a></p>
    `)
  }

  // ── /orders — protected sample page ─────────────────────────────────────────
  // Client JS checks for a valid token; if missing, redirects to /login?next=/orders
  if (path === '/orders') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    return res.end(`<!DOCTYPE html>
<html>
<head>
<style>
  body { font-family: monospace; max-width: 860px; margin: 2rem auto; padding: 0 1rem; background: #f9f9f9; }
  h1   { font-size: 1.2rem; margin-bottom: 0.5rem; }
  nav  { margin-bottom: 1.5rem; font-size: 0.85rem; color: #555; }
  nav a { color: #0066cc; text-decoration: none; margin-right: 1rem; }
  .card { background: #fff; border: 1px solid #ddd; border-radius: 6px; padding: 1rem 1.2rem; margin-bottom: 1rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th    { text-align: left; padding: 0.5rem 0.8rem; background: #f4f4f4; border-bottom: 2px solid #ddd; }
  td    { padding: 0.5rem 0.8rem; border-bottom: 1px solid #eee; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.78rem; font-weight: bold; }
  .open     { background: #d4edda; color: #155724; }
  .pending  { background: #fff3cd; color: #856404; }
  .closed   { background: #e2e3e5; color: #383d41; }
  .muted    { color: #888; font-size: 0.85rem; }
  #auth-check { display: none; }
</style>
</head>
<body>
  <h1>&#128230; Orders</h1>
  <nav>
    <a href="/">&#8592; Dashboard</a>
    <a href="/clear">Clear session</a>
  </nav>

  <div id="auth-check" class="card">
    <p class="muted">Checking session…</p>
  </div>

  <div id="page-content" style="display:none">
    <div class="card">
      <table>
        <thead>
          <tr><th>Order ID</th><th>Customer</th><th>Amount</th><th>Status</th><th>Date</th></tr>
        </thead>
        <tbody>
          <tr><td>#1042</td><td>Acme Corp</td><td>$4,200</td><td><span class="badge open">Open</span></td><td>2026-05-18</td></tr>
          <tr><td>#1041</td><td>Globex Inc</td><td>$1,850</td><td><span class="badge pending">Pending</span></td><td>2026-05-17</td></tr>
          <tr><td>#1040</td><td>Initech</td><td>$9,100</td><td><span class="badge closed">Closed</span></td><td>2026-05-15</td></tr>
          <tr><td>#1039</td><td>Umbrella Ltd</td><td>$620</td><td><span class="badge open">Open</span></td><td>2026-05-14</td></tr>
          <tr><td>#1038</td><td>Acme Corp</td><td>$3,300</td><td><span class="badge closed">Closed</span></td><td>2026-05-12</td></tr>
        </tbody>
      </table>
    </div>
    <div class="card">
      <p class="muted">Logged in as: <span id="user-email"></span> &nbsp;|&nbsp; Token expires: <span id="token-exp"></span></p>
    </div>
  </div>

  <script>
    function getCookie(name) {
      const m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'))
      return m ? decodeURIComponent(m[1]) : null
    }
    function decodeJwt(t) {
      return JSON.parse(atob(t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')))
    }
    function isExpired(t) {
      try { return decodeJwt(t).exp * 1000 < Date.now() } catch { return true }
    }

    async function checkAuth() {
      let token = sessionStorage.getItem('dummy_access_token') || getCookie('alora_at_readable')

      if (!token || isExpired(token)) {
        // Try silent refresh before giving up
        try {
          const r    = await fetch('/auth/refresh', { method: 'POST', credentials: 'include' })
          const data = await r.json()
          if (r.ok) {
            token = data.access_token
            sessionStorage.setItem('dummy_access_token', token)
          }
        } catch { /* network error — fall through */ }
      }

      if (!token || isExpired(token)) {
        // No valid session — redirect to login, encoding current page as next
        window.location.href = '/login?next=/orders'
        return
      }

      // Valid token — render the page
      const claims = decodeJwt(token)
      document.getElementById('user-email').textContent = claims.email || claims.sub || 'unknown'
      document.getElementById('token-exp').textContent  = new Date(claims.exp * 1000).toLocaleTimeString()
      document.getElementById('page-content').style.display = 'block'
    }

    checkAuth()
  </script>
</body>
</html>`)
  }

  // ── / — product dashboard ─────────────────────────────────────────────────
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
  res.end(`<!DOCTYPE html>
<html>
<head>
<style>
  body { font-family: monospace; max-width: 860px; margin: 2rem auto; padding: 0 1rem; background: #f9f9f9; }
  h1   { font-size: 1.2rem; margin-bottom: 1.5rem; }
  .card { background: #fff; border: 1px solid #ddd; border-radius: 6px; padding: 1rem 1.2rem; margin-bottom: 1rem; }
  .card h2 { margin: 0 0 0.5rem; font-size: 1rem; }
  .tag  { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; margin-bottom: 0.5rem; }
  .tag.green  { background: #d4edda; color: #155724; }
  .tag.red    { background: #f8d7da; color: #721c24; }
  .tag.yellow { background: #fff3cd; color: #856404; }
  pre  { background: #f4f4f4; padding: 0.7rem; border-radius: 4px; overflow-x: auto; font-size: 0.82rem; margin: 0.4rem 0 0; }
  .api-call { border-left: 3px solid #aaa; padding-left: 0.8rem; margin-bottom: 1rem; }
  .api-call.ok  { border-color: #28a745; }
  .api-call.err { border-color: #dc3545; }
  .api-label { font-weight: bold; margin-bottom: 0.3rem; }
  .status-badge { font-size: 0.78rem; padding: 1px 7px; border-radius: 3px; margin-left: 6px; }
  .status-ok  { background: #d4edda; color: #155724; }
  .status-err { background: #f8d7da; color: #721c24; }
  button { padding: 0.5rem 1.4rem; font-size: 0.95rem; cursor: pointer; border: none; border-radius: 4px; background: #0066cc; color: #fff; }
  button:hover { background: #0052a3; }
  .muted { color: #888; font-size: 0.85rem; }
</style>
</head>
<body>
  <h1>Dummy Product — CRM Dashboard</h1>
  <nav style="margin-bottom:1rem;font-size:0.85rem">
    <a href="/orders" style="color:#0066cc;text-decoration:none;margin-right:1rem">&#128230; Orders</a>
  </nav>
  <div id="status-card" class="card"><p class="muted">Checking session...</p></div>
  <div id="api-log"></div>

  <script>
    const TOKEN_KEY  = 'dummy_access_token'
    const LOG_KEY    = 'dummy_api_log'

    function decodeJwt(token) {
      return JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')))
    }

    function isExpired(token) {
      try { return decodeJwt(token).exp * 1000 < Date.now() } catch { return true }
    }

    function getLog()       { try { return JSON.parse(sessionStorage.getItem(LOG_KEY) || '[]') } catch { return [] } }
    function pushLog(entry) { const l = getLog(); l.push(entry); sessionStorage.setItem(LOG_KEY, JSON.stringify(l)) }

    function renderStatus(icon, title, tagClass, tagText, payload) {
      document.getElementById('status-card').innerHTML = \`
        <h2>\${icon} \${title}</h2>
        <span class="tag \${tagClass}">\${tagText}</span>
        <pre>\${JSON.stringify(payload, null, 2)}</pre>
        <br/>
        <a href="/clear"><button style="background:#c0392b">Clear session</button></a>
      \`
    }

    function renderLoginButton(reason) {
      document.getElementById('status-card').innerHTML = \`
        <h2>&#128274; \${reason}</h2>
        <p class="muted">No valid session. Please log in to continue.</p>
        <br/>
        <a href="/login"><button>Go to Login</button></a>
      \`
    }

    function renderApiLog() {
      const log = getLog()
      if (!log.length) { document.getElementById('api-log').innerHTML = ''; return }
      const items = log.map(e => \`
        <div class="api-call \${e.status < 400 ? 'ok' : 'err'}">
          <div class="api-label">
            \${e.label}
            <span class="status-badge \${e.status < 400 ? 'status-ok' : 'status-err'}">HTTP \${e.status}</span>
          </div>
          \${e.request ? \`<div class="muted">Request</div><pre>\${JSON.stringify(e.request, null, 2)}</pre>\` : ''}
          <div class="muted">Response</div>
          <pre>\${JSON.stringify(e.response, null, 2)}</pre>
          \${e.cookies ? \`<div class="muted">Response Cookies</div><pre>\${JSON.stringify(e.cookies, null, 2)}</pre>\` : ''}
        </div>
      \`).join('')
      document.getElementById('api-log').innerHTML = \`
        <div class="card">
          <h2>API Calls</h2>
          \${items}
        </div>
      \`
    }

    function getCookie(name) {
      const match = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'))
      return match ? decodeURIComponent(match[1]) : null
    }

    async function init() {
      // Step 1 — valid access token in sessionStorage
      let stored = sessionStorage.getItem(TOKEN_KEY)
      if (stored && !isExpired(stored)) {
        renderStatus('&#9989;', 'Access token present', 'green', 'FROM SESSION', decodeJwt(stored))
        renderApiLog()
        return
      }

      // Step 1b — token not in session, check persistent cookie
      const cookieToken = getCookie('alora_at_readable')
      if (cookieToken && !isExpired(cookieToken)) {
        sessionStorage.setItem(TOKEN_KEY, cookieToken)
        renderStatus('&#9989;', 'Access token present', 'green', 'FROM COOKIE', decodeJwt(cookieToken))
        renderApiLog()
        return
      }

      // Step 2 — call refresh (token missing or expired)
      let res, data
      try {
        res  = await fetch('/auth/refresh', { method: 'POST', credentials: 'include' })
        data = await res.json()
      } catch (err) {
        renderLoginButton('Network error: ' + err.message)
        return
      }

      pushLog({
        label:    'POST /auth/refresh',
        status:   res.status,
        response: data,
      })
      renderApiLog()

      if (res.ok) {
        sessionStorage.setItem(TOKEN_KEY, data.access_token)
        renderStatus('&#128260;', 'Access token obtained via refresh', 'yellow', 'REFRESHED', decodeJwt(data.access_token))
        return
      }

      // Step 3 — refresh failed, ask to login
      sessionStorage.removeItem(TOKEN_KEY)
      renderLoginButton(res.status === 401 ? 'Session expired or not found' : \`Refresh failed (HTTP \${res.status})\`)
    }

    init()
  </script>
</body>
</html>`)
})

function html(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' })
  res.end(`<!DOCTYPE html><html><body style="font-family:monospace;max-width:800px;margin:2rem auto;padding:0 1rem">
    ${body}
  </body></html>`)
}

server.listen(PORT, '0.0.0.0', () => {
  console.log(`\nDummy product running → http://prod1.alora.test:${PORT}`)
  console.log('Open that URL in your browser.\n')
})
