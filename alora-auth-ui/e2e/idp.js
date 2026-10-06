import { createServer } from 'node:http'
import { createHash, createSign, generateKeyPairSync, randomBytes } from 'node:crypto'

// A minimal OpenID Connect provider standing in for a company's Okta or Entra
// ID: discovery, JWKS, an authorization endpoint that signs the configured
// user in at once, and a token endpoint that issues an RS256 ID token. It
// checks what a real provider checks — the client's secret, the exact redirect
// URI, the PKCE verifier, single-use codes — so App Central's SSO client is
// exercised against a strict counterpart, not a permissive one.

const b64url = buf => Buffer.from(buf).toString('base64url')

export async function startIdP({ clientId, clientSecret }) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const kid = `idp-${randomBytes(4).toString('hex')}`
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid, alg: 'RS256', use: 'sig' }
  const codes = new Map()
  let issuer = ''
  let user = null // who the next sign-in is: { sub, email, email_verified }

  function sign(claims) {
    const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid }))
    const body = b64url(JSON.stringify(claims))
    const sig = createSign('RSA-SHA256').update(`${header}.${body}`).sign(privateKey)
    return `${header}.${body}.${b64url(sig)}`
  }

  const json = (res, status, body) => {
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
    res.end(JSON.stringify(body))
  }

  async function form(req) {
    let raw = ''
    for await (const chunk of req) raw += chunk
    return new URLSearchParams(raw)
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, issuer)
    if (url.pathname === '/.well-known/openid-configuration') {
      return json(res, 200, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic'],
        code_challenge_methods_supported: ['S256'],
      })
    }
    if (url.pathname === '/jwks') return json(res, 200, { keys: [jwk] })

    if (url.pathname === '/authorize') {
      const q = url.searchParams
      const redirect = q.get('redirect_uri')
      if (q.get('client_id') !== clientId || !redirect) return json(res, 400, { error: 'invalid_request' })
      const back = new URL(redirect)
      back.searchParams.set('state', q.get('state') ?? '')
      if (q.get('response_type') !== 'code' || q.get('code_challenge_method') !== 'S256' || !q.get('code_challenge') || !user) {
        back.searchParams.set('error', 'invalid_request')
      } else {
        const code = b64url(randomBytes(24))
        codes.set(code, { redirect, nonce: q.get('nonce'), challenge: q.get('code_challenge'), user: { ...user } })
        back.searchParams.set('code', code)
      }
      res.writeHead(302, { Location: back.href })
      return res.end()
    }

    if (url.pathname === '/token' && req.method === 'POST') {
      const [scheme, value] = (req.headers.authorization ?? '').split(' ')
      const [id, secret] = scheme === 'Basic'
        ? Buffer.from(value ?? '', 'base64').toString().split(':').map(decodeURIComponent)
        : []
      if (id !== clientId || secret !== clientSecret) return json(res, 401, { error: 'invalid_client' })
      const p = await form(req)
      const grant = codes.get(p.get('code'))
      codes.delete(p.get('code')) // single use
      const verifier = p.get('code_verifier') ?? ''
      if (!grant || p.get('grant_type') !== 'authorization_code' || p.get('redirect_uri') !== grant.redirect ||
          b64url(createHash('sha256').update(verifier).digest()) !== grant.challenge) {
        return json(res, 400, { error: 'invalid_grant' })
      }
      const now = Math.floor(Date.now() / 1000)
      return json(res, 200, {
        access_token: b64url(randomBytes(24)),
        token_type: 'Bearer',
        expires_in: 300,
        id_token: sign({
          iss: issuer, aud: clientId, sub: grant.user.sub, iat: now, exp: now + 300,
          nonce: grant.nonce, email: grant.user.email, email_verified: grant.user.email_verified,
        }),
      })
    }
    json(res, 404, { error: 'not_found' })
  })

  await new Promise(ok => server.listen(0, '127.0.0.1', ok))
  issuer = `http://127.0.0.1:${server.address().port}`
  return {
    issuer,
    signInAs(next) { user = { email_verified: true, ...next } },
    stop: () => new Promise(ok => server.close(ok)),
  }
}
