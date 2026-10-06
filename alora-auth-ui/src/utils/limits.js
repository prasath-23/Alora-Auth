// The API's length limits — its request models' validate tags — so a form stops
// where the API would refuse instead of sending a value to be turned away with
// "Invalid request". e2e/limits.spec.js holds every one equal to what the API
// actually enforces.
export const LIMITS = {
  groupName: 100,
  groupDescription: 500,
  apiClientName: 100,
  apiClientDescription: 500,
  companyName: 200,
  domain: 253,
  productKey: 40,
  productName: 200,
  productDescription: 1000,
  url: 2048,
  policyName: 100,
  ssoName: 100,
  ssoIssuer: 512,
  ssoClientID: 256,
  ssoClientSecret: 1024,
  ssoScopes: 256,
  email: 320,
  password: 512,
}

// Lists typed one entry per line: how many entries the API takes, and how long
// each may be. Past either, it refuses the whole list with a bare "Invalid
// request", so the form checks first and says which limit, in words.
export const LIST_LIMITS = {
  redirectURIs: { most: 20, each: LIMITS.url, one: 'redirect URI', many: 'redirect URIs' },
  roles: { most: 50, each: 64, one: 'role', many: 'roles' },
  domains: { most: 50, each: LIMITS.domain, one: 'domain', many: 'domains' },
}

const count = n => n.toLocaleString('en-US')

// listProblem is the limit a list breaks, in words, or null.
export function listProblem(entries, { most, each, one, many }) {
  if (entries.length > most) return `At most ${most} ${many}; this list has ${entries.length}.`
  const long = entries.find(e => e.length > each)
  if (long) return `A ${one} can be at most ${count(each)} characters; one has ${count(long.length)}.`
  return null
}

// A domain name as the API's fqdn rule reads one (RFC 1123): dot-separated
// labels of up to 63 letters, digits and hyphens, none starting with a hyphen,
// the last starting with a letter.
const FQDN = /^([a-zA-Z0-9][a-zA-Z0-9-]{0,62})(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,62})*?(\.[a-zA-Z][a-zA-Z0-9-]{0,62})\.?$/

const quoted = s => `“${s.length > 60 ? s.slice(0, 60) + '…' : s}”`

// domainProblem is why d is not a domain the API takes, in words, or null.
export function domainProblem(d) {
  if (d.length > LIMITS.domain) return `A domain can be at most ${LIMITS.domain} characters; one has ${count(d.length)}.`
  if (!FQDN.test(d)) return `${quoted(d)} is not a domain name, such as acme.com.`
  return null
}

// urlProblem is why u is not a URL the API takes, in words, or null: an
// absolute http(s) URL with a host, no user name and no fragment, its scheme in
// lower case, since the API reads the text as it will be stored. (In production
// the API also insists on https, and says so itself.) An issuer takes no query
// either.
export function urlProblem(label, u, { query = true } = {}) {
  const m = /^https?:\/\/([^/?#]*)/.exec(u)
  if (!m || !m[1]) return `${label} must be an absolute URL starting with https://, such as https://crm.acme.com; ${quoted(u)} is not.`
  if (m[1].includes('@')) return `${label} cannot carry a user name or password.`
  if (u.includes('#')) return `${label} cannot have a fragment (#…).`
  if (!query && u.includes('?')) return `${label} cannot have a query (?…).`
  return null
}

// A product key, as the API words its rule.
const PRODUCT_KEY = /^[A-Za-z0-9][A-Za-z0-9_-]{1,39}$/
export const keyProblem = k =>
  PRODUCT_KEY.test(k) ? null : "The key must be 2-40 letters, digits, '-' or '_', starting with a letter or digit."
