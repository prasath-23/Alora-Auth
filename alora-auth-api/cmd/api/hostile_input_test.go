package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/prasath-23/Alora-Auth/alora-auth-go/authpb"
	"google.golang.org/grpc/codes"
)

// Hostile input on every route. Whatever arrives — a malformed or oversized
// body, a value of the wrong type, text PostgreSQL cannot store, a strange id in
// the path or the query, a bad content type or credential — the answer is a
// client error in the standard shape: never a server error, and never the text
// of an internal one.

// hostileEnv raises every budget: a sweep sends thousands of requests from one
// address, and a 429 would hide what the handler behind it does.
var hostileEnv = map[string]string{
	"RATE_LIMIT_SCALE": "1000", "RATE_LIMIT_GLOBAL_MAX": "1000000", "RATE_LIMIT_AUTHORIZE_IP_MAX": "1000000",
}

// invalidUTF8 stands in for raw bytes that are not UTF-8: json.Marshal would
// repair them, so they are spliced into the encoded body afterwards.
const invalidUTF8 = "⁣INVALID-UTF8⁣"

// hostileText is every kind of text a field must survive: stored and returned
// verbatim when valid, refused with a 400 when PostgreSQL cannot store it or it
// is out of bounds — never a 500.
var hostileText = []struct{ name, value string }{
	{"NUL", "a\x00b"},
	{"invalid UTF-8", invalidUTF8},
	{"10,000 characters", strings.Repeat("x", 10000)},
	{"empty", ""},
	{"blank", "   "},
	{"right-to-left override", "‮evil.exe"},
	{"emoji", "😀👩‍👩‍👧‍👦"},
	{"zero-width space", "a​b"},
	{"control characters", "\x01\x02\x7f"},
	{"markup", "<script>alert(1)</script>"},
	{"SQL", "'; DROP TABLE users; --"},
	{"path traversal", "../../etc/passwd"},
	{"percent escapes", "%00%FF"},
	{"a URL", "https://evil.example/"},
	{"the replacement character", "�"},
}

// parserEdges are URLs a parser and a table's check read differently: url.Parse
// lower-cases the scheme and leaves the fragment of a lone "#" empty, while the
// value is stored, and checked, as given.
var parserEdges = []struct{ name, value string }{
	{"an upper-case scheme", "HTTPS://SWEEP.TEST/CB"},
	{"a lone #", "https://sweep.test/cb#"},
	{"a lone ?", "https://sweep.test/cb?"},
}

// letters is n random lower-case letters: text PostgreSQL cannot compress, as it
// compresses a repeated one to nothing.
func letters(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = 'a' + b[i]%26
	}
	return string(b)
}

// longValid are values a format check accepts — a domain, a URL, an address —
// that are longer than any index can hold: a format rule without a length limit
// lets them through to the database, where they are a server error.
var longValid = func() []struct{ name, value string } {
	labels := make([]string, 48)
	for i := range labels {
		labels[i] = letters(63)
	}
	domain := strings.Join(labels, ".") + ".test"
	return []struct{ name, value string }{
		{"3,000 random letters", letters(3000)},
		{"a well-formed domain of 3,000 characters", domain},
		{"a well-formed URL of 3,000 characters", "https://" + labels[0] + ".test/" + letters(3000)},
		{"a well-formed address of 3,000 characters", labels[0] + "@" + domain},
	}
}()

// hostilePath is every kind of id a path segment must survive. Each is written
// as it appears on the wire (percent-encoded).
var hostilePath = []string{
	noSuchID, "not-a-uuid", "a%00b", "%FF", "%C3%28", strings.Repeat("a", 3000),
	"%27%20OR%20%271%27%3D%271", "%E2%80%AE", "%F0%9F%98%80", "aci_" + noSuchID, "%20",
}

// hostileQuery is appended to every GET route.
var hostileQuery = []string{
	"search=a%00b", "search=%FF", "search=%27%3B%20DROP%20TABLE%20users%3B%20--", "search=" + strings.Repeat("s", 3000),
	"take=-1", "take=0", "take=99999999999999999999", "take=abc", "cursor=%00", "cursor=!!!", "cursor=%FF", "x=%00", "x=%FF",
}

// leakMarkers must never appear in an error: each would disclose the database,
// the code or the process behind the answer.
var leakMarkers = []string{"SQLSTATE", "pgx", "pgconn", "panic", "goroutine", "runtime error",
	"invalid byte sequence", ".go:", "stp_", "udf_", "tbl_", "vw_"}

// raw sends exactly the bytes and content type given.
func (a *app) raw(method, target, ctype string, body []byte, opts ...reqOpt) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for _, o := range opts {
		o(req)
	}
	w := httptest.NewRecorder()
	a.r.ServeHTTP(w, req)
	return w
}

// sweep collects what a hostile-input run found, route by route, so one broken
// rule reads as one finding rather than a thousand lines.
type sweep struct {
	t        *testing.T
	sent     int
	problems map[string][]string
}

func newSweep(t *testing.T) *sweep { return &sweep{t: t, problems: map[string][]string{}} }

func clip(s string) string {
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}

// check judges one answer to a hostile request on route ("METHOD /pattern").
func (s *sweep) check(route, what string, w *httptest.ResponseRecorder) {
	s.sent++
	fail := func(format string, args ...any) {
		s.problems[route] = append(s.problems[route], what+": "+fmt.Sprintf(format, args...))
	}
	gateway := strings.HasSuffix(route, "/sso-connections/:sid/test") && w.Code == http.StatusBadGateway
	if w.Code >= 500 && !gateway {
		fail("%d %s", w.Code, clip(w.Body.String()))
		return
	}
	if w.Code < 400 {
		return
	}
	body := w.Body.String()
	path := strings.SplitN(route, " ", 2)[1]
	if !strings.HasPrefix(path, "/docs") {
		for _, m := range leakMarkers {
			if strings.Contains(body, m) {
				fail("a %d answer discloses %q: %s", w.Code, m, clip(body))
			}
		}
	}
	isJSON := strings.Contains(w.Header().Get("Content-Type"), "application/json")
	switch {
	case strings.HasPrefix(path, "/api/"), strings.HasPrefix(path, "/auth/") && isJSON:
		var env struct {
			Error string `json:"error"`
			ReqID string `json:"reqId"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil || env.Error == "" || env.ReqID == "" {
			fail("a %d answer is not the error envelope: %s", w.Code, clip(body))
		}
	case path == "/oauth/token", path == "/oauth/revoke", path == "/oauth/introspect":
		var oe struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &oe); err != nil || oe.Error == "" {
			fail("a %d answer is not an OAuth error: %s", w.Code, clip(body))
		}
	}
}

func (s *sweep) report() {
	s.t.Helper()
	total := 0
	routes := make([]string, 0, len(s.problems))
	for r, ps := range s.problems {
		routes = append(routes, r)
		total += len(ps)
	}
	sort.Strings(routes)
	for _, r := range routes {
		ps := s.problems[r]
		shown := ps
		if len(shown) > 4 {
			shown = shown[:4]
		}
		s.t.Errorf("%s — %d bad answers, e.g.\n    %s", r, len(ps), strings.Join(shown, "\n    "))
	}
	if total > 0 {
		s.t.Errorf("%d bad answers on %d routes, out of %d hostile requests", total, len(routes), s.sent)
	} else {
		s.t.Logf("%d hostile requests, every answer a proper client error or success", s.sent)
	}
}

// sweepWorld is one company with one of everything, so a request can reach the
// deepest code its route has: someone to act on and their session, a group
// they are in, one the Admin manages, an invitation, a product the company
// subscribes to that accepts API clients, an API client with a secret, a login
// policy and an SSO connection.
type sweepWorld struct {
	co                         company
	admin, target              member
	as                         session
	sessionID                  string
	group, managed, invitation string
	product                    product
	client, secretID, secret   string
	policy, sso                string
}

func (a *app) newSweepWorld(owner session) sweepWorld {
	a.t.Helper()
	co := a.newCompany()
	admin, other, target := a.newAdmin(co), a.newAdmin(co), a.newMember(co, "")
	w := sweepWorld{co: co, admin: admin, target: target, as: a.login(admin)}
	a.login(target)
	var sessions []struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	decodeInto(a.t, a.get("/api/admin/sessions", bearer(w.as.Access)), &sessions)
	for _, s := range sessions {
		if s.Email == target.Email {
			w.sessionID = s.ID
		}
	}
	w.group = a.newGroup(co, "sessions:read")
	a.join(target, w.group)
	w.managed = a.newGroup(co)
	a.makeManager(w.managed, admin, other)
	a.join(target, w.managed)
	email, _ := a.invite(w.as, w.group)
	var invitations []struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	decodeInto(a.t, a.get("/api/admin/invitations", bearer(w.as.Access)), &invitations)
	for _, i := range invitations {
		if i.Email == email {
			w.invitation = i.ID
		}
	}
	w.product = a.newProduct("Viewer", "Editor")
	a.subscribe(co, w.product)
	a.acceptAPIClients(w.product, true)
	c := a.newAPIClient(w.as, "Sweep "+randSuffix(a.t))
	w.client = c.ID
	sec, code := a.newSecret(w.as, c.ID, nil)
	if code != http.StatusCreated {
		a.t.Fatalf("sweep secret: %d", code)
	}
	w.secretID, w.secret = sec.ID, sec.ClientSecret
	expect(a.t, a.send(http.MethodPut, "/api/admin/api-clients/"+c.ID+"/products",
		map[string]any{"product_ids": []string{w.product.ID}}, bearer(w.as.Access)), http.StatusOK, "sweep products")
	expect(a.t, a.send(http.MethodPut, "/api/admin/api-clients/"+c.ID+"/scopes",
		map[string]any{"scopes": []string{"api:read", "grpc:read"}}, bearer(w.as.Access)), http.StatusOK, "sweep scopes")
	res := a.ownerCall(owner, http.MethodPost, "/api/owner/companies/"+co.ID+"/login-policies", co.ID,
		map[string]any{"name": "Sweep " + randSuffix(a.t), "allow_password": true, "allow_google": false, "priority": 10})
	expect(a.t, res, http.StatusCreated, "sweep policy")
	w.policy = jsonField(res, "id")
	res = a.ownerCall(owner, http.MethodPost, "/api/owner/companies/"+co.ID+"/sso-connections", co.ID,
		map[string]any{"name": "Sweep " + randSuffix(a.t), "issuer": "https://sso.invalid", "client_id": "sweep-" + randSuffix(a.t),
			"client_secret": "s", "scopes": "openid email", "is_active": true})
	expect(a.t, res, http.StatusCreated, "sweep SSO connection")
	w.sso = jsonField(res, "id")
	for name, v := range map[string]string{"session": w.sessionID, "invitation": w.invitation, "policy": w.policy, "SSO": w.sso} {
		if v == "" {
			a.t.Fatalf("sweep world has no %s id", name)
		}
	}
	return w
}

// value is what a route parameter is in this world.
func (w sweepWorld) value(pattern, param string) string {
	switch param {
	case "cid":
		return w.co.ID
	case "uid", "userId":
		return w.target.ID
	case "iid":
		return w.invitation
	case "aid":
		return w.client
	case "gid":
		if strings.HasPrefix(pattern, "/api/me/managed-groups/") {
			return w.managed
		}
		return w.group
	case "pid":
		if strings.Contains(pattern, "/login-policies/") {
			return w.policy
		}
		return w.product.ID
	case "sid":
		if strings.Contains(pattern, "/sso-connections/") {
			return w.sso
		}
		return w.secretID
	case "any":
		return "index.html"
	case "id":
		switch {
		case strings.HasPrefix(pattern, "/api/admin/users/"):
			return w.target.ID
		case strings.HasPrefix(pattern, "/api/admin/groups/"):
			return w.group
		case strings.HasPrefix(pattern, "/api/admin/invitations/"):
			return w.invitation
		case strings.HasPrefix(pattern, "/api/admin/sessions/"):
			return w.sessionID
		case strings.HasPrefix(pattern, "/api/admin/api-clients/"):
			return w.client
		}
	}
	return noSuchID
}

// paramsOf lists a pattern's parameters, in order.
func paramsOf(pattern string) []string {
	var out []string
	for _, seg := range strings.Split(pattern, "/") {
		if strings.HasPrefix(seg, ":") || strings.HasPrefix(seg, "*") {
			out = append(out, seg[1:])
		}
	}
	return out
}

// fill writes a concrete path for pattern: every parameter from the world,
// except one — when override names it — taking the hostile value given.
func (w sweepWorld) fill(pattern, override, hostile string) string {
	segs := strings.Split(pattern, "/")
	for i, seg := range segs {
		if strings.HasPrefix(seg, ":") || strings.HasPrefix(seg, "*") {
			name := seg[1:]
			if name == override {
				segs[i] = hostile
			} else {
				segs[i] = url.PathEscape(w.value(pattern, name))
			}
		}
	}
	return strings.Join(segs, "/")
}

// callerFor is who sends a route's requests: the strongest caller it admits,
// so a request gets as deep as the route goes. target is the company an Owner
// write must name in its header.
func (w sweepWorld) callerFor(pattern string, owner session, target string) []reqOpt {
	switch {
	case strings.HasPrefix(pattern, "/api/owner/companies/:cid"):
		return []reqOpt{bearer(owner.Access), header("X-Alora-Target-Company", target)}
	case strings.HasPrefix(pattern, "/api/owner/"):
		return []reqOpt{bearer(owner.Access)}
	case strings.HasPrefix(pattern, "/api/"):
		return []reqOpt{bearer(w.as.Access)}
	}
	return nil
}

// template is a well-formed body for the route in this world, or nil for a
// route that takes none. Its values are what the hostile variants replace.
func (w sweepWorld) template(route string) map[string]any {
	email := "sweep-" + randSuffixN(8) + "@acme.test"
	grants := []any{map[string]any{"product_id": w.product.ID, "role_name": "Viewer"}}
	product := map[string]any{"name": "Sweep", "description": "d", "base_url": "https://sweep.test/",
		"initiate_login_uri": "https://sweep.test/login", "is_active": true}
	sso := map[string]any{"name": "Sweep " + randSuffixN(6), "issuer": "https://sso.invalid", "client_id": "sweep-" + randSuffixN(8),
		"client_secret": "s", "scopes": "openid email", "is_active": true}
	switch route {
	case "POST /auth/login/password":
		return map[string]any{"email": w.target.Email, "password": "not the password", "return_to": "/"}
	case "POST /auth/login/discover":
		return map[string]any{"email": w.target.Email}
	case "POST /auth/login/choose":
		return map[string]any{"client_id": w.co.ID}
	case "POST /auth/accept-invitation":
		return map[string]any{"token": "t000000000000000000000", "password": "a long enough password"}
	case "POST /auth/accept-invitation/federated":
		return map[string]any{"token": "t000000000000000000000"}
	case "POST /auth/reset-password":
		return map[string]any{"token": "t000000000000000000000", "new_password": "a long enough password"}
	case "POST /api/me/change-password":
		return map[string]any{"current_password": "not the password", "new_password": "a long enough password"}
	case "POST /api/me/managed-groups/:gid/members", "POST /api/admin/groups/:id/members", "POST /api/admin/groups/:id/managers",
		"POST /api/owner/companies/:cid/groups/:gid/members", "POST /api/owner/companies/:cid/groups/:gid/managers":
		return map[string]any{"email": w.target.Email}
	case "PATCH /api/admin/users/:id", "PATCH /api/owner/companies/:cid/users/:uid":
		return map[string]any{"is_active": true}
	case "PUT /api/admin/users/:id/scopes", "PUT /api/admin/groups/:id/scopes", "PUT /api/owner/companies/:cid/users/:uid/scopes",
		"PUT /api/owner/companies/:cid/groups/:gid/scopes":
		return map[string]any{"scopes": []any{"sessions:read"}}
	case "POST /api/admin/invitations", "POST /api/owner/companies/:cid/invitations":
		return map[string]any{"email": email, "group_ids": []any{w.group}}
	case "POST /api/admin/groups":
		return map[string]any{"name": "Sweep " + randSuffixN(6), "description": "d", "scopes": []any{"sessions:read"}}
	case "POST /api/owner/companies/:cid/groups":
		return map[string]any{"name": "Sweep " + randSuffixN(6), "description": "d", "scopes": []any{}, "product_grants": grants}
	case "PATCH /api/admin/groups/:id", "PATCH /api/owner/companies/:cid/groups/:gid":
		return map[string]any{"name": "Sweep " + randSuffixN(6), "description": "d"}
	case "PATCH /api/admin/client":
		return map[string]any{"name": "Sweep Co"}
	case "POST /api/admin/api-clients", "POST /api/owner/companies/:cid/api-clients":
		return map[string]any{"name": "Sweep " + randSuffixN(6), "description": "d"}
	case "PATCH /api/admin/api-clients/:id", "PATCH /api/owner/companies/:cid/api-clients/:aid":
		return map[string]any{"name": "Sweep " + randSuffixN(6), "description": "d", "is_active": true}
	case "PUT /api/admin/api-clients/:id/scopes", "PUT /api/owner/companies/:cid/api-clients/:aid/scopes":
		return map[string]any{"scopes": []any{"api:read"}}
	case "PUT /api/admin/api-clients/:id/products", "PUT /api/owner/companies/:cid/api-clients/:aid/products":
		return map[string]any{"product_ids": []any{w.product.ID}}
	case "POST /api/admin/api-clients/:id/secrets", "POST /api/owner/companies/:cid/api-clients/:aid/secrets":
		return map[string]any{"expires_in_days": 30}
	case "POST /api/owner/companies":
		return map[string]any{"name": "Sweep " + randSuffixN(6), "domain": "", "subscription_status": "ACTIVE", "is_active": true}
	case "PATCH /api/owner/companies/:cid":
		return map[string]any{"name": "Sweep Co", "subscription_status": "ACTIVE", "max_seats": 10}
	case "PUT /api/owner/companies/:cid/domain":
		return map[string]any{"domain": "sweep-" + randSuffixN(6) + ".test", "verified": false}
	case "PUT /api/owner/companies/:cid/subscriptions/:pid":
		return map[string]any{"is_active": true, "seat_limit": 5}
	case "PUT /api/owner/companies/:cid/users/:uid/login-policy", "PUT /api/owner/companies/:cid/groups/:gid/login-policy":
		return map[string]any{"policy_id": w.policy}
	case "PUT /api/owner/companies/:cid/users/:uid/grants/:pid":
		return map[string]any{"role_name": "Viewer"}
	case "PUT /api/owner/companies/:cid/groups/:gid/product-grants":
		return map[string]any{"product_grants": grants}
	case "POST /api/owner/companies/:cid/login-policies":
		return map[string]any{"name": "Sweep " + randSuffixN(6), "allow_password": true, "allow_google": false, "priority": 20}
	case "PATCH /api/owner/companies/:cid/login-policies/:pid":
		return map[string]any{"name": "Sweep " + randSuffixN(6), "allow_password": true, "allow_google": true, "priority": 30}
	case "POST /api/owner/companies/:cid/sso-connections":
		return sso
	case "PATCH /api/owner/companies/:cid/sso-connections/:sid":
		return sso
	case "PUT /api/owner/companies/:cid/sso-connections/:sid/domains":
		return map[string]any{"domains": []any{"sweep-" + randSuffixN(6) + ".test"}}
	case "POST /api/owner/products":
		p := map[string]any{"key": "SW" + strings.ToUpper(randSuffixN(6)), "accepts_api_clients": false}
		for k, v := range product {
			p[k] = v
		}
		return p
	case "PATCH /api/owner/products/:pid":
		return product
	case "PUT /api/owner/products/:pid/redirect-uris":
		return map[string]any{"redirect_uris": []any{"https://sweep.test/callback"}}
	case "PUT /api/owner/products/:pid/roles":
		return map[string]any{"roles": []any{"Viewer", "Editor"}}
	}
	return nil
}

// randSuffixN is a short random hex suffix that needs no *testing.T.
func randSuffixN(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)[:n]
}

// encode marshals a body, splicing in raw bytes that are not UTF-8 wherever the
// invalidUTF8 placeholder stands.
func encode(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return bytes.ReplaceAll(b, []byte(invalidUTF8), []byte("\xff\xfe"))
}

// hostileBody is one malformed or hostile request body.
type hostileBody struct {
	name, ctype string
	body        []byte
}

// genericBodies are the malformed bodies every route that reads one must
// refuse cleanly, whatever it expects.
func genericBodies(template map[string]any) []hostileBody {
	const js = "application/json"
	out := []hostileBody{
		{"no body", "", nil},
		{"an empty JSON body", js, []byte{}},
		{"null", js, []byte("null")},
		{"an array", js, []byte("[]")},
		{"a string", js, []byte(`"s"`)},
		{"a number", js, []byte("123")},
		{"truncated JSON", js, []byte("{")},
		{"two JSON values", js, []byte(`{}{"a":1}`)},
		{"an unknown field", js, []byte(`{"is_global_admin":true}`)},
		{"a NUL in a key", js, []byte(`{"na\u0000me":"x"}`)},
		{"nesting 20,000 deep", js, bytes.Repeat([]byte("["), 20000)},
		{"70 KB", js, append(append([]byte(`{"name":"`), bytes.Repeat([]byte("x"), 70000)...), []byte(`"}`)...)},
		{"a byte-order mark", js, []byte("\xef\xbb\xbf{}")},
		{"raw bytes that are not UTF-8", js, []byte("{\"name\":\"\xff\xfe\"}")},
	}
	if template != nil {
		t := encode(template)
		out = append(out,
			hostileBody{"text/plain", "text/plain", t},
			hostileBody{"a form content type", "application/x-www-form-urlencoded", t},
			hostileBody{"multipart", "multipart/form-data; boundary=x", t},
			hostileBody{"UTF-16 charset", "application/json; charset=utf-16", t},
			hostileBody{"a malformed content type", ";;;", t},
			hostileBody{"the template itself", js, t},
		)
		all := map[string]any{}
		for k, v := range template {
			if _, ok := v.(string); ok {
				all[k] = "a\x00b"
			} else {
				all[k] = v
			}
		}
		out = append(out, hostileBody{"NUL in every string", js, encode(all)})
	}
	return out
}

// fieldVariants replaces each field of the template in turn by values it must
// never be.
func fieldVariants(template map[string]any) []hostileBody {
	var out []hostileBody
	keys := make([]string, 0, len(template))
	for k := range template {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	with := func(key string, v any) []byte {
		m := map[string]any{}
		for k, x := range template {
			m[k] = x
		}
		m[key] = v
		return encode(m)
	}
	many := make([]any, 5000)
	for i := range many {
		many[i] = "x"
	}
	for _, k := range keys {
		add := func(name string, v any) {
			out = append(out, hostileBody{k + " = " + name, "application/json", with(k, v)})
		}
		switch template[k].(type) {
		case string:
			for _, h := range hostileText {
				add(h.name, h.value)
			}
			for _, h := range slices.Concat(longValid, parserEdges) {
				add(h.name, h.value)
			}
		case []any:
			for _, h := range slices.Concat(longValid, parserEdges) {
				add("an element: "+h.name, []any{h.value})
			}
			add("a NUL element", []any{"a\x00b"})
			add("an element that is not UTF-8", []any{invalidUTF8})
			add("5,000 elements", many)
			add("a number element", []any{123})
			add("a null element", []any{nil})
			add("a nested list", []any{[]any{}})
			add("an object element", []any{map[string]any{"x": "a\x00b"}})
			add("a string", "not a list")
		case bool:
			add("a string", "true")
			add("a number", 1)
		case int, float64:
			for _, n := range []any{1e308, -1, 0, 2147483648, int64(9223372036854775807), 0.5, "10"} {
				add(fmt.Sprintf("%v", n), n)
			}
		}
		add("null", nil)
		add("an object", map[string]any{"a": "b"})
		add("a number", 12.5)
	}
	return out
}

// Every route, every way: hostile ids in the path, hostile queries, hostile
// bodies and content types — each answered as a client error, or a success,
// but never with a server error or a leak.
func TestNoRouteAnswersHostileInputWithAServerError(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	owner := a.login(a.newOwner())
	s := newSweep(t)

	routes := a.r.Routes()
	sort.Slice(routes, func(i, j int) bool { return routes[i].Path+routes[i].Method < routes[j].Path+routes[j].Method })
	for _, r := range routes {
		route := r.Method + " " + r.Path
		w := a.newSweepWorld(owner)
		base := w.fill(r.Path, "", "")
		opts := w.callerFor(r.Path, owner, w.co.ID)
		template := w.template(route)

		// Anonymous, with junk: refused before anything is read.
		s.check(route, "anonymous", a.raw(r.Method, base, "application/json", []byte(`{"x":"a\u0000b"}`)))

		// Every parameter, every hostile value.
		for _, p := range paramsOf(r.Path) {
			for _, h := range hostilePath {
				target := w.co.ID
				if p == "cid" {
					target, _ = url.PathUnescape(h)
				}
				var body []byte
				ctype := ""
				if template != nil {
					body, ctype = encode(template), "application/json"
				}
				s.check(route, fmt.Sprintf(":%s = %q", p, clip(h)),
					a.raw(r.Method, w.fill(r.Path, p, h), ctype, body, w.callerFor(r.Path, owner, target)...))
			}
		}

		// Every hostile query.
		if r.Method == http.MethodGet {
			for _, q := range hostileQuery {
				s.check(route, "?"+clip(q), a.raw(r.Method, base+"?"+q, "", nil, opts...))
			}
		}

		// Every hostile body. Routes that take none must ignore one safely.
		if r.Method != http.MethodGet {
			for _, b := range genericBodies(template) {
				s.check(route, b.name, a.raw(r.Method, base, b.ctype, b.body, opts...))
			}
			if template != nil {
				for _, b := range fieldVariants(template) {
					s.check(route, b.name, a.raw(r.Method, base, b.ctype, b.body, opts...))
				}
			}
		}
	}
	s.report()
}

// The server-to-server OAuth endpoints read a form and HTTP Basic credentials,
// not JSON: every hostile form and credential is an OAuth error, never a
// server error.
func TestTheOAuthEndpointsAnswerHostileFormsWithOAuthErrors(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	owner := a.login(a.newOwner())
	w := a.newSweepWorld(owner)
	s := newSweep(t)

	formValues := []struct{ name, value string }{}
	for _, h := range hostileText {
		v := h.value
		if v == invalidUTF8 {
			v = "\xff\xfe"
		}
		formValues = append(formValues, struct{ name, value string }{h.name, v})
	}
	fields := map[string][]string{
		"/oauth/token":      {"grant_type", "code", "redirect_uri", "code_verifier", "refresh_token", "resource", "scope"},
		"/oauth/revoke":     {"token", "token_type_hint"},
		"/oauth/introspect": {"token", "token_type_hint"},
	}
	credentials := []struct{ name, id, secret string }{
		{"a product", w.product.ID, w.product.Secret},
		{"an API client", w.client, w.secret},
	}
	grants := []string{"authorization_code", "refresh_token", "client_credentials", "password", ""}
	for path, names := range fields {
		route := "POST " + path
		for _, c := range credentials {
			for _, g := range grants {
				for _, f := range names {
					for _, v := range formValues {
						form := url.Values{f: {v.value}}
						if path == "/oauth/token" && f != "grant_type" {
							form.Set("grant_type", g)
						}
						if path == "/oauth/token" && g == "client_credentials" && f != "resource" {
							form.Set("resource", "product:"+w.product.Key)
						}
						s.check(route, fmt.Sprintf("%s, %s grant, %s = %s", c.name, g, f, v.name),
							a.raw(http.MethodPost, path, "application/x-www-form-urlencoded", []byte(form.Encode()), basic(c.id, c.secret)))
					}
				}
				if path != "/oauth/token" {
					break
				}
			}
		}
		// Hostile credentials.
		auths := []struct{ name, header string }{
			{"none", ""},
			{"not Basic", "Bearer x"},
			{"not base64", "Basic !!!"},
			{"no colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon"))},
			{"an empty id", "Basic " + base64.StdEncoding.EncodeToString([]byte(":secret"))},
			{"a NUL in the id", "Basic " + base64.StdEncoding.EncodeToString([]byte("a\x00b:secret"))},
			{"a NUL in the secret", "Basic " + base64.StdEncoding.EncodeToString([]byte(w.client+":a\x00b"))},
			{"an id that is not UTF-8", "Basic " + base64.StdEncoding.EncodeToString([]byte("\xff\xfe:secret"))},
			{"a percent-encoded NUL", "Basic " + base64.StdEncoding.EncodeToString([]byte("a%00b:secret"))},
			{"a broken percent escape", "Basic " + base64.StdEncoding.EncodeToString([]byte("a%zzb:secret"))},
			{"a 20 KB id", "Basic " + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("i", 20000)+":s"))},
		}
		for _, h := range auths {
			var opts []reqOpt
			if h.header != "" {
				opts = append(opts, header("Authorization", h.header))
			}
			form := url.Values{"grant_type": {"client_credentials"}, "resource": {"product:" + w.product.Key}, "token": {"x"}}
			s.check(route, "credentials: "+h.name,
				a.raw(http.MethodPost, path, "application/x-www-form-urlencoded", []byte(form.Encode()), opts...))
		}
		// Hostile bodies.
		for _, b := range []hostileBody{
			{"JSON", "application/json", []byte(`{"grant_type":"client_credentials"}`)},
			{"no content type", "", []byte("grant_type=client_credentials")},
			{"a repeated parameter", "application/x-www-form-urlencoded", []byte("grant_type=a&grant_type=b")},
			{"a broken escape", "application/x-www-form-urlencoded", []byte("grant_type=%zz")},
			{"70 KB", "application/x-www-form-urlencoded", append([]byte("grant_type="), bytes.Repeat([]byte("x"), 70000)...)},
			{"raw bytes that are not UTF-8", "application/x-www-form-urlencoded", []byte("grant_type=\xff\xfe")},
		} {
			s.check(route, "body: "+b.name, a.raw(http.MethodPost, path, b.ctype, b.body, basic(w.client, w.secret)))
		}
	}

	// The browser door, signed in and not.
	ts := a.login(w.target)
	for _, k := range []string{"client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "prompt"} {
		for _, v := range formValues {
			q := url.Values{"client_id": {w.product.ID}, "redirect_uri": {w.product.Redirect}, "response_type": {"code"},
				"scope": {"openid"}, "state": {"s"}, "nonce": {"n"}, "code_challenge": {strings.Repeat("c", 43)},
				"code_challenge_method": {"S256"}}
			q.Set(k, v.value)
			for _, signedIn := range []bool{false, true} {
				var opts []reqOpt
				if signedIn {
					opts = append(opts, withCookie(ts.Cookie))
				}
				s.check("GET /oauth/authorize", fmt.Sprintf("%s = %s, signed in %v", k, v.name, signedIn),
					a.raw(http.MethodGet, "/oauth/authorize?"+q.Encode(), "", nil, opts...))
			}
		}
	}
	s.report()
}

// The gRPC door takes the same hostile values as the HTTP one: refused as a
// client error, never Internal.
func TestTheGRPCTokenServiceAnswersHostileRequestsWithClientErrors(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	app := a.newApplication(1, "grpc:read")
	client := authpb.NewTokenServiceClient(a.grpcConn())
	var bad []string
	try := func(what string, id, secret string, req *authpb.GetTokenRequest) {
		_, err := client.GetToken(asClient(t, id, secret), req)
		if err == nil {
			return
		}
		if code, _ := refusal(err); code == codes.Internal || code == codes.Unknown || code == codes.DataLoss {
			bad = append(bad, fmt.Sprintf("%s: %v", what, err))
		}
	}
	for _, h := range hostileText {
		if h.value == invalidUTF8 {
			continue // protobuf itself refuses to send a string that is not UTF-8
		}
		try("resource = "+h.name, app.id, app.secret, &authpb.GetTokenRequest{Resource: h.value})
		try("resource = product: + "+h.name, app.id, app.secret, &authpb.GetTokenRequest{Resource: "product:" + h.value})
		try("a scope = "+h.name, app.id, app.secret, &authpb.GetTokenRequest{Resource: "product:" + app.products[0].Key, Scopes: []string{h.value}})
		try("client id = "+h.name, h.value, app.secret, &authpb.GetTokenRequest{Resource: "product:" + app.products[0].Key})
		try("secret = "+h.name, app.id, h.value, &authpb.GetTokenRequest{Resource: "product:" + app.products[0].Key})
	}
	for _, b := range bad {
		t.Error(b)
	}
}

// Text the database cannot store — a NUL character, bytes that are not UTF-8 —
// is refused at every edge it can arrive through, with the answer that edge
// gives any malformed request. Valid text, however unusual, is kept exactly.
// A browser's identity is untrusted text that is stored, with the session and
// in the audit trail. Its header may carry bytes that are not UTF-8 (HTTP allows
// them), and cutting a long one to its limit must not split a character. It is
// display-only, so whatever it is, signing in works and what is kept is text.
func TestAnyBrowserIdentitySignsIn(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	co := a.newCompany()
	m := a.newMember(co, "")
	for name, ua := range map[string]string{
		"bytes that are not UTF-8":     "Mozilla/5.0 \xff\xfe",
		"a lone continuation byte":     "Chrome \x80",
		"a character cut by the limit": strings.Repeat("a", 511) + "é",
		"a NUL":                        "Chrome\x00",
		"far past the limit":           strings.Repeat("Mozilla/5.0 😀 ", 400),
	} {
		w := a.post("/auth/login/password", map[string]any{"email": m.Email, "password": m.Password}, header("User-Agent", ua))
		if w.Code != http.StatusOK {
			t.Errorf("%s: signing in answered %d %s", name, w.Code, clip(w.Body.String()))
		}
	}
	if n := a.count(`SELECT count(*) FROM tbl_user_sessions WHERE user_id = $1`, m.ID); n != 5 {
		t.Errorf("%d sessions, want one per sign-in", n)
	}
	if n := a.count(`SELECT count(*) FROM tbl_user_sessions WHERE user_id = $1 AND octet_length(user_agent) > 512`, m.ID); n != 0 {
		t.Errorf("%d sessions keep more than 512 bytes of a browser's identity", n)
	}
}

func TestTextTheDatabaseCannotStoreIsRefusedAtEveryEdge(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	groups := func() int { return a.count(`SELECT count(*) FROM tbl_groups WHERE client_id = $1`, co.ID) }
	before := groups()

	for name, w := range map[string]*httptest.ResponseRecorder{
		"a NUL in a JSON string":        a.raw(http.MethodPost, "/api/admin/groups", "application/json", []byte(`{"name":"a\u0000b"}`), bearer(s.Access)),
		"a NUL in a JSON list":          a.raw(http.MethodPost, "/api/admin/groups", "application/json", []byte(`{"name":"ok","scopes":["a\u0000"]}`), bearer(s.Access)),
		"a JSON body that is not UTF-8": a.raw(http.MethodPost, "/api/admin/groups", "application/json", []byte("{\"name\":\"\xff\xfe\"}"), bearer(s.Access)),
		"a NUL in the path":             a.get("/api/admin/users/a%00b", bearer(s.Access)),
		"a path that is not UTF-8":      a.get("/api/admin/users/%FF", bearer(s.Access)),
		"a NUL in the query":            a.get("/api/admin/users?search=a%00b", bearer(s.Access)),
		"a query that is not UTF-8":     a.get("/api/admin/users?search=%C3%28", bearer(s.Access)),
		"a NUL in an unused parameter":  a.get("/api/admin/users?x=%00", bearer(s.Access)),
		"a NUL in a public query":       a.get("/auth/accept-invitation/lookup?token=aaaaaaaaaa%00bbbb"),
		"a NUL in the Owner's path":     a.get("/api/owner/companies/a%00b"),
	} {
		if w.Code != http.StatusBadRequest || jsonField(w, "error") != "Invalid request" {
			t.Errorf("%s: %d %s, want 400 Invalid request", name, w.Code, w.Body.String())
		}
	}
	if n := groups(); n != before {
		t.Errorf("a refused body still created %d groups", n-before)
	}

	// The OAuth endpoints answer in their own words.
	app := a.newApplication(1, "api:read")
	key := app.products[0].Key
	if w := a.raw(http.MethodPost, "/oauth/token", "application/x-www-form-urlencoded",
		[]byte("grant_type=client_credentials&resource=product:"+key+"%00"), basic(app.id, app.secret)); w.Code != http.StatusBadRequest || oauthError(t, w) != "invalid_request" {
		t.Errorf("a NUL in a form value: %d %s, want 400 invalid_request", w.Code, w.Body.String())
	}
	for name, h := range map[string]string{
		"a NUL in the client id":        base64.StdEncoding.EncodeToString([]byte("a\x00b:" + app.secret)),
		"a client id that is not UTF-8": base64.StdEncoding.EncodeToString([]byte("\xff:" + app.secret)),
		"a percent-encoded NUL":         base64.StdEncoding.EncodeToString([]byte(app.id + "%00:" + app.secret)),
	} {
		w := a.raw(http.MethodPost, "/oauth/token", "application/x-www-form-urlencoded",
			[]byte("grant_type=client_credentials&resource=product:"+key), header("Authorization", "Basic "+h))
		if w.Code != http.StatusUnauthorized || oauthError(t, w) != "invalid_client" {
			t.Errorf("%s: %d %s, want 401 invalid_client", name, w.Code, w.Body.String())
		}
	}
	client := authpb.NewTokenServiceClient(a.grpcConn())
	if _, err := client.GetToken(asClient(t, app.id, app.secret), &authpb.GetTokenRequest{Resource: "product:" + key + "\x00"}); err == nil {
		t.Error("gRPC: a NUL in the resource earned a token")
	} else if code, reason := refusal(err); code != codes.InvalidArgument || reason != "invalid_request" {
		t.Errorf("gRPC: a NUL in the resource: %v %q, want InvalidArgument invalid_request", code, reason)
	}
	if _, err := client.GetToken(asClient(t, "a\x00b", app.secret), &authpb.GetTokenRequest{Resource: "product:" + key}); err == nil {
		t.Error("gRPC: a NUL in the client id earned a token")
	} else if code, reason := refusal(err); code != codes.Unauthenticated || reason != "invalid_client" {
		t.Errorf("gRPC: a NUL in the client id: %v %q, want Unauthenticated invalid_client", code, reason)
	}

	// Valid text, however unusual, is kept exactly as sent.
	for _, name := range []string{"😀 Field sales 👩‍👩‍👧‍👦", "\u202Eright-to-left", "zero\u200bwidth", "<script>alert(1)</script>", "'; DROP TABLE users; --", "Ünïcødé ñame"} {
		w := a.post("/api/admin/groups", map[string]any{"name": name}, bearer(s.Access))
		expect(t, w, http.StatusCreated, "create "+name)
		got := a.get("/api/admin/groups/"+jsonField(w, "id"), bearer(s.Access))
		if jsonField(got, "name") != name {
			t.Errorf("stored %q, read back %q", name, jsonField(got, "name"))
		}
	}
}

// A name is what a thing is known by in every list and every log. Whitespace
// alone — spaces, a tab, a newline, a no-break space — trims to nothing, so it
// is refused like no name at all, on every route that names something, and
// nothing nameless is stored.
func TestNoNameIsBlank(t *testing.T) {
	a := newAppWith(t, hostileEnv, nil)
	co := a.newCompany()
	s := a.login(a.newAdmin(co))
	own := a.login(a.newOwner())
	g := a.newGroup(co)
	c := a.newAPIClient(s, "Named "+randSuffix(t))
	p := a.newProduct()
	pol := a.newPolicy(own, co, "Named "+randSuffix(t), true, false, 71)
	cbase := "/api/owner/companies/" + co.ID
	w := a.ownerCall(own, http.MethodPost, cbase+"/sso-connections", co.ID, map[string]any{
		"name": "Named " + randSuffix(t), "issuer": "https://sso.invalid", "client_id": "b-" + randSuffix(t),
		"client_secret": "s", "is_active": true,
	})
	expect(t, w, http.StatusCreated, "SSO connection")
	sid := jsonField(w, "id")
	auth := bearer(s.Access)
	for _, blank := range []string{" ", "   ", "\t", "\n", " ", " \t\r\n "} {
		for what, w := range map[string]*httptest.ResponseRecorder{
			"a new group":           a.post("/api/admin/groups", map[string]any{"name": blank}, auth),
			"a group renamed":       a.send(http.MethodPatch, "/api/admin/groups/"+g, map[string]any{"name": blank, "description": ""}, auth),
			"a new API client":      a.post("/api/admin/api-clients", map[string]any{"name": blank}, auth),
			"an API client renamed": a.send(http.MethodPatch, "/api/admin/api-clients/"+c.ID, map[string]any{"name": blank, "description": "", "is_active": true}, auth),
			"the company renamed":   a.send(http.MethodPatch, "/api/admin/client", map[string]any{"name": blank}, auth),
			"a new company":         a.ownerCall(own, http.MethodPost, "/api/owner/companies", "", map[string]any{"name": blank}),
			"a company renamed":     a.ownerCall(own, http.MethodPatch, cbase, co.ID, map[string]any{"name": blank}),
			"a new product": a.ownerCall(own, http.MethodPost, "/api/owner/products", "", map[string]any{
				"key": "B" + randSuffix(t), "name": blank}),
			"a product renamed": a.ownerCall(own, http.MethodPatch, "/api/owner/products/"+p.ID, "", map[string]any{
				"name": blank, "is_active": true}),
			"a new policy": a.ownerCall(own, http.MethodPost, cbase+"/login-policies", co.ID, map[string]any{
				"name": blank, "allow_password": true, "allow_google": false, "priority": 72}),
			"a policy renamed": a.ownerCall(own, http.MethodPatch, cbase+"/login-policies/"+pol, co.ID, map[string]any{
				"name": blank, "allow_password": true, "allow_google": false, "priority": 71}),
			"a new SSO connection": a.ownerCall(own, http.MethodPost, cbase+"/sso-connections", co.ID, map[string]any{
				"name": blank, "issuer": "https://sso.invalid", "client_id": "b-" + randSuffix(t), "client_secret": "s", "is_active": true}),
			"an SSO connection renamed": a.ownerCall(own, http.MethodPatch, cbase+"/sso-connections/"+sid, co.ID, map[string]any{
				"name": blank, "issuer": "https://sso.invalid", "client_id": "b-" + randSuffix(t), "is_active": true}),
		} {
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s named %q: %d %s, want 400", what, blank, w.Code, clip(w.Body.String()))
			}
		}
	}
	for _, table := range []string{"tbl_groups", "tbl_api_clients", "tbl_clients", "tbl_products", "tbl_login_policies", "tbl_sso_connections"} {
		if n := a.count(`SELECT count(*) FROM ` + table + ` WHERE name ~ '^[\s ]*$'`); n != 0 {
			t.Errorf("%d rows of %s have no name", n, table)
		}
	}
}
