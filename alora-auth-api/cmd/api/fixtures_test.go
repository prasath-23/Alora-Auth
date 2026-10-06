package main

// Fixtures. Everything is seeded through the table services on the schema
// owner's connection, so a company is created exactly as production creates
// one — with its Admins group and default login policy — and a product is
// registered the way the Owner console registers it.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/core/shared/crypto/password"
	"github.com/alora/auth/internal/core/shared/crypto/pkce"
	"github.com/alora/auth/internal/core/shared/crypto/tokens"
	dbmodels "github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/services/clientproducts"
	"github.com/alora/auth/internal/database/services/clients"
	"github.com/alora/auth/internal/database/services/groups"
	"github.com/alora/auth/internal/database/services/productpermissions"
	"github.com/alora/auth/internal/database/services/products"
	"github.com/alora/auth/internal/database/services/usergroups"
	"github.com/alora/auth/internal/database/services/users"
)

type company struct {
	ID       string
	Name     string
	AdminsID string // the Admins group
}

type member struct {
	ID       string
	ClientID string
	Email    string
	Password string
}

type product struct {
	ID       string
	Key      string
	Secret   string
	Redirect string
	Initiate string
	Base     string
}

var hashCache = map[string]string{}

func hashOf(t *testing.T, pw string) string {
	t.Helper()
	if h, ok := hashCache[pw]; ok {
		return h
	}
	h, err := password.Hash(pw)
	if err != nil {
		t.Fatal(err)
	}
	hashCache[pw] = h
	return h
}

// newCompany creates an active company, with its Admins group and default
// policy, through stp_CreateClient.
func (a *app) newCompany(domain ...string) company {
	a.t.Helper()
	ctx := context.Background()
	name := "Acme " + randSuffix(a.t)
	c, err := clients.NewClientDbService(a.owner).Create(ctx, clients.NewClient{
		Name: name, SubscriptionStatus: dbmodels.SubscriptionActive, IsActive: true,
	})
	if err != nil {
		a.t.Fatalf("seed company: %v", err)
	}
	if len(domain) > 0 {
		d := domain[0]
		if _, err := clients.NewClientDbService(a.owner).SetDomain(ctx, c.ID, &d, true); err != nil {
			a.t.Fatalf("seed domain: %v", err)
		}
	}
	admins, err := groups.NewGroupDbService(a.owner).SystemGroupID(ctx, c.ID, dbmodels.SystemGroupAdmins)
	if err != nil {
		a.t.Fatalf("admins group: %v", err)
	}
	return company{ID: c.ID, Name: name, AdminsID: admins}
}

// newMember creates a live password account (EMAIL) in the company. An empty
// email gets a unique one.
func (a *app) newMember(co company, email string) member {
	a.t.Helper()
	if email == "" {
		email = "user-" + randSuffix(a.t) + "@acme.test"
	}
	hash := hashOf(a.t, testPassword)
	u, err := users.NewUserDbService(a.owner).Create(context.Background(), co.ID, strings.ToLower(email), &hash, dbmodels.AccountTypeEmail)
	if err != nil {
		a.t.Fatalf("seed user: %v", err)
	}
	return member{ID: u.ID, ClientID: co.ID, Email: u.Email, Password: testPassword}
}

// newPasswordless creates a live OAUTH_ONLY account.
func (a *app) newPasswordless(co company, email string) member {
	a.t.Helper()
	u, err := users.NewUserDbService(a.owner).Create(context.Background(), co.ID, strings.ToLower(email), nil, dbmodels.AccountTypeOAuthOnly)
	if err != nil {
		a.t.Fatalf("seed user: %v", err)
	}
	return member{ID: u.ID, ClientID: co.ID, Email: u.Email}
}

// newAdmin creates a member of the company's Admins group.
func (a *app) newAdmin(co company) member {
	a.t.Helper()
	m := a.newMember(co, "")
	a.join(m, co.AdminsID)
	return m
}

func (a *app) join(m member, groupID string) {
	a.t.Helper()
	if err := usergroups.NewUserGroupDbService(a.owner).Add(context.Background(), m.ID, groupID, m.ClientID, ""); err != nil {
		a.t.Fatalf("join group: %v", err)
	}
}

// newGroup creates a group in the company giving the App Central scopes named
// (an edit scope brings its read scope, as the API does).
func (a *app) newGroup(co company, scopes ...string) string {
	a.t.Helper()
	ctx := context.Background()
	g, err := groups.NewGroupDbService(a.owner).Create(ctx, co.ID, "Group "+randSuffix(a.t), "")
	if err != nil {
		a.t.Fatalf("seed group: %v", err)
	}
	if len(scopes) > 0 {
		full, err := shared.NormalizeScopes(scopes)
		if err != nil {
			a.t.Fatalf("seed group: %v", err)
		}
		a.exec(`SELECT stp_SetGroupScopes($1, $2, $3)`, g.ID, co.ID, full)
	}
	return g.ID
}

// giveExtras gives a person extra App Central scopes directly, as the Owner
// would (normalized the same way).
func (a *app) giveExtras(m member, scopes ...string) {
	a.t.Helper()
	full, err := shared.NormalizeScopes(scopes)
	if err != nil {
		a.t.Fatalf("give extras: %v", err)
	}
	a.exec(`SELECT stp_SetUserScopes($1, $2, $3, NULL, NULL)`, m.ID, m.ClientID, full)
}

// newProduct registers an active product with a secret, a redirect URI, an
// initiate-login URI and a role catalogue.
func (a *app) newProduct(roles ...string) product {
	a.t.Helper()
	if len(roles) == 0 {
		roles = []string{"Admin", "Editor", "Viewer"}
	}
	ctx := context.Background()
	sfx := randSuffix(a.t)
	base := "https://app-" + sfx + ".test"
	p := product{Key: "P" + sfx, Base: base, Redirect: base + "/callback", Initiate: base + "/login"}
	db := products.NewProductDbService(a.owner)
	row, err := db.Create(ctx, p.Key, products.ProductFields{
		Name: "Product " + sfx, BaseURL: base, InitiateLoginURI: p.Initiate, IsActive: true,
	})
	if err != nil {
		a.t.Fatalf("seed product: %v", err)
	}
	p.ID = row.ID
	if _, err := db.SetRoles(ctx, p.ID, roles); err != nil {
		a.t.Fatal(err)
	}
	if _, err := db.SetRedirectURIs(ctx, p.ID, []string{p.Redirect}); err != nil {
		a.t.Fatal(err)
	}
	raw, _ := tokens.GenerateOpaque()
	p.Secret = "acs_" + raw
	if _, err := db.SetClientSecret(ctx, p.ID, tokens.HashToken(p.Secret)); err != nil {
		a.t.Fatal(err)
	}
	return p
}

func (a *app) subscribe(co company, p product) {
	a.t.Helper()
	if _, err := clientproducts.NewClientProductDbService(a.owner).Upsert(context.Background(), co.ID, p.ID, true, nil, nil); err != nil {
		a.t.Fatalf("subscribe: %v", err)
	}
}

// grant gives a user a direct role in a product.
func (a *app) grant(m member, p product, role string) {
	a.t.Helper()
	if err := productpermissions.NewProductPermissionDbService(a.owner).Upsert(context.Background(), m.ID, m.ClientID, p.ID, role, m.ID); err != nil {
		a.t.Fatalf("grant: %v", err)
	}
}

// grantGroup makes a group confer a role in a product.
func (a *app) grantGroup(co company, groupID string, p product, role string) {
	a.t.Helper()
	if _, err := groups.NewGroupDbService(a.owner).SetProductGrants(context.Background(), groupID, co.ID,
		[]groups.ProductGrant{{ProductID: p.ID, RoleName: role}}, ""); err != nil {
		a.t.Fatalf("grant group: %v", err)
	}
}

// platform returns the one platform company, creating it on first use.
func (a *app) platform() company {
	a.t.Helper()
	platformOnce.Lock()
	defer platformOnce.Unlock()
	ctx := context.Background()
	var id, name string
	err := a.pool.QueryRow(ctx, `SELECT id, name FROM tbl_clients WHERE is_platform`).Scan(&id, &name)
	if err != nil {
		c, cerr := clients.NewClientDbService(a.owner).Create(ctx, clients.NewClient{
			Name: "Alora Platform", SubscriptionStatus: dbmodels.SubscriptionActive, IsActive: true, IsPlatform: true,
		})
		if cerr != nil {
			a.t.Fatalf("seed platform: %v (after %v)", cerr, err)
		}
		id, name = c.ID, c.Name
	}
	admins, err := groups.NewGroupDbService(a.owner).SystemGroupID(ctx, id, dbmodels.SystemGroupAdmins)
	if err != nil {
		a.t.Fatal(err)
	}
	return company{ID: id, Name: name, AdminsID: admins}
}

// newOwner creates a platform Owner: a member of the platform company's Admins
// group, promoted through the provisioning procedure the application role
// cannot call.
func (a *app) newOwner() member {
	a.t.Helper()
	pl := a.platform()
	m := a.newAdmin(pl)
	if err := users.NewUserDbService(a.owner).CreatePlatformOwner(context.Background(), m.ID, pl.ID); err != nil {
		a.t.Fatalf("promote owner: %v", err)
	}
	return m
}

// ---------- sessions ----------

// session is a signed-in App Central browser: its access token and the
// HttpOnly session cookie.
type session struct {
	Access string
	Cookie *http.Cookie
}

const centralCookie = "alora_cs" // the dev/test name; production adds __Host-

// login signs a member in with their password and returns the session.
func (a *app) login(m member) session {
	a.t.Helper()
	w := a.post("/auth/login/password", map[string]any{"email": m.Email, "password": m.Password})
	expect(a.t, w, http.StatusOK, "login "+m.Email)
	if s := jsonField(w, "status"); s != "authenticated" {
		a.t.Fatalf("login %s: status %q (%s)", m.Email, s, w.Body.String())
	}
	ck := cookieNamed(w, centralCookie)
	if ck == nil {
		a.t.Fatalf("login %s set no session cookie", m.Email)
	}
	return session{Access: jsonField(w, "access_token"), Cookie: ck}
}

// refresh rotates a session's cookie and returns the new session, with the
// response for a test that expects it to fail.
func (a *app) refresh(s session) (session, *httptest.ResponseRecorder) {
	a.t.Helper()
	w := a.post("/auth/central/refresh", nil, withCookie(s.Cookie))
	if w.Code != http.StatusOK {
		return session{}, w
	}
	return session{Access: jsonField(w, "access_token"), Cookie: cookieNamed(w, centralCookie)}, w
}

// ---------- the OAuth provider ----------

// flow is one authorization request of a product.
type flow struct {
	Verifier string
	State    string
	Nonce    string
	Scope    string
}

func newFlow(t *testing.T) flow {
	t.Helper()
	v, err := pkce.NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	return flow{Verifier: v, State: "st-" + randSuffix(t), Nonce: "n-" + randSuffix(t), Scope: "openid email"}
}

func (f flow) query(p product) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {p.ID},
		"redirect_uri":          {p.Redirect},
		"scope":                 {f.Scope},
		"state":                 {f.State},
		"nonce":                 {f.Nonce},
		"code_challenge":        {pkce.ChallengeS256(f.Verifier)},
		"code_challenge_method": {"S256"},
	}
}

// authorize sends the browser (with its session cookie) to /oauth/authorize.
func (a *app) authorize(s session, q url.Values) *httptest.ResponseRecorder {
	a.t.Helper()
	return a.get("/oauth/authorize?"+q.Encode(), withCookie(s.Cookie))
}

// location parses a redirect's target.
func location(t *testing.T, w interface{ Header() http.Header }) *url.URL {
	t.Helper()
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatalf("bad Location %q", w.Header().Get("Location"))
	}
	return u
}
