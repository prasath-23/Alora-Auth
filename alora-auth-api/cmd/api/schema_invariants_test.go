package main

// Invariants that live in the SCHEMA rather than in Go, tested here because a
// unit test cannot see them and a code review will not notice when one is
// loosened. Each is exercised through the connection it constrains: the owner's
// for what the schema itself refuses, the application role's for what it must
// never be granted.

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/alora/auth/internal/core/shared"
)

// violates reports whether err is the database refusing a row by the named
// constraint, so a test cannot pass on some unrelated error.
func violates(err error, constraint string) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && strings.EqualFold(pg.ConstraintName, constraint)
}

// requireAppRole fails when the harness is split (an owner DSN is configured) but
// the router is not running as alora_app — the configuration these tests exist
// to catch — and skips when the whole suite runs as a single superuser.
func requireAppRole(t *testing.T, a *app) {
	t.Helper()
	var who string
	if err := a.db.Pool().QueryRow(context.Background(), `SELECT current_user`).Scan(&who); err != nil {
		t.Fatal(err)
	}
	if who == "alora_app" {
		return
	}
	if os.Getenv("ALORA_TEST_OWNER_DB") != "" {
		t.Fatalf("the router connects as %q; the harness must run it as alora_app", who)
	}
	t.Skipf("the router connects as %q, not alora_app; run scripts/integration-test.sh", who)
}

// The audit trail records WHO did each thing. An ON DELETE SET NULL on the actor
// key would silently defeat that.
func TestAuditActorKeyIsRestrict(t *testing.T) {
	a := newApp(t)
	var action string
	a.scalar(&action, `SELECT confdeltype::text FROM pg_constraint WHERE conname = 'fk_tbl_audit_logs_tbl_users_actor_user_id'`)
	if action != "r" {
		t.Fatalf("audit actor FK is %q, want %q (RESTRICT)", action, "r")
	}
}

func TestDeletingAnAuditedUserIsRefused(t *testing.T) {
	a := newApp(t)
	ctx := context.Background()
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	co := a.newCompany()
	m := a.newMember(co, "")
	if _, err := tx.Exec(ctx, `INSERT INTO tbl_audit_logs (client_id, actor_user_id, event_type) VALUES ($1, $2, 'INVARIANT_PROBE')`,
		co.ID, m.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tbl_users WHERE id = $1`, m.ID); err == nil {
		t.Fatal("deleted a user that has audit history")
	}
}

// Nobody promotes themselves: the application role can read the Owners, never
// write them — not directly, and not through the provisioning procedure.
func TestAppRoleCannotWriteOwners(t *testing.T) {
	a := newApp(t)
	requireAppRole(t, a)
	pl := a.platform()
	m := a.newMember(pl, "")
	ctx := context.Background()
	for name, sql := range map[string]string{
		"insert":    `INSERT INTO tbl_platform_owners (user_id, client_id) VALUES ($1, $2)`,
		"procedure": `CALL stp_CreatePlatformOwner($1, $2)`,
	} {
		if _, err := a.db.Pool().Exec(ctx, sql, m.ID, pl.ID); err == nil {
			t.Errorf("SECURITY: the application role promoted an Owner via %s", name)
		}
	}
	if _, err := a.db.Pool().Exec(ctx, `DELETE FROM tbl_platform_owners`); err == nil {
		t.Error("SECURITY: the application role deleted the Owners")
	}
	var n int
	if err := a.db.Pool().QueryRow(ctx, `SELECT count(*) FROM tbl_platform_owners`).Scan(&n); err != nil {
		t.Errorf("the application role cannot even read the Owners: %v", err)
	}
}

// Sessions and their families are revoked, never deleted: the chain is the
// evidence replay detection reads.
func TestAppRoleCannotDeleteSessions(t *testing.T) {
	a := newApp(t)
	requireAppRole(t, a)
	for _, table := range []string{"tbl_user_sessions", "tbl_session_families", "tbl_audit_logs", "tbl_users"} {
		if _, err := a.db.Pool().Exec(context.Background(), `DELETE FROM `+table+` WHERE false`); err == nil {
			t.Errorf("SECURITY: the application role may DELETE from %s", table)
		}
	}
	if _, err := a.db.Pool().Exec(context.Background(), `UPDATE tbl_audit_logs SET event_type = event_type WHERE false`); err == nil {
		t.Error("SECURITY: the application role may rewrite the audit trail")
	}
}

// What the procedures the Owner console calls need, the role must hold — or
// the feature works for the owner in development and fails in production.
func TestAppRoleHoldsWhatTheRoutinesNeed(t *testing.T) {
	a := newApp(t)
	requireAppRole(t, a)
	for _, grant := range []struct{ table, privilege string }{
		{"tbl_client_products", "INSERT"}, {"tbl_client_products", "UPDATE"},
		{"tbl_product_permissions", "UPDATE"}, {"tbl_product_roles", "DELETE"},
		{"tbl_login_states", "DELETE"}, {"tbl_group_product_grants", "INSERT"},
		{"tbl_sso_connections", "UPDATE"}, {"tbl_sso_connection_domains", "DELETE"},
		{"tbl_group_scopes", "INSERT"}, {"tbl_group_scopes", "DELETE"},
		{"tbl_user_scopes", "INSERT"}, {"tbl_user_scopes", "DELETE"},
		{"tbl_api_clients", "INSERT"}, {"tbl_api_clients", "DELETE"},
		{"tbl_api_client_scopes", "INSERT"}, {"tbl_api_client_scopes", "DELETE"},
		{"tbl_api_client_products", "INSERT"}, {"tbl_api_client_products", "DELETE"},
		{"tbl_api_client_secrets", "INSERT"},
		{"tbl_group_managers", "INSERT"}, {"tbl_group_managers", "DELETE"},
	} {
		var ok bool
		a.scalar(&ok, `SELECT has_table_privilege('alora_app', $1, $2)`, grant.table, grant.privilege)
		if !ok {
			t.Errorf("alora_app lacks %s on %s", grant.privilege, grant.table)
		}
	}
}

// The scope catalogue is the database's as much as the code's: every grant
// references it, so the two must list exactly the same scopes. A scope added to
// one and not the other is either ungrantable or unenforced.
func TestTheScopeCatalogueMatchesTheRegistry(t *testing.T) {
	a := newApp(t)
	list := func(kind string) []string {
		t.Helper()
		var out []string
		a.scalar(&out, `SELECT coalesce(array_agg(scope ORDER BY sort_order), '{}') FROM tbl_scopes WHERE kind = $1`, kind)
		return out
	}
	if got, want := list("PERSON"), shared.GrantableScopes(); !slices.Equal(got, want) {
		t.Errorf("PERSON scopes in the database = %v, in the registry = %v", got, want)
	}
	if got, want := list("CLIENT"), shared.ClientScopes(); !slices.Equal(got, want) {
		t.Errorf("CLIENT scopes = %v, want %v", got, want)
	}
	for _, f := range shared.Features {
		for level, scope := range map[string]string{"read": f.Read, "edit": f.Edit} {
			if scope == "" {
				continue
			}
			if n := a.count(`SELECT count(*) FROM tbl_scopes WHERE scope = $1 AND feature = $2 AND level = $3`, scope, f.Key, level); n != 1 {
				t.Errorf("%s is not filed under feature %s, level %s", scope, f.Key, level)
			}
		}
	}
	// A person cannot hold an application's scope, nor a group give one.
	co := a.newCompany()
	m := a.newMember(co, "")
	g := a.newGroup(co)
	ctx := context.Background()
	for _, c := range []struct {
		name, constraint, sql string
		args                  []any
	}{
		{"a person holding an application's scope", "ck_tbl_user_scopes_kind",
			`INSERT INTO tbl_user_scopes (user_id, client_id, scope, kind) VALUES ($1, $2, 'api:read', 'CLIENT')`, []any{m.ID, co.ID}},
		{"a group giving an application's scope", "ck_tbl_group_scopes_kind",
			`INSERT INTO tbl_group_scopes (group_id, client_id, scope, kind) VALUES ($1, $2, 'grpc:edit', 'CLIENT')`, []any{g, co.ID}},
		{"a scope outside the catalogue", "fk_tbl_group_scopes_tbl_scopes_scope_kind",
			`INSERT INTO tbl_group_scopes (group_id, client_id, scope) VALUES ($1, $2, 'users:admin')`, []any{g, co.ID}},
		{"an extra with two grantors", "ck_tbl_user_scopes_one_granter",
			`INSERT INTO tbl_user_scopes (user_id, client_id, scope, granted_by_user_id, granted_by_owner_id) VALUES ($1, $2, 'users:read', $1, $1)`, []any{m.ID, co.ID}},
	} {
		if _, err := a.pool.Exec(ctx, c.sql, c.args...); !violates(err, c.constraint) {
			t.Errorf("SECURITY: %s: %v, want a violation of %s", c.name, err, c.constraint)
		}
	}
}

// The application can read the catalogue, never change it: an application
// that could add a scope could invent a permission.
func TestAppRoleCannotWriteTheScopeCatalogue(t *testing.T) {
	a := newApp(t)
	requireAppRole(t, a)
	ctx := context.Background()
	for name, sql := range map[string]string{
		"insert": `INSERT INTO tbl_scopes (scope, kind, feature, level, description, sort_order) VALUES ('users:god', 'PERSON', 'users', 'edit', 'x', 999)`,
		"update": `UPDATE tbl_scopes SET kind = kind WHERE false`,
		"delete": `DELETE FROM tbl_scopes WHERE false`,
	} {
		if _, err := a.db.Pool().Exec(ctx, sql); err == nil {
			t.Errorf("SECURITY: the application role may %s the scope catalogue", name)
		}
	}
	var n int
	if err := a.db.Pool().QueryRow(ctx, `SELECT count(*) FROM tbl_scopes`).Scan(&n); err != nil || n == 0 {
		t.Errorf("the application role cannot read the catalogue: %d, %v", n, err)
	}
}

// A secret's hash is fixed when it is made, and a secret is revoked, never
// deleted: an application role that could rewrite one could swap a secret it
// knows in for any API client. Only revocation and the last-use stamp may
// change, and an API client never changes company.
func TestAppRoleCannotRewriteAPIClientSecrets(t *testing.T) {
	a := newApp(t)
	requireAppRole(t, a)
	may := func(table, col string) bool {
		t.Helper()
		var ok bool
		a.scalar(&ok, `SELECT has_column_privilege('alora_app', $1, $2, 'UPDATE')`, table, col)
		return ok
	}
	for _, col := range []string{"secret_hash", "prefix", "api_client_id", "client_id", "expires_at", "created_at"} {
		if may("tbl_api_client_secrets", col) {
			t.Errorf("SECURITY: alora_app may UPDATE tbl_api_client_secrets.%s", col)
		}
	}
	for _, col := range []string{"revoked_at", "last_used_at"} {
		if !may("tbl_api_client_secrets", col) {
			t.Errorf("alora_app lacks UPDATE on tbl_api_client_secrets.%s", col)
		}
	}
	for _, col := range []string{"id", "client_id", "created_by_user_id", "created_by_owner_id"} {
		if may("tbl_api_clients", col) {
			t.Errorf("SECURITY: alora_app may UPDATE tbl_api_clients.%s", col)
		}
	}
	if _, err := a.db.Pool().Exec(context.Background(), `DELETE FROM tbl_api_client_secrets WHERE false`); err == nil {
		t.Error("SECURITY: the application role may delete API client secrets")
	}
}

// What an API client may hold is pinned by the schema too: its id's shape, one
// creator of its own company, application scopes only, its own company's rows,
// and products its company subscribes to.
func TestAPIClientTablesKeepTheirInvariants(t *testing.T) {
	a := newApp(t)
	co, other := a.newCompany(), a.newCompany()
	admin := a.newAdmin(co)
	var id string
	a.scalar(&id, `SELECT id FROM stp_CreateApiClient($1, 'Probe', NULL, $2, NULL)`, co.ID, admin.ID)
	unsubscribed := a.newProduct()
	ctx := context.Background()
	for _, c := range []struct {
		name, constraint, sql string
		args                  []any
	}{
		{"an id without the API-client prefix", "ck_tbl_api_clients_id",
			`INSERT INTO tbl_api_clients (id, client_id, name, created_by_user_id) VALUES (gen_random_uuid()::text, $1, 'Bare', $2)`,
			[]any{co.ID, admin.ID}},
		{"an API client with no creator", "ck_tbl_api_clients_one_creator",
			`INSERT INTO tbl_api_clients (client_id, name) VALUES ($1, 'Orphan')`, []any{co.ID}},
		{"a creator from another company", "fk_tbl_api_clients_created_by_user",
			`INSERT INTO tbl_api_clients (client_id, name, created_by_user_id) VALUES ($1, 'Foreign', $2)`, []any{other.ID, admin.ID}},
		{"a person's scope for an application", "fk_tbl_api_client_scopes_tbl_scopes_scope_kind",
			`INSERT INTO tbl_api_client_scopes (api_client_id, client_id, scope) VALUES ($1, $2, 'users:edit')`, []any{id, co.ID}},
		{"a scope filed under another company", "fk_tbl_api_client_scopes_api_client",
			`INSERT INTO tbl_api_client_scopes (api_client_id, client_id, scope) VALUES ($1, $2, 'api:read')`, []any{id, other.ID}},
		{"a product the company does not subscribe to", "fk_tbl_api_client_products_subscription",
			`INSERT INTO tbl_api_client_products (api_client_id, client_id, product_id) VALUES ($1, $2, $3)`, []any{id, co.ID, unsubscribed.ID}},
		{"a secret prefix that is not one", "ck_tbl_api_client_secrets_prefix",
			`INSERT INTO tbl_api_client_secrets (api_client_id, client_id, secret_hash, prefix, created_by_user_id)
			 VALUES ($1, $2, 'h1', 'acs_12345678', $3)`, []any{id, co.ID, admin.ID}},
		{"a secret with no creator", "ck_tbl_api_client_secrets_one_creator",
			`INSERT INTO tbl_api_client_secrets (api_client_id, client_id, secret_hash, prefix)
			 VALUES ($1, $2, 'h2', 'acc_12345678')`, []any{id, co.ID}},
	} {
		if _, err := a.pool.Exec(ctx, c.sql, c.args...); !violates(err, c.constraint) {
			t.Errorf("SECURITY: %s: %v, want a violation of %s", c.name, err, c.constraint)
		}
	}
}

// Who runs a group is kept honest by the schema, whatever the application does:
// an appointment names exactly one appointer, never the appointee themselves,
// and never crosses companies — and the application role can make and end one,
// never move it. The Admins group is refused by the procedure that appoints.
func TestGroupManagersKeepTheirInvariants(t *testing.T) {
	a := newApp(t)
	co, other := a.newCompany(), a.newCompany()
	admin, lead := a.newAdmin(co), a.newMember(co, "")
	g, foreignGroup := a.newGroup(co), a.newGroup(other)
	stranger := a.newMember(other, "")
	ctx := context.Background()
	for _, c := range []struct {
		name, constraint, sql string
		args                  []any
	}{
		{"an appointment with no appointer", "ck_tbl_group_managers_one_appointer",
			`INSERT INTO tbl_group_managers (group_id, client_id, user_id) VALUES ($1, $2, $3)`, []any{g, co.ID, lead.ID}},
		{"an appointment with two appointers", "ck_tbl_group_managers_one_appointer",
			`INSERT INTO tbl_group_managers (group_id, client_id, user_id, appointed_by_user_id, appointed_by_owner_id)
			 VALUES ($1, $2, $3, $4, $4)`, []any{g, co.ID, lead.ID, admin.ID}},
		{"appointing yourself", "ck_tbl_group_managers_not_self",
			`INSERT INTO tbl_group_managers (group_id, client_id, user_id, appointed_by_user_id) VALUES ($1, $2, $3, $3)`,
			[]any{g, co.ID, lead.ID}},
		{"a manager from another company", "fk_tbl_group_managers_user",
			`INSERT INTO tbl_group_managers (group_id, client_id, user_id, appointed_by_user_id) VALUES ($1, $2, $3, $4)`,
			[]any{g, co.ID, stranger.ID, admin.ID}},
		{"another company's group", "fk_tbl_group_managers_group",
			`INSERT INTO tbl_group_managers (group_id, client_id, user_id, appointed_by_user_id) VALUES ($1, $2, $3, $4)`,
			[]any{foreignGroup, co.ID, lead.ID, admin.ID}},
		{"an appointer from another company", "fk_tbl_group_managers_appointed_by_user",
			`INSERT INTO tbl_group_managers (group_id, client_id, user_id, appointed_by_user_id) VALUES ($1, $2, $3, $4)`,
			[]any{g, co.ID, lead.ID, stranger.ID}},
	} {
		if _, err := a.pool.Exec(ctx, c.sql, c.args...); !violates(err, c.constraint) {
			t.Errorf("SECURITY: %s: %v, want a violation of %s", c.name, err, c.constraint)
		}
	}
	var n int
	a.scalar(&n, `SELECT stp_AddGroupManager($1, $2, $3, $4, NULL)`, co.AdminsID, co.ID, lead.ID, admin.ID)
	if n != -2 {
		t.Errorf("SECURITY: the Admins group took a manager (%d)", n)
	}

	requireAppRole(t, a)
	for _, privilege := range []string{"UPDATE", "TRUNCATE"} {
		var ok bool
		a.scalar(&ok, `SELECT has_table_privilege('alora_app', 'tbl_group_managers', $1)`, privilege)
		if ok {
			t.Errorf("SECURITY: alora_app holds %s on tbl_group_managers: an appointment could be moved", privilege)
		}
	}
}

// A name a standard bounds is bounded by its table too: a domain is at most 253
// characters (RFC 1035) and a provider's subject at most 255 (OpenID Connect
// Core §2). Each limit is accepted exactly, and one character more is refused by
// its own constraint — never left to an index that cannot hold the value.
func TestStandardNamesKeepTheirLengths(t *testing.T) {
	a := newApp(t)
	sso := a.setupSSO()
	m := a.newMember(sso.co, "")
	ctx := context.Background()
	for _, c := range []struct {
		name, constraint, sql string
		limit                 int
		args                  func(v string) []any
	}{
		{"a company's domain", "ck_tbl_clients_domain_length",
			`UPDATE tbl_clients SET domain = $1 WHERE id = $2`, 253,
			func(v string) []any { return []any{v, sso.co.ID} }},
		{"an SSO connection's domain", "ck_tbl_sso_connection_domains_length",
			`INSERT INTO tbl_sso_connection_domains (domain, connection_id, client_id) VALUES ($1, $2, $3)`, 253,
			func(v string) []any { return []any{v, sso.conn, sso.co.ID} }},
		{"a provider's subject", "ck_tbl_linked_identities_provider_id_length",
			`INSERT INTO tbl_linked_identities (user_id, client_id, provider, provider_id) VALUES ($1, $2, 'GOOGLE', $3)`, 255,
			func(v string) []any { return []any{m.ID, sso.co.ID, v} }},
	} {
		long := letters(c.limit + 1)
		if _, err := a.pool.Exec(ctx, c.sql, c.args(long)...); !violates(err, c.constraint) {
			t.Errorf("%s of %d characters: %v, want a violation of %s", c.name, c.limit+1, err, c.constraint)
		}
		if _, err := a.pool.Exec(ctx, c.sql, c.args(long[:c.limit])...); err != nil {
			t.Errorf("%s of exactly %d characters was refused: %v", c.name, c.limit, err)
		}
	}
}

// Every company has exactly one Admins group and exactly one default policy —
// however it was created.
func TestEveryCompanyHasItsAdminsGroupAndDefaultPolicy(t *testing.T) {
	a := newApp(t)
	a.newCompany()
	if n := a.count(`SELECT count(*) FROM tbl_clients c WHERE
	        (SELECT count(*) FROM tbl_groups g WHERE g.client_id = c.id AND g.system_key = 'ADMINS') <> 1
	     OR (SELECT count(*) FROM tbl_login_policies p WHERE p.client_id = c.id AND p.is_default) <> 1`); n != 0 {
		t.Fatalf("%d companies lack exactly one Admins group and one default policy", n)
	}
	// And the schema refuses a second of either.
	co := a.newCompany()
	ctx := context.Background()
	if _, err := a.pool.Exec(ctx, `INSERT INTO tbl_groups (client_id, name, system_key) VALUES ($1, 'Admins 2', 'ADMINS')`, co.ID); err == nil {
		t.Error("a second Admins group was accepted")
	}
	if _, err := a.pool.Exec(ctx, `INSERT INTO tbl_login_policies (client_id, name, priority, is_default) VALUES ($1, 'Second', 99, true)`, co.ID); err == nil {
		t.Error("a second default policy was accepted")
	}
	// Only one platform company can exist.
	a.platform()
	if _, err := a.pool.Exec(ctx, `INSERT INTO tbl_clients (name, is_platform) VALUES ('Another platform', true)`); err == nil {
		t.Error("a second platform company was accepted")
	}
}

// Rows that tie two companies together are refused by composite keys, whatever
// the application does.
func TestCompositeKeysKeepCompaniesApart(t *testing.T) {
	a := newApp(t)
	coA, coB := a.newCompany(), a.newCompany()
	inA := a.newMember(coA, "")
	groupB := a.newGroup(coB)
	p := a.newProduct("Viewer")
	a.subscribe(coB, p)
	ctx := context.Background()
	for name, q := range map[string][]any{
		"a membership across companies":  {`INSERT INTO tbl_user_groups (user_id, group_id, client_id) VALUES ($1, $2, $3)`, inA.ID, groupB, coA.ID},
		"a grant without a subscription": {`INSERT INTO tbl_product_permissions (user_id, client_id, product_id, role_name) VALUES ($1, $2, $3, 'Viewer')`, inA.ID, coA.ID, p.ID},
		"a role outside the catalogue":   {`INSERT INTO tbl_group_product_grants (group_id, client_id, product_id, role_name) VALUES ($1, $2, $3, 'Emperor')`, groupB, coB.ID, p.ID},
		"an Owner outside the platform":  {`INSERT INTO tbl_platform_owners (user_id, client_id) VALUES ($1, $2)`, inA.ID, coA.ID},
		"a session of another company":   {`INSERT INTO tbl_session_families (user_id, client_id, kind, auth_method, absolute_expires_at) VALUES ($1, $2, 'CENTRAL', 'EMAIL', now() + interval '1 day')`, inA.ID, coB.ID},
	} {
		if _, err := a.pool.Exec(ctx, q[0].(string), q[1:]...); err == nil {
			t.Errorf("SECURITY: %s was accepted", name)
		}
	}
}

// The database is the v3 schema: the v1 rule "is_global_admin" is gone, so no
// flag on a user row can make anyone an administrator of every company, and
// v2's feature keys are gone, so no grant exists outside the scope catalogue.
// (The build itself refuses to run over a v1 or v2 database; the database
// repository's check script exercises that.)
func TestSchemaIsV3(t *testing.T) {
	a := newApp(t)
	var n int
	a.scalar(&n, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'tbl_users' AND column_name = 'is_global_admin'`)
	if n != 0 {
		t.Fatal("the v1 is_global_admin column exists")
	}
	a.scalar(&n, `SELECT count(*) FROM information_schema.tables WHERE table_name = 'tbl_group_features'`)
	if n != 0 {
		t.Fatal("the v2 tbl_group_features table exists")
	}
}
