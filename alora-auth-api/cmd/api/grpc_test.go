package main

// App Central's gRPC door: TokenService over an in-memory connection, through
// the real server and its whole interceptor chain. It answers with the same
// code as POST /oauth/token, and draws on the same budgets.

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/prasath-23/Alora-Auth/alora-auth-go/authpb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/alora/auth/internal/core/shared/crypto/jwtkeys"
)

// sameAddress makes every in-memory connection appear to come from the address
// httptest requests do, so a test can show the two doors' budgets meeting.
type sameAddress struct{ net.Listener }

func (l sameAddress) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return addressedConn{c}, nil
}

type addressedConn struct{ net.Conn }

func (addressedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1234}
}

// grpcConn serves the app's gRPC server on an in-memory listener and dials it.
func (a *app) grpcConn() *grpc.ClientConn {
	a.t.Helper()
	srv, err := newGRPCServer(a.cfg, testLogger(), a.m)
	if err != nil {
		a.t.Fatalf("gRPC server: %v", err)
	}
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(sameAddress{lis}) }()
	a.t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///app-central",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		a.t.Fatal(err)
	}
	a.t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// asClient is a call context carrying an API client's credentials, as the
// token endpoint takes them: client_secret_basic.
func asClient(t *testing.T, id, secret string) context.Context {
	creds := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(id) + ":" + url.QueryEscape(secret)))
	return metadata.AppendToOutgoingContext(t.Context(), "authorization", "Basic "+creds)
}

// refusal is a call's status code and the OAuth error code in its ErrorInfo.
func refusal(err error) (codes.Code, string) {
	st, _ := status.FromError(err)
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return st.Code(), info.GetReason()
		}
	}
	return st.Code(), ""
}

// A token over gRPC is the token over HTTP: for the product named, with the
// scopes asked for or all the client holds.
func TestGRPCTokenService(t *testing.T) {
	a := newApp(t)
	app := a.newApplication(1, "grpc:read", "grpc:edit")
	p := app.products[0]
	client := authpb.NewTokenServiceClient(a.grpcConn())

	var header metadata.MD
	res, err := client.GetToken(asClient(t, app.id, app.secret), &authpb.GetTokenRequest{Resource: "product:" + p.Key}, grpc.Header(&header))
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if res.GetTokenType() != "Bearer" || res.GetExpiresIn() != 900 ||
		strings.Join(res.GetScopes(), " ") != "grpc:edit grpc:read" {
		t.Errorf("response = %v", res)
	}
	if _, err := jwtkeys.VerifyAccess(res.GetAccessToken(), "product:"+p.Key); err != nil {
		t.Fatalf("the token does not verify for its product: %v", err)
	}
	c := claims(t, res.GetAccessToken())
	if c["sub"] != app.id || c["principal"] != "client" || c["scope"] != "grpc:edit grpc:read" || c["tenant_id"] != app.co.ID {
		t.Errorf("claims = %v", c)
	}
	if len(header.Get("x-request-id")) != 1 {
		t.Errorf("no request id came back: %v", header)
	}
	// Asking for less.
	res, err = client.GetToken(asClient(t, app.id, app.secret), &authpb.GetTokenRequest{Resource: "product:" + p.Key, Scopes: []string{"grpc:read"}})
	if err != nil || strings.Join(res.GetScopes(), " ") != "grpc:read" {
		t.Errorf("a subset: %v %v", res, err)
	}
	// And it is stamped as used, as over HTTP.
	if a.count(`SELECT count(*) FROM tbl_api_client_secrets WHERE id = $1 AND last_used_at IS NOT NULL`, app.secretID) != 1 {
		t.Error("a token over gRPC left no last-use stamp")
	}
}

// Every refusal is the gRPC status the OAuth error maps to, with the OAuth
// code as its reason.
func TestGRPCTokenServiceRefusals(t *testing.T) {
	a := newApp(t)
	app := a.newApplication(1, "grpc:read")
	p := app.products[0]
	other := a.newProduct()
	client := authpb.NewTokenServiceClient(a.grpcConn())
	req := &authpb.GetTokenRequest{Resource: "product:" + p.Key}
	for _, c := range []struct {
		what   string
		ctx    context.Context
		req    *authpb.GetTokenRequest
		code   codes.Code
		reason string
	}{
		{"no credentials", t.Context(), req, codes.Unauthenticated, "invalid_client"},
		{"credentials that are not Basic", metadata.AppendToOutgoingContext(t.Context(), "authorization", "Bearer x"), req,
			codes.Unauthenticated, "invalid_client"},
		{"credentials twice", metadata.AppendToOutgoingContext(asClient(t, app.id, app.secret), "authorization", "Basic eDp5"), req,
			codes.Unauthenticated, "invalid_client"},
		{"a wrong secret", asClient(t, app.id, app.secret+"x"), req, codes.Unauthenticated, "invalid_client"},
		{"a product not on the list", asClient(t, app.id, app.secret), &authpb.GetTokenRequest{Resource: "product:" + other.Key},
			codes.PermissionDenied, "invalid_target"},
		{"no resource", asClient(t, app.id, app.secret), &authpb.GetTokenRequest{}, codes.PermissionDenied, "invalid_target"},
		{"a scope it lacks", asClient(t, app.id, app.secret), &authpb.GetTokenRequest{Resource: "product:" + p.Key, Scopes: []string{"grpc:edit"}},
			codes.InvalidArgument, "invalid_scope"},
		{"a product's credentials", asClient(t, p.ID, p.Secret), req, codes.PermissionDenied, "unauthorized_client"},
	} {
		_, err := client.GetToken(c.ctx, c.req)
		if code, reason := refusal(err); code != c.code || reason != c.reason {
			t.Errorf("%s: %v %q, want %v %q (%v)", c.what, code, reason, c.code, c.reason, err)
		}
	}
	// A message past the limit is refused before any handler reads it.
	_, err := client.GetToken(asClient(t, app.id, app.secret), &authpb.GetTokenRequest{Resource: "product:" + strings.Repeat("x", grpcMaxMessage)})
	if status.Code(err) != codes.ResourceExhausted {
		t.Errorf("an oversized message: %v", err)
	}
}

// The HTTP and gRPC doors draw on one budget: an address that spent its failed
// authentications on one is refused on the other, even with the right secret.
func TestGRPCSharesTheTokenBudgets(t *testing.T) {
	a := newApp(t)
	app := a.newApplication(1, "grpc:read")
	client := authpb.NewTokenServiceClient(a.grpcConn())
	req := &authpb.GetTokenRequest{Resource: "product:" + app.products[0].Key}
	for i := 0; i < 20; i++ {
		expect(t, a.clientCredentials("aci_"+randSuffix(t), "guess", req.Resource, ""), http.StatusUnauthorized, "a guess over HTTP")
	}
	_, err := client.GetToken(asClient(t, app.id, app.secret), req)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("SECURITY: gRPC ignored the address's spent budget: %v", err)
	}
	st, _ := status.FromError(err)
	retry := false
	for _, d := range st.Details() {
		if _, ok := d.(*errdetails.RetryInfo); ok {
			retry = true
		}
	}
	if !retry {
		t.Error("a ResourceExhausted without RetryInfo")
	}

	// The other way round, on a fresh app: failures over gRPC close HTTP.
	b := newApp(t)
	app2 := b.newApplication(1, "grpc:read")
	client2 := authpb.NewTokenServiceClient(b.grpcConn())
	req2 := &authpb.GetTokenRequest{Resource: "product:" + app2.products[0].Key}
	for i := 0; i < 20; i++ {
		if _, err := client2.GetToken(asClient(t, "aci_"+randSuffix(t), "guess"), req2); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("guess %d: %v", i, err)
		}
	}
	if w := b.clientCredentials(app2.id, app2.secret, req2.Resource, ""); w.Code != http.StatusTooManyRequests {
		t.Errorf("SECURITY: HTTP ignored failures spent over gRPC: %d", w.Code)
	}
}

// Under memory pressure every call is shed with Unavailable before it is
// authenticated; the health service says the token service is serving; and
// reflection is a development convenience only.
func TestGRPCServerShape(t *testing.T) {
	a := newAppWith(t, nil, func(m *modules) { m.pressure = pressureStub(true) })
	app := authpb.NewTokenServiceClient(a.grpcConn())
	if _, err := app.GetToken(t.Context(), &authpb.GetTokenRequest{}); status.Code(err) != codes.Unavailable {
		t.Errorf("under pressure: %v", err)
	}

	b := newApp(t)
	conn := b.grpcConn()
	res, err := healthpb.NewHealthClient(conn).Check(t.Context(), &healthpb.HealthCheckRequest{Service: authpb.TokenService_ServiceDesc.ServiceName})
	if err != nil || res.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Errorf("health: %v %v", res, err)
	}
	has := func(isProd bool, name string) bool {
		cfg := *b.cfg
		cfg.IsProd = isProd
		srv, err := newGRPCServer(&cfg, testLogger(), b.m)
		if err != nil {
			t.Fatal(err)
		}
		defer srv.Stop()
		_, ok := srv.GetServiceInfo()[name]
		return ok
	}
	const refl = "grpc.reflection.v1.ServerReflection"
	if !has(false, refl) || has(true, refl) {
		t.Errorf("reflection: development %v, production %v; want only in development", has(false, refl), has(true, refl))
	}
	if !has(true, authpb.TokenService_ServiceDesc.ServiceName) {
		t.Error("the token service is not registered")
	}
}
