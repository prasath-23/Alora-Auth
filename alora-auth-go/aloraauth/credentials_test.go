package aloraauth

import (
	"context"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/prasath-23/Alora-Auth/alora-auth-go/authpb"
)

// tokenStub is App Central's TokenService: it counts calls, records what it
// was sent, and can be told to fail or to hold every call at a gate.
type tokenStub struct {
	authpb.UnimplementedTokenServiceServer
	calls     atomic.Int32
	mu        sync.Mutex
	lastAuth  string
	lastReq   *authpb.GetTokenRequest
	fail      error
	expiresIn int32
	gate      chan struct{}
}

func (s *tokenStub) GetToken(ctx context.Context, req *authpb.GetTokenRequest) (*authpb.GetTokenResponse, error) {
	n := s.calls.Add(1)
	if s.gate != nil {
		<-s.gate
	}
	md, _ := metadata.FromIncomingContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastReq = req
	if v := md.Get("authorization"); len(v) == 1 {
		s.lastAuth = v[0]
	}
	if s.fail != nil {
		return nil, s.fail
	}
	return &authpb.GetTokenResponse{AccessToken: "token-" + strconv.Itoa(int(n)), TokenType: "Bearer", ExpiresIn: s.expiresIn, Scopes: req.GetScopes()}, nil
}

func newTokenStub(t *testing.T, stub *tokenStub) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	authpb.RegisterTokenServiceServer(srv, stub)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///central",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func credsFor(t *testing.T, stub *tokenStub, scopes ...string) *TokenCredentials {
	t.Helper()
	c, err := ClientCredentials(Config{
		Conn: newTokenStub(t, stub), ClientID: "aci_1", ClientSecret: "acc_s+cret", Product: "INV", Scopes: scopes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The first call fetches a token, with the client's credentials as
// client_secret_basic; the calls after it reuse it.
func TestClientCredentialsFetchOnceAndReuse(t *testing.T) {
	stub := &tokenStub{expiresIn: 900}
	c := credsFor(t, stub, "grpc:read")
	for i := 0; i < 3; i++ {
		md, err := c.GetRequestMetadata(t.Context())
		if err != nil || md["authorization"] != "Bearer token-1" {
			t.Fatalf("call %d: %v %v", i, md, err)
		}
	}
	if n := stub.calls.Load(); n != 1 {
		t.Errorf("%d fetches, want 1", n)
	}
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(stub.lastAuth, "Basic "))
	if string(raw) != "aci_1:acc_s%2Bcret" {
		t.Errorf("credentials sent = %q (form-encoded, then Basic)", raw)
	}
	if stub.lastReq.GetResource() != "product:INV" || strings.Join(stub.lastReq.GetScopes(), " ") != "grpc:read" {
		t.Errorf("request = %v", stub.lastReq)
	}
	if !c.RequireTransportSecurity() {
		t.Error("the token would be sent over plaintext")
	}
}

// A token is renewed shortly before it expires — a fifth of its life before, at
// most a minute — not after a call has failed with it.
func TestClientCredentialsRenewBeforeExpiry(t *testing.T) {
	stub := &tokenStub{expiresIn: 900}
	c := credsFor(t, stub)
	clock := time.Now()
	c.now = func() time.Time { return clock }
	if tok, _ := c.Token(t.Context()); tok != "token-1" {
		t.Fatalf("first token %q", tok)
	}
	clock = clock.Add(839 * time.Second) // 61s left: kept
	if tok, _ := c.Token(t.Context()); tok != "token-1" {
		t.Errorf("renewed too early: %q", tok)
	}
	clock = clock.Add(2 * time.Second) // 59s left: renewed
	if tok, _ := c.Token(t.Context()); tok != "token-2" {
		t.Errorf("not renewed a minute before expiry: %q", tok)
	}
	// A short-lived token is renewed at four fifths of its life.
	stub.expiresIn = 50
	clock = clock.Add(20 * time.Minute)
	_, _ = c.Token(t.Context())
	clock = clock.Add(41 * time.Second)
	if tok, _ := c.Token(t.Context()); tok != "token-4" {
		t.Errorf("a 50s token was not renewed after 41s: %q", tok)
	}
}

// Calls arriving while a token is being fetched share that one request.
func TestClientCredentialsShareOneFetch(t *testing.T) {
	stub := &tokenStub{expiresIn: 900, gate: make(chan struct{})}
	c := credsFor(t, stub)
	var wg sync.WaitGroup
	got := make([]string, 20)
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], _ = c.Token(t.Context())
		}()
	}
	for stub.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // every caller is now waiting
	close(stub.gate)
	wg.Wait()
	if n := stub.calls.Load(); n != 1 {
		t.Errorf("%d fetches for 20 concurrent calls", n)
	}
	for i, tok := range got {
		if tok != "token-1" {
			t.Errorf("caller %d got %q", i, tok)
		}
	}
}

// A refusal reaches the caller and is not kept: the next call asks again. A
// caller that gives up while waiting gets its own context's error.
func TestClientCredentialsFailures(t *testing.T) {
	stub := &tokenStub{expiresIn: 900, fail: status.Error(codes.Unauthenticated, "no")}
	c := credsFor(t, stub)
	if _, err := c.GetRequestMetadata(t.Context()); status.Code(errorsUnwrap(err)) != codes.Unauthenticated {
		t.Errorf("a refusal: %v", err)
	}
	stub.fail = nil
	if tok, err := c.Token(t.Context()); err != nil || tok != "token-2" {
		t.Errorf("after the refusal: %q %v", tok, err)
	}

	slow := &tokenStub{expiresIn: 900, gate: make(chan struct{})}
	c2 := credsFor(t, slow)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := c2.Token(ctx); err != context.DeadlineExceeded {
		t.Errorf("a caller that gave up: %v", err)
	}
	close(slow.gate)
	if tok, err := c2.Token(t.Context()); err != nil || tok != "token-1" {
		t.Errorf("the fetch went on for the others: %q %v", tok, err)
	}

	for _, bad := range []Config{
		{TokenAddress: "x:1", ClientSecret: "s", Product: "P"},
		{TokenAddress: "x:1", ClientID: "i", Product: "P"},
		{TokenAddress: "x:1", ClientID: "i", ClientSecret: "s"},
		{ClientID: "i", ClientSecret: "s", Product: "P"},
	} {
		if _, err := ClientCredentials(bad); err == nil {
			t.Errorf("an incomplete config was accepted: %+v", bad)
		}
	}
	dev, err := ClientCredentials(Config{TokenAddress: "localhost:3002", ClientID: "i", ClientSecret: "s", Product: "P", Insecure: true})
	if err != nil || dev.RequireTransportSecurity() {
		t.Errorf("an Insecure config: %v", err)
	}
	_ = dev.Close()
}

// errorsUnwrap reaches the gRPC status under the helper's wrapping.
func errorsUnwrap(err error) error {
	for err != nil {
		if _, ok := status.FromError(err); ok {
			return err
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return err
		}
		err = u.Unwrap()
	}
	return nil
}
