package middlewares

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

var unaryInfo = &grpc.UnaryServerInfo{FullMethod: "/alora.auth.v1.TokenService/GetToken"}

func fromAddr(ip string, md ...string) context.Context {
	ctx := peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 5555}})
	if len(md) > 0 {
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(md...))
	}
	return ctx
}

// A panic becomes Internal — logged with its stack, its text never sent back.
func TestGRPCRecoverTurnsAPanicIntoInternal(t *testing.T) {
	var logs bytes.Buffer
	rec := GRPCRecover(slog.New(slog.NewTextHandler(&logs, nil)))
	_, err := rec(context.Background(), nil, unaryInfo, func(context.Context, any) (any, error) {
		panic("secret detail")
	})
	if status.Code(err) != codes.Internal || strings.Contains(err.Error(), "secret detail") {
		t.Errorf("err = %v", err)
	}
	if !strings.Contains(logs.String(), "secret detail") || !strings.Contains(logs.String(), "stack") {
		t.Errorf("the panic was not logged: %s", logs.String())
	}
}

// Each call gets its own request id; one the caller sends is ignored.
func TestGRPCRequestIDIsFreshAndIgnoresTheCallers(t *testing.T) {
	ids := map[string]bool{}
	for i := 0; i < 3; i++ {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-request-id", "forged"))
		_, _ = GRPCRequestID()(ctx, nil, unaryInfo, func(ctx context.Context, _ any) (any, error) {
			ids[GRPCRequestIDFrom(ctx)] = true
			return nil, nil
		})
	}
	if len(ids) != 3 || ids["forged"] || ids[""] {
		t.Errorf("request ids = %v", ids)
	}
}

// The address a call came from: the peer's, unless the peer is a trusted proxy
// — then the right-most forwarded address that is not itself a trusted proxy.
// A forwarded address from anyone else is never believed.
func TestGRPCClientIPBelievesOnlyTrustedProxies(t *testing.T) {
	none, err := GRPCClientIP(nil)
	if err != nil {
		t.Fatal(err)
	}
	proxied, err := GRPCClientIP([]string{"10.0.0.0/8", "192.168.1.7"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		what string
		fn   func(context.Context) string
		ctx  context.Context
		want string
	}{
		{"no proxy trusted", none, fromAddr("203.0.113.9", "x-forwarded-for", "1.2.3.4"), "203.0.113.9"},
		{"an untrusted peer's forwarding", proxied, fromAddr("203.0.113.9", "x-forwarded-for", "1.2.3.4"), "203.0.113.9"},
		{"a trusted proxy", proxied, fromAddr("10.1.2.3", "x-forwarded-for", "198.51.100.4"), "198.51.100.4"},
		{"a chain through trusted proxies", proxied, fromAddr("10.1.2.3", "x-forwarded-for", "1.1.1.1, 198.51.100.4, 192.168.1.7"), "198.51.100.4"},
		{"a single trusted IP", proxied, fromAddr("192.168.1.7", "x-forwarded-for", "198.51.100.5"), "198.51.100.5"},
		{"a trusted proxy forwarding nothing", proxied, fromAddr("10.1.2.3"), "10.1.2.3"},
		{"a garbled chain", proxied, fromAddr("10.1.2.3", "x-forwarded-for", "not-an-ip"), "10.1.2.3"},
	} {
		if got := c.fn(c.ctx); got != c.want {
			t.Errorf("%s: %q, want %q", c.what, got, c.want)
		}
	}
	if _, err := GRPCClientIP([]string{"10.0.0.0/99"}); err == nil {
		t.Error("a malformed trusted proxy was accepted")
	}
}

// The failure budget counts only failed authentications, refuses an exhausted
// address even with the right credentials, and says when to retry.
func TestGRPCFailureBudget(t *testing.T) {
	r := NewRateLimiter(2, time.Minute)
	fb := r.GRPCFailureBudget(func(ctx context.Context) string { return "addr" })
	call := func(result error) error {
		_, err := fb(context.Background(), nil, unaryInfo, func(context.Context, any) (any, error) { return nil, result })
		return err
	}
	for i := 0; i < 5; i++ {
		if err := call(nil); err != nil {
			t.Fatalf("a successful call was budgeted: %v", err)
		}
	}
	_ = call(status.Error(codes.Unauthenticated, "no"))
	_ = call(status.Error(codes.Unauthenticated, "no"))
	err := call(nil)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("after two failures: %v", err)
	}
	st, _ := status.FromError(err)
	var delay time.Duration
	for _, d := range st.Details() {
		if ri, ok := d.(*errdetails.RetryInfo); ok {
			delay = ri.GetRetryDelay().AsDuration()
		}
	}
	if delay < time.Second || delay > time.Minute {
		t.Errorf("retry delay = %v", delay)
	}
}

// The client id a call claims, read exactly as the HTTP door reads it.
func TestGRPCBasicClientID(t *testing.T) {
	basicOf := func(s string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte(s)) }
	for _, c := range []struct {
		md   []string
		want string
	}{
		{[]string{"authorization", basicOf("aci_1:secret")}, "aci_1"},
		{[]string{"authorization", basicOf("a+b:secret")}, "a b"},
		{[]string{"authorization", "Bearer x"}, ""},
		{nil, ""},
	} {
		ctx := context.Background()
		if len(c.md) > 0 {
			ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(c.md...))
		}
		if got := GRPCBasicClientID(ctx); got != c.want {
			t.Errorf("%v: %q, want %q", c.md, got, c.want)
		}
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", basicOf("a:b"), "authorization", basicOf("c:d")))
	if got := GRPCBasicClientID(ctx); got != "" {
		t.Errorf("two credentials claimed %q", got)
	}
}
