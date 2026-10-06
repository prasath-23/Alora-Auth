package aloraauth

import (
	"context"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	listItems = "/alora.demo.inventory.v1.InventoryService/ListItems"
	addItem   = "/alora.demo.inventory.v1.InventoryService/AddItem"
)

var demoRules = Rules{listItems: "grpc:read", addItem: "grpc:edit", "/x.Open/Any": ""}

func withBearer(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
}

func reasonOf(err error) (codes.Code, string, map[string]string) {
	st, _ := status.FromError(err)
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return st.Code(), info.GetReason(), info.GetMetadata()
		}
	}
	return st.Code(), "", nil
}

func TestUnaryInterceptor(t *testing.T) {
	s := newIssuer(t)
	v := newVerifierFor(t, s)
	intercept := v.UnaryServerInterceptor(demoRules)
	call := func(ctx context.Context, method string) (*Claims, error) {
		var seen *Claims
		_, err := intercept(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method}, func(ctx context.Context, _ any) (any, error) {
			seen, _ = ClaimsFrom(ctx)
			return nil, nil
		})
		return seen, err
	}

	// A token with the scope the method needs: through, with its claims.
	c, err := call(withBearer(s.token(t, nil)), listItems)
	if err != nil || c == nil || c.Subject != "aci_1" {
		t.Fatalf("a good call: %+v, %v", c, err)
	}
	// An empty rule admits any valid token.
	if _, err := call(withBearer(s.token(t, func(_, c map[string]any) { c["scope"] = "" })), "/x.Open/Any"); err != nil {
		t.Errorf("an open method: %v", err)
	}

	for _, r := range []struct {
		what   string
		ctx    context.Context
		method string
		code   codes.Code
		reason string
	}{
		{"no token", context.Background(), listItems, codes.Unauthenticated, "invalid_token"},
		{"not a bearer token", metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Basic eDp5")), listItems,
			codes.Unauthenticated, "invalid_token"},
		{"two tokens", metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer a", "authorization", "Bearer b")),
			listItems, codes.Unauthenticated, "invalid_token"},
		{"an invalid token", withBearer(s.token(t, func(_, c map[string]any) { c["aud"] = "product:OTHER" })), listItems,
			codes.Unauthenticated, "invalid_token"},
		{"a method with no rule", withBearer(s.token(t, nil)), "/grpc.health.v1.Health/Check", codes.PermissionDenied, "method_not_open"},
		{"a scope it lacks", withBearer(s.token(t, nil)), addItem, codes.PermissionDenied, "insufficient_scope"},
		{"a person's token", withBearer(s.token(t, func(_, c map[string]any) { c["principal"], c["scope"] = "user", "" })), listItems,
			codes.PermissionDenied, "insufficient_scope"},
	} {
		_, err := call(r.ctx, r.method)
		code, reason, md := reasonOf(err)
		if code != r.code || reason != r.reason {
			t.Errorf("%s: %v %q, want %v %q (%v)", r.what, code, reason, r.code, r.reason, err)
		}
		if r.reason == "insufficient_scope" && md["scope"] != demoRules[r.method] {
			t.Errorf("%s: the refusal names scope %q", r.what, md["scope"])
		}
	}
}

type fakeStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f *fakeStream) Context() context.Context { return f.ctx }

func TestStreamInterceptor(t *testing.T) {
	s := newIssuer(t)
	v := newVerifierFor(t, s)
	intercept := v.StreamServerInterceptor(demoRules)
	var seen *Claims
	handler := func(_ any, ss grpc.ServerStream) error {
		seen, _ = ClaimsFrom(ss.Context())
		return nil
	}
	if err := intercept(nil, &fakeStream{ctx: withBearer(s.token(t, nil))}, &grpc.StreamServerInfo{FullMethod: listItems}, handler); err != nil || seen == nil {
		t.Errorf("a good stream: %v %v", seen, err)
	}
	err := intercept(nil, &fakeStream{ctx: withBearer(s.token(t, nil))}, &grpc.StreamServerInfo{FullMethod: "/y.Stream/Unmapped"}, handler)
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("an unmapped stream: %v", err)
	}
}
