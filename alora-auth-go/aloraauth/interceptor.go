package aloraauth

import (
	"context"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Rules maps each gRPC method a product serves — its full name,
// "/package.Service/Method" — to the scope a call of it needs. A method with no
// rule is refused, whatever the token: a service added to the server stays
// closed until someone decides who may call it. An empty scope admits any valid
// token for the product; say so only on purpose.
type Rules map[string]string

// ErrorDomain names App Central's helper in a refusal's google.rpc.ErrorInfo.
const ErrorDomain = "auth.alora.io"

type claimsKey struct{}

// ClaimsFrom returns the verified claims of the call being handled, put there
// by the Verifier's interceptors.
func ClaimsFrom(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(*Claims)
	return c, ok
}

// UnaryServerInterceptor admits a call only with a valid bearer token for this
// product, for a method that has a rule, carrying the rule's scope. A missing
// or invalid token is Unauthenticated; anything else refused is
// PermissionDenied. The handler finds the claims with ClaimsFrom.
func (v *Verifier) UnaryServerInterceptor(rules Rules) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, err := v.authorize(ctx, rules, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor is UnaryServerInterceptor for streaming calls.
func (v *Verifier) StreamServerInterceptor(rules Rules) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := v.authorize(ss.Context(), rules, info.FullMethod)
		if err != nil {
			return err
		}
		return handler(srv, &authorizedStream{ServerStream: ss, ctx: ctx})
	}
}

type authorizedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authorizedStream) Context() context.Context { return s.ctx }

func (v *Verifier) authorize(ctx context.Context, rules Rules, method string) (context.Context, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	auth := md.Get("authorization")
	if len(auth) != 1 {
		return nil, refuse(codes.Unauthenticated, "invalid_token", "a bearer token is required", "")
	}
	scheme, token, ok := strings.Cut(auth[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return nil, refuse(codes.Unauthenticated, "invalid_token", "a bearer token is required", "")
	}
	claims, err := v.Verify(ctx, strings.TrimSpace(token))
	if err != nil {
		// The reason stays here: telling the caller why a token failed helps
		// only whoever is forging one.
		return nil, refuse(codes.Unauthenticated, "invalid_token", "the token is not valid for this product", "")
	}
	scope, mapped := rules[method]
	if !mapped {
		return nil, refuse(codes.PermissionDenied, "method_not_open", "this method is not open to tokens", "")
	}
	if scope != "" && !claims.HasScope(scope) {
		return nil, refuse(codes.PermissionDenied, "insufficient_scope", "this method needs the scope "+scope, scope)
	}
	return context.WithValue(ctx, claimsKey{}, claims), nil
}

// refuse is a status carrying the reason as ErrorInfo, and the scope a call
// lacked when that is why.
func refuse(code codes.Code, reason, msg, scope string) error {
	info := &errdetails.ErrorInfo{Reason: reason, Domain: ErrorDomain}
	if scope != "" {
		info.Metadata = map[string]string{"scope": scope}
	}
	st := status.New(code, msg)
	if d, err := st.WithDetails(info); err == nil {
		return d.Err()
	}
	return st.Err()
}
