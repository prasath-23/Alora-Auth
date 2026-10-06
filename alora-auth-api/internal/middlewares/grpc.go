package middlewares

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

// gRPC. App Central's gRPC server (cmd/api/grpc.go) runs these interceptors in
// the same order and to the same effect as the HTTP chain: a request id,
// recovery, a log line, shedding under memory pressure, then the token
// endpoint's own budgets — the SAME limiters the HTTP door uses, keyed the same
// way, so an application's HTTP and gRPC calls draw on one budget.

type grpcKey int

const grpcRequestID grpcKey = 0

// GRPCRequestIDFrom returns the call's request id, or "" outside the chain.
func GRPCRequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(grpcRequestID).(string)
	return id
}

// GRPCRequestID gives every call a fresh request id, in its context and back to
// the caller in the x-request-id header. An inbound id is ignored, as over HTTP:
// a caller must not choose what its call is logged as.
func GRPCRequestID() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		id := uuid.NewString()
		_ = grpc.SetHeader(ctx, metadata.Pairs("x-request-id", id))
		return handler(context.WithValue(ctx, grpcRequestID, id), req)
	}
}

// GRPCRecover turns a panic in a handler into Internal, logged with its stack:
// never a crashed process, and never the panic's text sent to the caller.
func GRPCRecover(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Error("panic in a gRPC call", "method", info.FullMethod, "reqId", GRPCRequestIDFrom(ctx),
					"panic", fmt.Sprint(r), "stack", string(debug.Stack()))
				resp, err = nil, status.Error(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}

// GRPCStreamRecover is GRPCRecover for streaming calls (the health service's
// Watch).
func GRPCStreamRecover(log *slog.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				log.Error("panic in a gRPC stream", "method", info.FullMethod, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
				err = status.Error(codes.Internal, "internal error")
			}
		}()
		return handler(srv, ss)
	}
}

// GRPCLog logs one line per call: its method, outcome, duration and address.
// Never its metadata or its messages, which carry client secrets and tokens.
// A refusal is ordinary traffic (debug); a server fault is an error.
func GRPCLog(log *slog.Logger, addr func(context.Context) string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		code := status.Code(err)
		level := slog.LevelDebug
		if code == codes.Internal || code == codes.Unknown || code == codes.DataLoss {
			level = slog.LevelError
		}
		log.Log(ctx, level, "grpc call", "method", info.FullMethod, "code", code.String(),
			"ms", time.Since(start).Milliseconds(), "ip", addr(ctx), "reqId", GRPCRequestIDFrom(ctx))
		return resp, err
	}
}

// GRPCUnderPressure sheds every call with Unavailable while memory is over its
// ceiling, before authentication or a handler spends anything on it.
func GRPCUnderPressure(m PressureMonitor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if m.Overloaded() {
			return nil, withRetry(codes.Unavailable, "overloaded; retry later", 10*time.Second)
		}
		return handler(ctx, req)
	}
}

// GRPCBudget spends one unit of the limiter per call, keyed by keyFn: the key
// the HTTP door uses for the same budget, so the two share it.
func (r *RateLimiter) GRPCBudget(keyFn func(context.Context) string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if ok, retry := r.Allow(ctx, keyFn(ctx)); !ok {
			return nil, withRetry(codes.ResourceExhausted, "too many requests", retry)
		}
		return handler(ctx, req)
	}
}

// GRPCFailureBudget budgets FAILED client authentications per address, as
// LimitFailures does over HTTP: once an address has failed max times in the
// window, its calls are refused until the window resets, while calls that
// authenticate cost nothing.
func (r *RateLimiter) GRPCFailureBudget(addr func(context.Context) string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		key := addr(ctx)
		if blocked, retry := r.exhausted(ctx, key); blocked {
			return nil, withRetry(codes.ResourceExhausted, "too many failed authentications", retry)
		}
		resp, err := handler(ctx, req)
		if status.Code(err) == codes.Unauthenticated {
			r.Allow(ctx, key) // counts the failure; the verdict applies to the next call
		}
		return resp, err
	}
}

// withRetry is a status telling the caller when to try again
// (google.rpc.RetryInfo), floored at a second as Retry-After is.
func withRetry(code codes.Code, msg string, retry time.Duration) error {
	if retry < time.Second {
		retry = time.Second
	}
	st := status.New(code, msg)
	if d, err := st.WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(retry)}); err == nil {
		return d.Err()
	}
	return st.Err()
}

// GRPCBasicClientID is the client id a call's authorization metadata claims —
// for keying the per-client budget exactly as the HTTP door keys it.
func GRPCBasicClientID(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	if v := md.Get("authorization"); len(v) == 1 {
		return BasicClientID(v[0])
	}
	return ""
}

// GRPCClientIP returns the address a call came from: its peer's IP, or — when
// the peer is one of the trusted proxies — the right-most address in
// x-forwarded-for that is not itself a trusted proxy, as gin decides over HTTP.
// With no trusted proxies (the default) a forwarded address is never believed.
func GRPCClientIP(trusted []string) (func(context.Context) string, error) {
	nets := make([]*net.IPNet, 0, len(trusted))
	for _, t := range trusted {
		if !strings.Contains(t, "/") {
			if ip := net.ParseIP(t); ip != nil && ip.To4() != nil {
				t += "/32"
			} else {
				t += "/128"
			}
		}
		_, n, err := net.ParseCIDR(t)
		if err != nil {
			return nil, fmt.Errorf("grpc: trusted proxy %q: %w", t, err)
		}
		nets = append(nets, n)
	}
	isTrusted := func(ip net.IP) bool {
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	return func(ctx context.Context) string {
		p, ok := peer.FromContext(ctx)
		if !ok || p.Addr == nil {
			return ""
		}
		host, _, err := net.SplitHostPort(p.Addr.String())
		if err != nil {
			host = p.Addr.String()
		}
		ip := net.ParseIP(host)
		if ip == nil || !isTrusted(ip) {
			return host
		}
		md, _ := metadata.FromIncomingContext(ctx)
		hops := []string{}
		for _, v := range md.Get("x-forwarded-for") {
			hops = append(hops, strings.Split(v, ",")...)
		}
		for i := len(hops) - 1; i >= 0; i-- {
			hop := net.ParseIP(strings.TrimSpace(hops[i]))
			if hop == nil {
				break // a garbled chain: believe only the peer
			}
			if !isTrusted(hop) {
				return hop.String()
			}
		}
		return host
	}, nil
}
