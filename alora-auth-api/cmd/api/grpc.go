package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"

	"github.com/prasath-23/Alora-Auth/alora-auth-go/authpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"

	"github.com/alora/auth/internal/config"
	"github.com/alora/auth/internal/middlewares"
)

// grpcMaxMessage bounds a gRPC message, as BodyLimit bounds an HTTP body: a
// token request is a few hundred bytes, a token a kilobyte or two.
const grpcMaxMessage = 64 << 10

// newGRPCServer assembles App Central's gRPC server: TokenService, where
// applications get tokens with client credentials, and the standard health
// service. Extracted from run() like newRouter, so tests exercise the real
// server and its interceptor chain.
//
// The interceptors run in the HTTP chain's order: a request id first, recovery,
// the log line, shedding under memory pressure, then the token endpoint's
// budgets — the same limiters the HTTP door uses, keyed the same way.
func newGRPCServer(cfg *config.Config, log *slog.Logger, m *modules) (*grpc.Server, error) {
	addr, err := middlewares.GRPCClientIP(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(grpcMaxMessage),
		grpc.MaxSendMsgSize(grpcMaxMessage),
		// One application needs a handful of concurrent calls, not thousands.
		grpc.MaxConcurrentStreams(64),
		// A connection that never finishes its handshake is dropped (slowloris).
		grpc.ConnectionTimeout(10 * time.Second),
		// Idle and long-lived connections are recycled, and a client pinging more
		// often than every 30 seconds is told to stop.
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 5 * time.Minute, MaxConnectionAge: 30 * time.Minute,
			MaxConnectionAgeGrace: 15 * time.Second, Time: 2 * time.Minute, Timeout: 20 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 30 * time.Second}),
		grpc.ChainUnaryInterceptor(
			middlewares.GRPCRequestID(),
			middlewares.GRPCRecover(log),
			middlewares.GRPCLog(log, addr),
			middlewares.GRPCUnderPressure(m.pressure),
			m.tokenFailures.GRPCFailureBudget(addr),
			m.tokenClients.GRPCBudget(func(ctx context.Context) string {
				return addr(ctx) + "|" + middlewares.GRPCBasicClientID(ctx)
			}),
		),
		grpc.ChainStreamInterceptor(middlewares.GRPCStreamRecover(log)),
	}
	if cfg.GRPC.TLS() {
		cert, err := tls.LoadX509KeyPair(cfg.GRPC.TLSCertFile, cfg.GRPC.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("grpc: GRPC_TLS_CERT / GRPC_TLS_KEY: %w", err)
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
		})))
	}

	s := grpc.NewServer(opts...)
	authpb.RegisterTokenServiceServer(s, m.tokenGRPC)
	h := health.NewServer()
	h.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	h.SetServingStatus(authpb.TokenService_ServiceDesc.ServiceName, healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(s, h)
	// Reflection lets grpcurl discover the services: a convenience in development,
	// free reconnaissance in production (as /docs is).
	if !cfg.IsProd {
		reflection.Register(s)
	}
	return s, nil
}
