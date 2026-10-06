package controller

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/prasath-23/Alora-Auth/alora-auth-go/authpb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/alora/auth/internal/core/oauth/models"
	"github.com/alora/auth/internal/core/oauth/service"
	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/exceptions"
	"github.com/alora/auth/internal/middlewares"
)

// TokenGRPC serves TokenService: the client-credentials grant over gRPC. It
// authenticates the call and issues the token through the SAME service calls as
// POST /oauth/token, so the rules cannot drift apart between the two doors.
type TokenGRPC struct {
	authpb.UnimplementedTokenServiceServer
	svc service.OAuthService
	log *slog.Logger
}

// NewTokenGRPC builds the gRPC handler.
func NewTokenGRPC(svc service.OAuthService, log *slog.Logger) *TokenGRPC {
	return &TokenGRPC{svc: svc, log: log}
}

// ErrorDomain names App Central in a failure's google.rpc.ErrorInfo; the
// reason beside it is the OAuth error code.
const ErrorDomain = "auth.alora.io"

// GetToken issues an API client a token for one product on its list. Its
// credentials are the call's authorization metadata — client_secret_basic, as
// over HTTP — exactly once.
func (h *TokenGRPC) GetToken(ctx context.Context, req *authpb.GetTokenRequest) (*authpb.GetTokenResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	auth := md.Get("authorization")
	if len(auth) != 1 {
		return nil, h.fail(ctx, models.InvalidClientError())
	}
	id, secret, ok := basicAuth(auth[0])
	if !ok {
		return nil, h.fail(ctx, models.InvalidClientError())
	}
	client, err := h.svc.Authenticate(ctx, id, secret)
	if err != nil {
		return nil, h.fail(ctx, err)
	}
	if !shared.Storable(req.GetResource()) || !shared.AllStorable(req.GetScopes()) {
		return nil, h.fail(ctx, models.InvalidRequestError("resource and scopes must be text without NUL characters"))
	}
	set, err := h.svc.ClientCredentials(ctx, client, req.GetResource(), strings.Join(req.GetScopes(), " "))
	if err != nil {
		return nil, h.fail(ctx, err)
	}
	return &authpb.GetTokenResponse{
		AccessToken: set.AccessToken, TokenType: "Bearer", ExpiresIn: int32(set.ExpiresIn), Scopes: strings.Fields(set.Scope),
	}, nil
}

// grpcCodes is the status each OAuth error answers with: failed credentials
// are Unauthenticated, what the client may not have is PermissionDenied, and a
// request it could correct is InvalidArgument.
var grpcCodes = map[string]codes.Code{
	"invalid_client":      codes.Unauthenticated,
	"unauthorized_client": codes.PermissionDenied,
	"invalid_target":      codes.PermissionDenied,
	"invalid_scope":       codes.InvalidArgument,
	"invalid_request":     codes.InvalidArgument,
}

// fail renders an OAuth error as a gRPC status carrying the OAuth error code as
// its ErrorInfo reason. Anything else is a server fault: logged here, with the
// call's request id, and answered with a bare Internal.
func (h *TokenGRPC) fail(ctx context.Context, err error) error {
	var oe *models.Error
	if !errors.As(err, &oe) {
		if exceptions.IsUnstorableText(err) {
			oe = models.InvalidRequestError("the request holds text that cannot be stored")
		} else {
			h.log.Error("token over gRPC failed", "err", err, "reqId", middlewares.GRPCRequestIDFrom(ctx))
			return status.Error(codes.Internal, "internal error")
		}
	}
	code, ok := grpcCodes[oe.Code]
	if !ok {
		code = codes.InvalidArgument
	}
	st := status.New(code, oe.Description)
	if d, err := st.WithDetails(&errdetails.ErrorInfo{Reason: oe.Code, Domain: ErrorDomain}); err == nil {
		return d.Err()
	}
	return st.Err()
}
