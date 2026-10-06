package controller

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A token request the database refuses as text it cannot store is the
// caller's mistake over gRPC too: InvalidArgument with invalid_request, never
// Internal — whatever check before it let the text through.
func TestTheGRPCDoorMapsUnstorableTextToInvalidArgument(t *testing.T) {
	h := &TokenGRPC{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, c := range []struct {
		err    error
		code   codes.Code
		reason string
	}{
		{&pgconn.PgError{Code: "22021"}, codes.InvalidArgument, "invalid_request"},
		{&pgconn.PgError{Code: "22P05"}, codes.InvalidArgument, "invalid_request"},
		{errors.New("something broke"), codes.Internal, ""},
	} {
		st, _ := status.FromError(h.fail(context.Background(), c.err))
		reason := ""
		for _, d := range st.Details() {
			if info, ok := d.(*errdetails.ErrorInfo); ok {
				reason = info.GetReason()
			}
		}
		if st.Code() != c.code || reason != c.reason {
			t.Errorf("fail(%v) = %v %q, want %v %q", c.err, st.Code(), reason, c.code, c.reason)
		}
	}
}
