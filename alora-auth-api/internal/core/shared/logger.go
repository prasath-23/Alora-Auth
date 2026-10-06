// Package shared holds the utilities common to the feature modules: the
// application logger, strict JSON binding, and signed cookies.
//
// The logger's redaction is a security control: any attribute whose key is
// sensitive (auth/cookie headers or secret body fields) is replaced with
// [REDACTED] wherever it appears, mirroring the Node pino redact config. Query
// logging is never enabled (queries carry hashed tokens).
package shared

import (
	"log/slog"
	"os"
	"strings"
)

const censor = "[REDACTED]"

// Keys that must never be logged in the clear (lowercased for case-insensitive match).
var sensitiveKeys = map[string]struct{}{
	"authorization": {},
	"cookie":        {},
	"set-cookie":    {},
	"password":      {},
	"token":         {},
	"code":          {},
	"code_verifier": {},
	"refresh_token": {},
	"access_token":  {},
	"id_token":      {},
	"client_secret": {},
	"secret":        {},
}

// NewLogger returns a logger: text (human) in dev at debug level, JSON in prod at info.
func NewLogger(isProd bool) *slog.Logger {
	level := slog.LevelDebug
	if isProd {
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level, ReplaceAttr: redact}

	var h slog.Handler
	if isProd {
		h = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(h)
}

// redact censors sensitive attribute values regardless of nesting group.
func redact(_ []string, a slog.Attr) slog.Attr {
	if _, ok := sensitiveKeys[strings.ToLower(a.Key)]; ok {
		return slog.String(a.Key, censor)
	}
	return a
}
