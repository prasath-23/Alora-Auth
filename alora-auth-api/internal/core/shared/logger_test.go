package shared

import (
	"log/slog"
	"testing"
)

func TestRedactCensorsSensitiveKeys(t *testing.T) {
	// Includes mixed-case to confirm case-insensitive matching.
	keys := []string{"authorization", "Cookie", "Set-Cookie", "password", "token", "code", "code_verifier", "refresh_token",
		"access_token", "id_token", "client_secret", "Secret"}
	for _, k := range keys {
		got := redact(nil, slog.String(k, "super-secret-value"))
		if got.Value.String() != censor {
			t.Errorf("key %q not censored: got %q", k, got.Value.String())
		}
	}
}

func TestRedactPassesThroughNonSensitive(t *testing.T) {
	got := redact(nil, slog.String("user_id", "u-123"))
	if got.Value.String() != "u-123" {
		t.Errorf("non-sensitive value altered: %q", got.Value.String())
	}
}
