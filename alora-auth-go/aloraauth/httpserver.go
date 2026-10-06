package aloraauth

import (
	"context"
	"net/http"
	"strings"
)

// RequireScope admits an HTTP request only with a valid bearer token for this
// product that carries scope — for a product's REST API ("api:read",
// "api:edit") or its MCP endpoint ("mcp:tools"). An empty scope admits any
// valid token. Refusals follow RFC 6750: 401 with error="invalid_token" for a
// missing or invalid token, 403 with error="insufficient_scope" and the scope
// needed. The handler finds the claims with ClaimsFrom(r.Context()).
func (v *Verifier) RequireScope(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
			challenge(w, http.StatusUnauthorized, `Bearer error="invalid_token"`)
			return
		}
		claims, err := v.Verify(r.Context(), strings.TrimSpace(token))
		if err != nil {
			challenge(w, http.StatusUnauthorized, `Bearer error="invalid_token"`)
			return
		}
		if scope != "" && !claims.HasScope(scope) {
			challenge(w, http.StatusForbidden, `Bearer error="insufficient_scope", scope="`+scope+`"`)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, claims)))
	})
}

func challenge(w http.ResponseWriter, status int, value string) {
	w.Header().Set("WWW-Authenticate", value)
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(status), status)
}
