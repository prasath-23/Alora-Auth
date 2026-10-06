package aloraauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// HTTPClient asks App Central's token endpoint for client credentials the way
// it wants them — the credentials in the Authorization header, the product as
// resource — and puts the token on every request, reusing it.
func TestHTTPClient(t *testing.T) {
	var issued atomic.Int32
	central := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if r.URL.Path != "/oauth/token" || !ok || id != "aci_1" || secret != "acc_s" || r.FormValue("client_secret") != "" ||
			r.FormValue("grant_type") != "client_credentials" || r.FormValue("resource") != "product:INV" || r.FormValue("scope") != "api:read" {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		issued.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "token_type": "Bearer", "expires_in": 900, "scope": "api:read"})
	}))
	defer central.Close()
	var seen []string
	product := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
	}))
	defer product.Close()

	client := HTTPConfig{Issuer: central.URL + "/", ClientID: "aci_1", ClientSecret: "acc_s", Product: "INV", Scopes: []string{"api:read"}}.Client(t.Context())
	for i := 0; i < 2; i++ {
		res, err := client.Get(product.URL + "/api/items")
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
	}
	if len(seen) != 2 || seen[0] != "Bearer tok" || seen[1] != "Bearer tok" {
		t.Errorf("the product saw %v", seen)
	}
	if n := issued.Load(); n != 1 {
		t.Errorf("%d tokens issued for two calls", n)
	}
}
