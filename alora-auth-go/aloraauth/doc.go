// Package aloraauth is the Go helper for applications and products that use App
// Central's tokens.
//
// # Applications
//
// An application — a sync job, a backend, an agent: anything with no person
// behind it — calls a product with a token App Central issued to its API client
// (the client-credentials grant). ClientCredentials gets that token from App
// Central's gRPC TokenService, keeps it, renews it shortly before it expires,
// and puts it on every call:
//
//	creds, err := aloraauth.ClientCredentials(aloraauth.Config{
//		TokenAddress: "central.example.com:443", // App Central's gRPC port
//		ClientID:     os.Getenv("ALORA_CLIENT_ID"),     // aci_…
//		ClientSecret: os.Getenv("ALORA_CLIENT_SECRET"), // acc_…
//		Product:      "INVENTORY",
//	})
//	conn, err := grpc.NewClient("inventory.example.com:443",
//		grpc.WithTransportCredentials(credentials.NewTLS(nil)),
//		grpc.WithPerRPCCredentials(creds))
//
// HTTPConfig does the same over HTTP, with App Central's token endpoint, for an
// application calling a product's REST API.
//
// # Products
//
// A product checks every token it receives with a Verifier: App Central's
// signing keys, fetched and cached (an unknown key id refreshes them, at most
// once a minute); RS256 and nothing else; the issuer; the audience, which is
// the product's own "product:<key>"; the expiry; and the type, an access token.
// Claims then says who the token speaks for — a person ("user", with roles) or
// an application ("client", with scopes).
//
// For gRPC, the Verifier's interceptors demand a scope for each method and deny
// every method they were not told about, so a service added to the server is
// closed until someone decides who may call it:
//
//	v, err := aloraauth.NewVerifier(aloraauth.VerifierConfig{
//		Issuer:  "https://central.example.com",
//		Product: "INVENTORY",
//	})
//	srv := grpc.NewServer(
//		grpc.UnaryInterceptor(v.UnaryServerInterceptor(aloraauth.Rules{
//			"/alora.demo.inventory.v1.InventoryService/ListItems": "grpc:read",
//			"/alora.demo.inventory.v1.InventoryService/AddItem":   "grpc:edit",
//		})))
//
// A handler reads the caller from its context with ClaimsFrom.
package aloraauth
