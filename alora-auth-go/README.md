# alora-auth-go

What products and applications build against when they use App Central's
tokens — with none of App Central's own dependencies.

```
go get github.com/prasath-23/Alora-Auth/alora-auth-go
```

| Package | What it is |
|---|---|
| `authpb` | App Central's gRPC `TokenService`, generated from `proto/alora/auth/v1/token.proto` |
| `aloraauth` | The Go helper: tokens for applications, token checks for products |
| `examples/grpcdemo` | A demo product (a gRPC inventory) and a demo application that calls it |

## The two kinds of product token

A product receives tokens of two kinds, both with the audience `product:<key>`,
both signed by App Central (RS256, `typ: at+jwt`, keys at
`/.well-known/jwks.json`):

| | A person's | An application's |
|---|---|---|
| Issued by | the product's own sign-in (the code flow) | client credentials, to an API client |
| `principal` | `user` | `client` |
| `sub` | the person | the API client (`aci_…`) |
| What it may do | `roles` (in this product) | `scope`: `api:read` `api:edit` (REST), `grpc:read` `grpc:edit` (gRPC), `mcp:tools` (MCP) |
| Lifetime | 15 minutes, renewed with a refresh token | 15 minutes; the application asks again |

An API client gets a token only for a product on its list that the Owner has
switched to *Accepts API clients*, and only for scopes it holds (an edit scope
brings its read scope).

## Applications: getting a token

### gRPC

`ClientCredentials` asks App Central's gRPC `TokenService` for a token with the
API client's id and secret, keeps it, renews it shortly before it expires (a
fifth of its life before, at most a minute), and puts it on every call.
Concurrent calls share one request.

```go
creds, err := aloraauth.ClientCredentials(aloraauth.Config{
	TokenAddress: "central.example.com:443",        // App Central's gRPC port
	ClientID:     os.Getenv("ALORA_CLIENT_ID"),     // aci_…
	ClientSecret: os.Getenv("ALORA_CLIENT_SECRET"), // acc_…
	Product:      "INVENTORY",
	Scopes:       []string{"grpc:read"},            // optional: all it holds by default
})
if err != nil { … }
defer creds.Close()

conn, err := grpc.NewClient("inventory.example.com:443",
	grpc.WithTransportCredentials(credentials.NewTLS(nil)),
	grpc.WithPerRPCCredentials(creds))
```

The credentials refuse to travel over plaintext. `Insecure: true` allows it —
for development only, since a secret or a token in the clear is anyone's.

### HTTP

```go
client := aloraauth.HTTPConfig{
	Issuer:       "https://central.example.com",
	ClientID:     os.Getenv("ALORA_CLIENT_ID"),
	ClientSecret: os.Getenv("ALORA_CLIENT_SECRET"),
	Product:      "INVENTORY",
	Scopes:       []string{"api:read"},
}.Client(ctx)
res, err := client.Get("https://inventory.example.com/api/items")
```

Or by hand, with any HTTP client:

```sh
curl -s https://central.example.com/oauth/token \
  -u "$ALORA_CLIENT_ID:$ALORA_CLIENT_SECRET" \
  -d grant_type=client_credentials -d resource=product:INVENTORY
```

## Products: checking a token

A `Verifier` checks the signature against App Central's published keys
(fetched and cached; an unknown key id refetches them, at most once a minute;
a key App Central stops publishing stops being accepted), pins RS256, and
checks the issuer, the audience `product:<key>`, the expiry and the type.

```go
v, err := aloraauth.NewVerifier(aloraauth.VerifierConfig{
	Issuer:  "https://central.example.com", // exactly as its tokens name it
	Product: "INVENTORY",
})
claims, err := v.Verify(ctx, token) // errors.Is(err, aloraauth.ErrInvalidToken)
```

### gRPC

The interceptors demand a scope for each method and **deny every method they
were not told about**, so a service added to the server stays closed until
someone decides who may call it.

```go
srv := grpc.NewServer(
	grpc.UnaryInterceptor(v.UnaryServerInterceptor(aloraauth.Rules{
		inventorypb.InventoryService_ListItems_FullMethodName: "grpc:read",
		inventorypb.InventoryService_AddItem_FullMethodName:   "grpc:edit",
	})),
	grpc.StreamInterceptor(v.StreamServerInterceptor(aloraauth.Rules{})), // no stream open
)

func (s *server) ListItems(ctx context.Context, _ *inventorypb.ListItemsRequest) (…) {
	claims, _ := aloraauth.ClaimsFrom(ctx) // claims.Subject is the API client
	…
}
```

A refusal is `Unauthenticated` (no token, or an invalid one) or
`PermissionDenied` (a method with no rule, or a scope the token lacks), with a
`google.rpc.ErrorInfo` whose reason is `invalid_token`, `method_not_open` or
`insufficient_scope`.

### REST, and MCP

`RequireScope` is the same check for an HTTP handler, answering as RFC 6750
says (401 `invalid_token`, 403 `insufficient_scope`):

```go
mux.Handle("GET /api/items", v.RequireScope("api:read", listItems))
mux.Handle("POST /api/items", v.RequireScope("api:edit", addItem))
```

An MCP server over HTTP is a product endpoint like any other; its tools are for
applications holding `mcp:tools`:

```go
// Only an AI agent's API client given "MCP tools" in App Central gets through.
mux.Handle("/mcp", v.RequireScope("mcp:tools", mcpServer))

// Inside a tool, the caller is known:
claims, _ := aloraauth.ClaimsFrom(r.Context())
log.Printf("tool called by %s of company %s", claims.Subject, claims.TenantID)
```

A person's token carries roles, not scopes: check `claims.HasRole(…)` where
people call the product.

## The demo

```sh
# The product: an inventory, checking every call with the helper.
go run ./examples/grpcdemo/server -issuer http://localhost:5173 -product INVENTORY -addr 127.0.0.1:4200

# The application: an API client with INVENTORY on its list and grpc:read.
ALORA_CLIENT_SECRET=acc_… go run ./examples/grpcdemo/client \
  -central 127.0.0.1:3002 -client-id aci_… -product INVENTORY \
  -addr 127.0.0.1:4200 -insecure list
# {"caller":"aci_…","items":[{"id":1,"name":"Pallet jack"},…]}

ALORA_CLIENT_SECRET=acc_… go run ./examples/grpcdemo/client … add Forklift
# {"code":"PermissionDenied","message":"this method needs the scope grpc:edit","reason":"insufficient_scope"}
```

The Playwright suite (`alora-auth-ui/e2e/grpc.spec.js`) runs exactly this
against a live App Central.

## Keep-alives

App Central's gRPC server tells a client that pings more often than every 30
seconds to stop. Leave gRPC's client keep-alive off, or set it to 30 seconds or
more.

## Regenerating the code

The generated code is checked in, so `go get` needs no tools. After changing a
proto:

```sh
bash scripts/generate.sh   # buf 1.73.0, protoc-gen-go v1.36.12, protoc-gen-go-grpc 1.6.2
```

It installs those exact versions into `.bin/`, lints the protos
(`buf lint`) and regenerates. `scripts/check-generated.sh` at the repository
root fails when the checked-in code differs from what the protos produce.

This module never imports App Central (`cmd/api`'s architecture test holds it
to that).
