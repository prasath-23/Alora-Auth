package aloraauth

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/prasath-23/Alora-Auth/alora-auth-go/authpb"
)

// Config is an application's API client, and where to get its tokens.
type Config struct {
	// TokenAddress is App Central's gRPC address ("host:port"), where
	// TokenService answers. Ignored when Conn is set.
	TokenAddress string
	// Conn is a connection to App Central to use instead of dialling
	// TokenAddress: one the application already has, or a test's.
	Conn grpc.ClientConnInterface
	// ClientID and ClientSecret are the API client's credentials (aci_…, acc_…).
	ClientID     string
	ClientSecret string
	// Product is the key of the product the tokens are for.
	Product string
	// Scopes asks for some of the scopes the API client holds; none asks for
	// all of them.
	Scopes []string
	// Insecure allows plaintext: to App Central when dialling TokenAddress, and
	// on the calls the credentials are put on. Development only — a secret or a
	// token sent in the clear is anyone's.
	Insecure bool
	// TLS configures the connection to App Central when dialling TokenAddress.
	// nil: the system's roots, TLS 1.2 or later.
	TLS *tls.Config
}

// TokenCredentials puts a product token on every gRPC call: it is a
// credentials.PerRPCCredentials. It asks App Central for a token on first use,
// keeps it, and asks again shortly before it expires; calls made while a token
// is being fetched wait for that one request rather than each making their own.
type TokenCredentials struct {
	cfg    Config
	client authpb.TokenServiceClient
	closer io.Closer
	now    func() time.Time

	mu      sync.Mutex
	token   string
	renewAt time.Time
	pending *fetch
}

type fetch struct {
	done  chan struct{}
	token string
	err   error
}

// ClientCredentials builds the credentials. It dials App Central, unless Conn
// is given, without waiting for the connection; nothing is fetched until the
// first call.
func ClientCredentials(cfg Config) (*TokenCredentials, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.Product == "" {
		return nil, errors.New("aloraauth: ClientCredentials needs ClientID, ClientSecret and Product")
	}
	c := &TokenCredentials{cfg: cfg, now: time.Now}
	conn := cfg.Conn
	if conn == nil {
		if cfg.TokenAddress == "" {
			return nil, errors.New("aloraauth: ClientCredentials needs TokenAddress or Conn")
		}
		var creds credentials.TransportCredentials
		switch {
		case cfg.Insecure:
			creds = insecure.NewCredentials()
		case cfg.TLS != nil:
			creds = credentials.NewTLS(cfg.TLS)
		default:
			creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
		}
		cc, err := grpc.NewClient(cfg.TokenAddress, grpc.WithTransportCredentials(creds))
		if err != nil {
			return nil, fmt.Errorf("aloraauth: dialling App Central: %w", err)
		}
		conn, c.closer = cc, cc
	}
	c.client = authpb.NewTokenServiceClient(conn)
	return c, nil
}

// GetRequestMetadata puts the token on a call.
func (c *TokenCredentials) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	token, err := c.Token(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]string{"authorization": "Bearer " + token}, nil
}

// RequireTransportSecurity is true unless Config.Insecure: gRPC then refuses to
// send the token over a plaintext connection.
func (c *TokenCredentials) RequireTransportSecurity() bool { return !c.cfg.Insecure }

// Close closes the connection to App Central, when ClientCredentials dialled it.
func (c *TokenCredentials) Close() error {
	if c.closer != nil {
		return c.closer.Close()
	}
	return nil
}

// Token returns a current token, asking App Central for one when there is none
// or the one held is about to expire.
func (c *TokenCredentials) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.token != "" && c.now().Before(c.renewAt) {
		token := c.token
		c.mu.Unlock()
		return token, nil
	}
	f := c.pending
	if f == nil {
		f = &fetch{done: make(chan struct{})}
		c.pending = f
		// Not bound to this caller's context: one caller giving up must not fail
		// the others waiting on the same request.
		go c.get(f)
	}
	c.mu.Unlock()
	select {
	case <-f.done:
		return f.token, f.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// get asks App Central for a token, with the client's credentials in the call's
// metadata as client_secret_basic, and keeps it until a fifth of its life (at
// most a minute) is left.
func (c *TokenCredentials) get(f *fetch) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	basic := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(c.cfg.ClientID) + ":" + url.QueryEscape(c.cfg.ClientSecret)))
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Basic "+basic)
	res, err := c.client.GetToken(ctx, &authpb.GetTokenRequest{Resource: "product:" + c.cfg.Product, Scopes: c.cfg.Scopes})

	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending = nil
	switch {
	case err != nil:
		f.err = fmt.Errorf("aloraauth: getting a token: %w", err)
	case res.GetAccessToken() == "" || res.GetExpiresIn() <= 0:
		f.err = errors.New("aloraauth: App Central returned no usable token")
	default:
		life := time.Duration(res.GetExpiresIn()) * time.Second
		margin := min(life/5, time.Minute)
		c.token, c.renewAt = res.GetAccessToken(), c.now().Add(life-margin)
		f.token = c.token
	}
	close(f.done)
}
