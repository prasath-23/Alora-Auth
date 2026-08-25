// Package jwtkeys is the RS256 signing keystore. Keys are loaded once at startup
// and indexed by kid to support overlapping rotation (deploy a new kid, keep the
// old one verifying for a grace window, then retire). Verification pins RS256 and
// resolves the key by kid, so algorithm-confusion (alg=none/HS256) is rejected.
package jwtkeys

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// minModulusBits is the smallest RSA key this will load. jwx's own key
// validation checks structure, not strength, so without this a 512-bit key is
// accepted and then PUBLISHED through the JWKS endpoint — where anyone can take
// it, factor it (hours on a laptop for 512-bit, and 1024 is no longer a serious
// obstacle), and mint tokens for any user in any tenant. There is no detection
// story for that: the forgeries are valid signatures.
//
// 2048 is the floor rather than the recommendation. The cost of refusing a weak
// key is a failed deploy with a clear message; the cost of accepting one is
// silent total compromise.
const minModulusBits = 2048

type keyPair struct {
	priv *rsa.PrivateKey
	pub  *rsa.PublicKey
}

var (
	mu        sync.RWMutex
	keys      = map[string]keyPair{}
	activeKid string
	issuer    string
)

// Init loads a PKCS8 private / PKIX public RS256 keypair under kid and marks it
// active. Call once at startup; call again to register additional (rotated) kids.
func Init(privatePEM, publicPEM, kid, iss string) error {
	priv, err := parsePrivate(privatePEM)
	if err != nil {
		return fmt.Errorf("jwtkeys: private key: %w", err)
	}
	pub, err := parsePublic(publicPEM)
	if err != nil {
		return fmt.Errorf("jwtkeys: public key: %w", err)
	}
	if n := priv.N.BitLen(); n < minModulusBits {
		return fmt.Errorf("jwtkeys: private key is %d-bit, minimum is %d: a key this small can be "+
			"factored from the public half published at /.well-known/jwks.json", n, minModulusBits)
	}
	if n := pub.N.BitLen(); n < minModulusBits {
		return fmt.Errorf("jwtkeys: public key is %d-bit, minimum is %d", n, minModulusBits)
	}
	// Mismatched halves are a deployment mistake that otherwise surfaces as a
	// system where every login succeeds and every authenticated request is then
	// rejected -- signed with one key, verified against another. Catch it at
	// startup, where the message can name the cause.
	if !priv.PublicKey.Equal(pub) {
		return errors.New("jwtkeys: public key is not the private key's counterpart; " +
			"tokens would be signed with one key and verified against another")
	}
	mu.Lock()
	keys[kid] = keyPair{priv: priv, pub: pub}
	activeKid = kid
	issuer = iss
	mu.Unlock()
	return nil
}

func parsePrivate(p string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return rk, nil
}

func parsePublic(p string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return rk, nil
}

// Sign issues an RS256 JWT with registered claims (iss, iat, exp, jti) plus the
// given subject and private claims. audience is set only when non-empty. The
// protected header carries kid + typ=JWT.
func Sign(subject string, claims map[string]any, ttl time.Duration, audience []string) (string, error) {
	mu.RLock()
	kp, ok := keys[activeKid]
	kid, iss := activeKid, issuer
	mu.RUnlock()
	if !ok {
		return "", errors.New("jwtkeys: not initialized")
	}

	if ttl <= 0 {
		return "", errors.New("jwtkeys: ttl must be positive")
	}

	now := time.Now()
	b := jwt.NewBuilder()

	// Private claims are applied FIRST, and any reserved name is refused outright.
	// Later Claim() calls win in jwx, so applying the caller's map after the
	// registered claims would let a caller override exp/sub/iss/jti and mint a
	// never-expiring token that survives logout, family burn and the pv bump.
	for k, v := range claims {
		if isReservedClaim(k) {
			return "", fmt.Errorf("jwtkeys: private claim %q collides with a reserved claim", k)
		}
		b = b.Claim(k, v)
	}

	b = b.Issuer(iss).
		Subject(subject).
		IssuedAt(now).
		Expiration(now.Add(ttl)).
		JwtID(uuid.NewString())
	if len(audience) > 0 {
		b = b.Claim(jwt.AudienceKey, audience)
	}
	tok, err := b.Build()
	if err != nil {
		return "", err
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, kid)
	_ = hdrs.Set(jws.TypeKey, "JWT")

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, kp.priv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// keyProvider resolves the verification key by the token's kid and pins RS256,
// so a token claiming alg=none/HS256 can never be verified with our RSA key.
// reservedClaims are the registered JWT claims this package controls. A private
// claim may never shadow one of these (see Sign).
var reservedClaims = map[string]struct{}{
	jwt.IssuerKey:     {},
	jwt.SubjectKey:    {},
	jwt.AudienceKey:   {},
	jwt.ExpirationKey: {},
	jwt.IssuedAtKey:   {},
	jwt.NotBeforeKey:  {},
	jwt.JwtIDKey:      {},
}

func isReservedClaim(k string) bool {
	_, ok := reservedClaims[k]
	return ok
}

type keyProvider struct{}

func (keyProvider) FetchKeys(_ context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
	kid := sig.ProtectedHeaders().KeyID()
	if kid == "" {
		return errors.New("missing kid")
	}
	mu.RLock()
	kp, ok := keys[kid]
	mu.RUnlock()
	if !ok {
		return errors.New("unknown kid")
	}
	sink.Key(jwa.RS256, kp.pub)
	return nil
}

// Verify parses and validates an RS256 token: kid-resolved key, pinned RS256,
// issuer match, 5s clock skew, and required claims [sub, exp, iat, iss].
// audience is enforced only when non-empty.
func Verify(token string, audience string) (jwt.Token, error) {
	mu.RLock()
	iss := issuer
	mu.RUnlock()

	opts := []jwt.ParseOption{
		jwt.WithKeyProvider(keyProvider{}),
		jwt.WithValidate(true),
		jwt.WithIssuer(iss),
		jwt.WithAcceptableSkew(5 * time.Second),
	}
	if audience != "" {
		opts = append(opts, jwt.WithAudience(audience))
	}
	tok, err := jwt.Parse([]byte(token), opts...)
	if err != nil {
		return nil, err
	}
	// Required-claim recheck. Expiration/IssuedAt are compared against the Unix
	// epoch, NOT IsZero(): time.Unix(0,0).IsZero() is false (IsZero means year 1),
	// so an `exp: 0` sentinel would slip past an IsZero() guard.
	if tok.Subject() == "" || tok.Issuer() == "" ||
		tok.Expiration().Unix() <= 0 || tok.IssuedAt().Unix() <= 0 {
		return nil, errors.New("missing or invalid required claim")
	}
	return tok, nil
}

// JWKS returns the public JWK Set (all kids), each marked use=sig, alg=RS256.
func JWKS() ([]byte, error) {
	set := jwk.NewSet()
	mu.RLock()
	defer mu.RUnlock()
	for kid, kp := range keys {
		key, err := jwk.FromRaw(kp.pub)
		if err != nil {
			return nil, err
		}
		_ = key.Set(jwk.KeyIDKey, kid)
		_ = key.Set(jwk.KeyUsageKey, "sig")
		_ = key.Set(jwk.AlgorithmKey, jwa.RS256)
		_ = set.AddKey(key)
	}
	return json.Marshal(set)
}
