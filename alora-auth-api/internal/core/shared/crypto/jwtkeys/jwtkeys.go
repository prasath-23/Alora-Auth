// Package jwtkeys is the RS256 keystore: one active signing key, plus any number
// of verify-only keys, all indexed by kid and all published in the JWKS. That is
// what makes rotation overlap: deploy a new signing key with the old one
// verify-only, wait out the longest token lifetime, then drop the old one.
//
// Verification pins RS256 and resolves the key by kid, so algorithm confusion
// (alg=none/HS256) is rejected. It also pins the token's type: an access token
// carries typ "at+jwt" (RFC 9068) and an ID token "JWT", and each verifier
// accepts only its own, so an ID token handed to a product can never be replayed
// as an access token. The audience is mandatory in both directions.
package jwtkeys

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
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
// obstacle), and mint tokens for any user in any company. There is no detection
// story for that: the forgeries are valid signatures.
//
// 2048 is the floor rather than the recommendation. The cost of refusing a weak
// key is a failed deploy with a clear message; the cost of accepting one is
// silent total compromise.
const minModulusBits = 2048

// Token types, as the protected header's typ.
const (
	TypeAccess = "at+jwt" // RFC 9068 §2.1
	TypeID     = "JWT"
)

type keyPair struct {
	priv *rsa.PrivateKey // nil for a verify-only key
	pub  *rsa.PublicKey
}

var (
	mu        sync.RWMutex
	keys      = map[string]keyPair{}
	activeKid string
	issuer    string
)

// Init loads a PKCS8 private / PKIX public RS256 keypair under kid as THE
// signing key and makes iss the issuer. It replaces the whole keystore, verify-
// only keys included: call AddVerifyKey afterwards for each key being retired.
func Init(privatePEM, publicPEM, kid, iss string) error {
	if kid == "" {
		return errors.New("jwtkeys: the signing key needs a kid")
	}
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
	// Mismatched halves are a deployment mistake that otherwise surfaces as a
	// system where every login succeeds and every authenticated request is then
	// rejected -- signed with one key, verified against another. Catch it at
	// startup, where the message can name the cause.
	if !priv.PublicKey.Equal(pub) {
		return errors.New("jwtkeys: public key is not the private key's counterpart; " +
			"tokens would be signed with one key and verified against another")
	}
	mu.Lock()
	keys = map[string]keyPair{kid: {priv: priv, pub: pub}}
	activeKid = kid
	issuer = iss
	mu.Unlock()
	return nil
}

// AddVerifyKey registers a PKIX public key under kid that verifies tokens but
// never signs one. A kid already in the keystore is refused: two keys under one
// kid would make every verification a coin toss.
func AddVerifyKey(kid, publicPEM string) error {
	if kid == "" {
		return errors.New("jwtkeys: a verify-only key needs a kid")
	}
	pub, err := parsePublic(publicPEM)
	if err != nil {
		return fmt.Errorf("jwtkeys: verify-only key %q: %w", kid, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if _, dup := keys[kid]; dup {
		return fmt.Errorf("jwtkeys: kid %q is already in the keystore", kid)
	}
	keys[kid] = keyPair{pub: pub}
	return nil
}

// Issuer is the issuer every token is signed with and verified against.
func Issuer() string {
	mu.RLock()
	defer mu.RUnlock()
	return issuer
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
	if n := rk.N.BitLen(); n < minModulusBits {
		return nil, fmt.Errorf("public key is %d-bit, minimum is %d", n, minModulusBits)
	}
	return rk, nil
}

// SignAccess issues an RS256 access token (typ at+jwt) for one audience.
func SignAccess(subject string, claims map[string]any, ttl time.Duration, audience string) (string, error) {
	return sign(TypeAccess, subject, claims, ttl, audience)
}

// SignID issues an RS256 OpenID Connect ID token (typ JWT) for one audience, the
// client it was requested by.
func SignID(subject string, claims map[string]any, ttl time.Duration, audience string) (string, error) {
	return sign(TypeID, subject, claims, ttl, audience)
}

// sign builds the registered claims (iss, sub, aud, iat, exp, jti) around the
// caller's private claims and signs with the active key. The audience is
// mandatory: a token that names no recipient would be accepted by any verifier
// that forgot to check.
func sign(typ, subject string, claims map[string]any, ttl time.Duration, audience string) (string, error) {
	mu.RLock()
	kp, ok := keys[activeKid]
	kid, iss := activeKid, issuer
	mu.RUnlock()
	if !ok || kp.priv == nil {
		return "", errors.New("jwtkeys: not initialized")
	}
	if ttl <= 0 {
		return "", errors.New("jwtkeys: ttl must be positive")
	}
	if audience == "" {
		return "", errors.New("jwtkeys: a token must name its audience")
	}

	now := time.Now()
	b := jwt.NewBuilder()

	// Private claims are applied FIRST, and any reserved name is refused outright.
	// Later Claim() calls win in jwx, so applying the caller's map after the
	// registered claims would let a caller override exp/sub/iss/jti and mint a
	// never-expiring token that survives logout and revocation.
	for k, v := range claims {
		if isReservedClaim(k) {
			return "", fmt.Errorf("jwtkeys: private claim %q collides with a reserved claim", k)
		}
		b = b.Claim(k, v)
	}

	b = b.Issuer(iss).
		Subject(subject).
		Audience([]string{audience}).
		IssuedAt(now).
		Expiration(now.Add(ttl)).
		JwtID(uuid.NewString())
	tok, err := b.Build()
	if err != nil {
		return "", err
	}

	hdrs := jws.NewHeaders()
	_ = hdrs.Set(jws.KeyIDKey, kid)
	_ = hdrs.Set(jws.TypeKey, typ)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, kp.priv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// reservedClaims are the registered JWT claims this package controls. A private
// claim may never shadow one of these (see sign).
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

// keyProvider resolves the verification key by the token's kid and pins RS256,
// so a token claiming alg=none/HS256 can never be verified with our RSA key. It
// also pins the header's typ to the one the caller expects.
type keyProvider struct{ typ string }

func (p keyProvider) FetchKeys(_ context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
	h := sig.ProtectedHeaders()
	if !typeMatches(h.Type(), p.typ) {
		return errors.New("wrong token type")
	}
	kid := h.KeyID()
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

// typeMatches compares a typ header the way RFC 9068 §4 says to: without case,
// and with the "application/" prefix optional.
func typeMatches(got, want string) bool {
	got = strings.TrimPrefix(strings.ToLower(got), "application/")
	return got == strings.ToLower(want)
}

// VerifyAccess parses and validates an access token for one audience: typ
// at+jwt, a kid-resolved key, pinned RS256, the issuer, the audience, 5s clock
// skew, and the required claims [sub, exp, iat, iss].
func VerifyAccess(token, audience string) (jwt.Token, error) {
	return verify(token, audience, TypeAccess)
}

// VerifyID is VerifyAccess for an ID token (typ JWT).
func VerifyID(token, audience string) (jwt.Token, error) {
	return verify(token, audience, TypeID)
}

func verify(token, audience, typ string) (jwt.Token, error) {
	// A verifier with no audience would accept a token minted for anyone.
	if audience == "" {
		return nil, errors.New("jwtkeys: verification requires an audience")
	}
	mu.RLock()
	iss := issuer
	mu.RUnlock()

	tok, err := jwt.Parse([]byte(token),
		jwt.WithKeyProvider(keyProvider{typ: typ}),
		jwt.WithValidate(true),
		jwt.WithIssuer(iss),
		jwt.WithAudience(audience),
		jwt.WithAcceptableSkew(5*time.Second),
	)
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

// JWKS returns the public JWK Set — the signing key and every verify-only key —
// each marked use=sig, alg=RS256, in kid order so the document is stable.
func JWKS() ([]byte, error) {
	set := jwk.NewSet()
	mu.RLock()
	defer mu.RUnlock()
	kids := make([]string, 0, len(keys))
	for kid := range keys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	for _, kid := range kids {
		key, err := jwk.FromRaw(keys[kid].pub)
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
