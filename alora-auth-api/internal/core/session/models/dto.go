// Package models holds the session feature's DTOs and HTTP response models.
package models

import "time"

// Session kinds: a login at App Central, or one product's login under it.
const (
	KindCentral = "CENTRAL"
	KindProduct = "PRODUCT"
)

// Issued is a freshly minted refresh token and the session behind it. On a
// benign rotation race only FamilyID, UserID and ClientID are set: the session
// is still good, but this request did not get its successor.
type Issued struct {
	RawToken  string
	SessionID string
	FamilyID  string
	UserID    string
	ClientID  string
	ExpiresAt time.Time // the token's own expiry, already capped at the family's
}

// TTL is how long the token has left, for a cookie's Max-Age.
func (i Issued) TTL() time.Duration { return time.Until(i.ExpiresAt) }

// Want is what kind of session a presented refresh token must belong to. A
// central token is honoured only where central tokens are expected, and a
// product's only by that product.
type Want struct {
	Kind      string // KindCentral or KindProduct
	ProductID string // KindProduct only: the product that authenticated
}

// Gate is the state of one session family.
type Gate struct {
	FamilyID         string
	UserID           string
	ClientID         string
	Email            string
	Kind             string
	ProductID        string
	ParentFamilyID   string
	AuthMethod       string // EMAIL, GOOGLE or OIDC
	AuthConnectionID string
	AuthenticatedAt  time.Time
	PermVersion      int32
	// Usable: the family, its parent, its user and its company are all live, and
	// for a product login the user still has access to the product.
	Usable bool
}

// TokenFamily is the family a refresh token belongs to, and whether the token
// itself is still the family's live one.
type TokenFamily struct {
	Gate
	TokenLive bool
}

// ActiveSession is one live session family as the admin list shows it.
type ActiveSession struct {
	ID              string
	Email           string // whose it is
	Kind            string
	ProductKey      *string
	AuthMethod      string
	AuthenticatedAt *time.Time
	DeviceLabel     string
	IPAddress       string
	LastSeenAt      *time.Time
	CreatedAt       *time.Time
}
