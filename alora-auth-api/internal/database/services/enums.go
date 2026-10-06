package services

import (
	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/sqlc"
)

// ProviderPtr converts a nullable IdpProvider column. NULL stays nil.
func ProviderPtr(p sqlc.NullIdpProvider) *models.IdpProvider {
	if !p.Valid {
		return nil
	}
	v := models.IdpProvider(p.IdpProvider)
	return &v
}

// NullProvider is the inverse. A nil pointer writes SQL NULL.
func NullProvider(p *models.IdpProvider) sqlc.NullIdpProvider {
	if p == nil {
		return sqlc.NullIdpProvider{}
	}
	return sqlc.NullIdpProvider{IdpProvider: sqlc.IdpProvider(*p), Valid: true}
}

// RevokeReasonPtr converts a nullable SessionRevokedReason column. NULL stays
// nil: a rotated-away session has no reason, and that absence is meaningful.
func RevokeReasonPtr(r sqlc.NullSessionRevokedReason) *models.RevokeReason {
	if !r.Valid {
		return nil
	}
	v := models.RevokeReason(r.SessionRevokedReason)
	return &v
}
