package services

import (
	"encoding/json"

	"github.com/alora/auth/internal/database/models"
	"github.com/alora/auth/internal/database/sqlc"
)

// Row conversions shared by more than one table service. A table's own
// conversion lives in its package; these are here because another table's
// queries return the same row type, and a table service may not import another.

// LoginPolicyFromRow converts a tbl_login_policies row. The login-policy service
// returns it, and so does the invitation lookup of the policy an invitee will
// sign in under.
func LoginPolicyFromRow(r sqlc.TblLoginPolicy) models.LoginPolicy {
	return models.LoginPolicy{
		ID: r.ID, ClientID: r.ClientID, Name: r.Name,
		AllowPassword: r.AllowPassword, AllowGoogle: r.AllowGoogle,
		SSOConnectionID: StringPtr(r.SsoConnectionID), Priority: r.Priority, IsDefault: r.IsDefault,
		CreatedAt: TimePtr(r.CreatedAt), UpdatedAt: TimePtr(r.UpdatedAt),
	}
}

// ClientProductDetailFromRow converts a vw_ClientProductDetail row: a company's
// subscriptions are listed by the subscription service, and the products a
// company may put on an API client's list by the API-client service.
func ClientProductDetailFromRow(r sqlc.VwClientproductdetail) models.ClientProductDetail {
	return models.ClientProductDetail{
		ID: r.ID, ClientID: r.ClientID, ProductID: r.ProductID, IsActive: r.IsActive,
		SeatLimit: Int32Ptr(r.SeatLimit), StartsAt: TimePtr(r.StartsAt), EndsAt: TimePtr(r.EndsAt),
		CreatedAt: TimePtr(r.CreatedAt), ProductKey: r.ProductKey, ProductName: r.ProductName,
		ProductDescription: StringPtr(r.ProductDescription), ProductBaseURL: StringPtr(r.ProductBaseUrl),
		ProductIsActive: r.ProductIsActive, ProductAcceptsAPIClients: r.ProductAcceptsApiClients,
	}
}

// APIClientSecretFromRow converts a vw_ApiClientSecret row: the secret service
// returns one when it makes a secret, and its listing returns them all.
func APIClientSecretFromRow(r sqlc.VwApiclientsecret) models.APIClientSecret {
	return models.APIClientSecret{
		ID: r.ID, APIClientID: r.ApiClientID, ClientID: r.ClientID, Prefix: r.Prefix,
		ExpiresAt: TimePtr(r.ExpiresAt), RevokedAt: TimePtr(r.RevokedAt), LastUsedAt: TimePtr(r.LastUsedAt),
		CreatedByUserID: StringPtr(r.CreatedByUserID), CreatedByOwnerID: StringPtr(r.CreatedByOwnerID),
		CreatedAt: TimePtr(r.CreatedAt), IsLive: r.IsLive,
	}
}

// DecodeJSON reads an aggregated jsonb array from a view column.
//
// The parameter is `any` because sqlc cannot infer a concrete type through the
// jsonb_agg expressions of the aggregating views (groups, API clients), so it
// generates interface{}. Both forms pgx may produce are handled, and anything
// unexpected degrades to an empty list rather than a 500: a row whose aggregate
// cannot be read should still render. The result is never nil.
func DecodeJSON[T any](v any) []T {
	if v == nil {
		return []T{}
	}
	var raw []byte
	switch t := v.(type) {
	case []byte:
		raw = t
	case string:
		raw = []byte(t)
	default:
		// pgx decodes jsonb into a Go value (e.g. []interface{}) when the target is
		// interface{}, so neither branch above fires. Re-marshal and decode: the
		// round trip costs nothing at these sizes and keeps one decode path.
		b, err := json.Marshal(t)
		if err != nil {
			return []T{}
		}
		raw = b
	}
	var out []T
	if len(raw) == 0 || json.Unmarshal(raw, &out) != nil || out == nil {
		return []T{}
	}
	return out
}
