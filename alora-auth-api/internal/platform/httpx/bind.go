package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

var validate = validator.New(validator.WithRequiredStructEnabled())

// BindJSON decodes the request body into dst and validates it.
//
// It deliberately does NOT use c.ShouldBindJSON: Gin's binder silently DISCARDS
// unknown fields, whereas the Fastify schemas this ports set
// additionalProperties:false, which REJECTS them with 400. Silently accepting an
// unknown field is a mass-assignment foothold — a client probing `is_global_admin`
// should be told no, not ignored.
//
// It also rejects a trailing second JSON value, so `{}{"x":1}` cannot smuggle
// content past the decoder.
func BindJSON(c *gin.Context, dst any) error {
	dec := json.NewDecoder(c.Request.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return decodeError(err)
	}
	// Exactly one JSON value may be present.
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return NewAPIError(http.StatusBadRequest, "Invalid request", errors.New("trailing content after JSON body"))
	}
	if err := validate.Struct(dst); err != nil {
		return NewAPIError(http.StatusBadRequest, "Invalid request", err)
	}
	return nil
}

// decodeError converts decoder failures into a 400 with a stable, non-leaky
// message. http.MaxBytesReader surfaces as a 413 so an oversized body is
// distinguishable from a malformed one.
func decodeError(err error) error {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return NewAPIError(http.StatusRequestEntityTooLarge, "Payload Too Large", err)
	}
	if errors.Is(err, io.EOF) {
		return NewAPIError(http.StatusBadRequest, "Invalid request", errors.New("empty body"))
	}
	// Unknown-field and type errors both collapse to the same client message:
	// echoing the offending field name back would confirm which internal fields
	// exist, which is a (small) enumeration aid.
	return NewAPIError(http.StatusBadRequest, "Invalid request", err)
}

// NormalizeEmail lowercases and trims an email so it aligns with the
// lower(email) partial unique index. Every write and lookup path must use this;
// a raw-cased insert would bypass the index's uniqueness semantics.
func NormalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
