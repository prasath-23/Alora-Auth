package shared

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/go-playground/validator/v10/non-standard/validators"
)

var validate = func() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())
	// notblank: a name that trims to nothing — spaces, tabs, newlines — is no
	// name, though min=1 would count its characters.
	if err := v.RegisterValidation("notblank", validators.NotBlank); err != nil {
		panic(err)
	}
	return v
}()

// BindJSON decodes the request body into dst and validates it.
//
// It deliberately does NOT use c.ShouldBindJSON: Gin's binder silently DISCARDS
// unknown fields, whereas the Fastify schemas this ports set
// additionalProperties:false, which REJECTS them with 400. Silently accepting an
// unknown field is a mass-assignment foothold — a client probing `is_global_admin`
// should be told no, not ignored.
//
// It also rejects a trailing second JSON value, so `{}{"x":1}` cannot smuggle
// content past the decoder; a body that is not UTF-8, which Go's decoder would
// silently repair, changing what the client sent; and any string holding a NUL,
// which the database cannot store.
func BindJSON(c *gin.Context, dst any) error {
	// Only a JSON body is accepted. A hostile page can POST a text/plain form
	// cross-site with no CORS preflight, and a text/plain body can be shaped into
	// valid JSON — so without this check it could submit its own credentials to a
	// login endpoint from the victim's browser (login CSRF). application/json
	// cannot be sent cross-site without a preflight, which CORS refuses.
	if mt, _, err := mime.ParseMediaType(c.GetHeader("Content-Type")); err != nil || mt != "application/json" {
		return exceptions.NewAPIError(http.StatusUnsupportedMediaType, "Unsupported Media Type", err)
	}

	// The body limit caps what is read here; past it, the read fails with the
	// error decodeError turns into a 413.
	raw, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return decodeError(err)
	}
	if !utf8.Valid(raw) {
		return exceptions.NewAPIError(http.StatusBadRequest, "Invalid request", errors.New("body is not UTF-8"))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return decodeError(err)
	}
	// Exactly one JSON value may be present.
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return exceptions.NewAPIError(http.StatusBadRequest, "Invalid request", errors.New("trailing content after JSON body"))
	}
	if !storableValue(reflect.ValueOf(dst)) {
		return exceptions.NewAPIError(http.StatusBadRequest, "Invalid request", errors.New("a string holds a NUL character"))
	}
	if err := validate.Struct(dst); err != nil {
		return exceptions.NewAPIError(http.StatusBadRequest, "Invalid request", err)
	}
	return nil
}

// decodeError converts decoder failures into a 400 with a stable, non-leaky
// message. http.MaxBytesReader surfaces as a 413 so an oversized body is
// distinguishable from a malformed one.
func decodeError(err error) error {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return exceptions.NewAPIError(http.StatusRequestEntityTooLarge, "Payload Too Large", err)
	}
	if errors.Is(err, io.EOF) {
		return exceptions.NewAPIError(http.StatusBadRequest, "Invalid request", errors.New("empty body"))
	}
	// Unknown-field and type errors both collapse to the same client message:
	// echoing the offending field name back would confirm which internal fields
	// exist, which is a (small) enumeration aid.
	return exceptions.NewAPIError(http.StatusBadRequest, "Invalid request", err)
}

// NormalizeEmail lowercases and trims an email so it aligns with the
// lower(email) partial unique index. Every write and lookup path must use this;
// a raw-cased insert would bypass the index's uniqueness semantics.
func NormalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
