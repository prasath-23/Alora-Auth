package middlewares

import (
	"net/http"

	"github.com/alora/auth/internal/core/shared"
	"github.com/alora/auth/internal/exceptions"
	"github.com/gin-gonic/gin"
)

// errUnstorable is the answer to a path or query holding text the database
// cannot store.
var errUnstorable = exceptions.NewAPIError(http.StatusBadRequest, "Invalid request", nil)

// StorableText refuses, before any handler reads a parameter, a request whose
// path or query holds text PostgreSQL cannot store: a NUL character, or bytes
// that are not UTF-8. Path ids and query terms all reach the database as text,
// where such a value is an error; here it is the client's 400.
func StorableText() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !shared.Storable(c.Request.URL.Path) {
			exceptions.Fail(c, errUnstorable)
			return
		}
		for k, vs := range c.Request.URL.Query() {
			if !shared.Storable(k) || !shared.AllStorable(vs) {
				exceptions.Fail(c, errUnstorable)
				return
			}
		}
		c.Next()
	}
}
