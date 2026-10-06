package shared

import (
	"net/http"
	"strings"
)

// AddVary adds field to the response's Vary header unless it is already listed,
// merging every Vary line into one. Setting Vary instead would overwrite what an
// earlier layer declared — CORS's Origin — and let a shared cache serve a response
// stored for one origin to another.
func AddVary(h http.Header, field string) {
	values := h.Values("Vary")
	for _, line := range values {
		for _, token := range strings.Split(line, ",") {
			token = strings.TrimSpace(token)
			if token == "*" || strings.EqualFold(token, field) {
				return // "*" already varies on everything
			}
		}
	}
	merged := field
	if len(values) > 0 {
		merged = strings.Join(values, ", ") + ", " + field
	}
	h.Set("Vary", merged)
}
