package shared

import (
	"net/url"
	"strings"
)

// AbsoluteURL parses raw as an absolute http or https URL: a host, no user name
// and no fragment. It reads the text as well as the parse, because the value is
// stored as given. url.Parse lower-cases the scheme and leaves the fragment of a
// lone "#" empty, where the tables' own checks read the text: "HTTPS://…" and
// "…#" would pass a check of the parse alone and then be refused by the table.
func AbsoluteURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || strings.Contains(raw, "#") ||
		(u.Scheme != "https" && u.Scheme != "http") || !strings.HasPrefix(raw, u.Scheme+"://") {
		return nil, false
	}
	return u, true
}
