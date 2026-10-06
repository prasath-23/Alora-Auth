package shared

import (
	"net/url"
	"strings"
)

// SafeReturnTo reports whether s may be followed after a sign-in: a path on App
// Central's own origin, and nothing that a browser could resolve to anywhere
// else. It returns the cleaned path, or "" when s must not be followed.
//
// Browsers are generous in what they treat as a host. "//evil.example" and
// "/\evil.example" are both protocol-relative URLs to evil.example, a
// backslash is read as a slash, and tabs and newlines are stripped before
// parsing, so "/\t/evil" is "//evil". Each is refused rather than normalised.
func SafeReturnTo(s string) string {
	if s == "" || len(s) > 2048 || s[0] != '/' {
		return ""
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return ""
		}
	}
	if strings.HasPrefix(s, "//") {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" {
		return ""
	}
	return s
}
