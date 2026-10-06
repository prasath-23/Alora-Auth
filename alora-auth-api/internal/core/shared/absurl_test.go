package shared

import (
	"regexp"
	"testing"
)

// The tables' checks on a stored URL: a product's redirect and launch URIs, and
// (its prefix) an SSO issuer.
var tableURL = regexp.MustCompile(`^https?://[^#]+$`)

func TestAbsoluteURL(t *testing.T) {
	for _, s := range []string{"https://crm.acme.test/cb", "http://localhost:4100/cb?x=1", "https://[::1]:8443/cb",
		"https://crm.acme.test/%23", "https://crm.acme.test"} {
		if _, ok := AbsoluteURL(s); !ok {
			t.Errorf("AbsoluteURL(%q) refused an ordinary URL", s)
		}
	}
	for _, s := range []string{"HTTPS://CRM.ACME.TEST/CB", "hTTps://crm.acme.test", "https://crm.acme.test/cb#",
		"https://crm.acme.test/#frag", "https://@crm.acme.test", "https://user:pw@crm.acme.test", "https:/crm.acme.test",
		"https:crm.acme.test", "//crm.acme.test", "/cb", "ftp://crm.acme.test", "https://", "javascript:alert(1)", ""} {
		if _, ok := AbsoluteURL(s); ok {
			t.Errorf("AbsoluteURL(%q) accepted it", s)
		}
	}
}

// Whatever AbsoluteURL accepts, the tables accept: their checks read the text,
// and a check of the parse alone would pass an upper-case scheme or a lone "#"
// that they refuse.
func FuzzAbsoluteURL(f *testing.F) {
	for _, s := range []string{"https://crm.acme.test/cb", "HTTPS://CRM.ACME.TEST/CB", "https://crm.acme.test/cb#",
		"https://@crm.acme.test", "https:crm.acme.test", "ftp://crm.acme.test", "https://x.test:99999/", "http://[::1]/"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, ok := AbsoluteURL(s)
		if !ok {
			return
		}
		if !tableURL.MatchString(s) {
			t.Fatalf("AbsoluteURL accepted %q, which the tables' check refuses", s)
		}
		if u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
			t.Fatalf("AbsoluteURL accepted %q as %+v", s, u)
		}
	})
}
