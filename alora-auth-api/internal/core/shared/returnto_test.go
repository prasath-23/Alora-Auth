package shared

import "testing"

func TestSafeReturnToAcceptsOwnPaths(t *testing.T) {
	for _, ok := range []string{
		"/",
		"/apps",
		"/oauth/authorize?response_type=code&client_id=abc&redirect_uri=https%3A%2F%2Fcrm.test%2Fcb",
		"/admin/users?search=a%40b",
	} {
		if got := SafeReturnTo(ok); got != ok {
			t.Errorf("SafeReturnTo(%q) = %q, want it unchanged", ok, got)
		}
	}
}

// Every one of these is a way a browser can be sent to another origin by a
// value that looks like a path.
func TestSafeReturnToRefusesOffsiteTargets(t *testing.T) {
	for _, bad := range []string{
		"",
		"https://evil.example/",
		"http://evil.example",
		"//evil.example",
		"///evil.example",
		`/\evil.example`,
		`\\evil.example`,
		"/\t/evil.example",
		"/\n/evil.example",
		"javascript:alert(1)",
		"JAVASCRIPT:alert(1)",
		"data:text/html,<script>alert(1)</script>",
		"evil.example",
		"apps",
		"/%zz", // unparseable escape
	} {
		if got := SafeReturnTo(bad); got != "" {
			t.Errorf("SECURITY: SafeReturnTo(%q) = %q, want it refused", bad, got)
		}
	}
	long := "/" + string(make([]byte, 2048))
	if SafeReturnTo(long) != "" {
		t.Error("an oversized return path was accepted")
	}
}
