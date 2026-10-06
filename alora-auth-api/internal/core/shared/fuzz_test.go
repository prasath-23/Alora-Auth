package shared

import (
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

// Fuzzing the pure guards: each property below must hold for every input, not
// just the ones someone thought of.

// A return path is refused, or it is itself — and it then resolves to App
// Central's own origin however a browser reads it.
func FuzzSafeReturnTo(f *testing.F) {
	for _, s := range []string{"/", "/apps", "//evil.example", `/\evil.example`, "/\t/evil", "/%2F%2Fevil",
		"/.//evil", "/..//evil", "/@evil.example", "/?next=//evil", "/#//evil", "https://evil.example",
		"javascript:alert(1)", "/　/evil", "/%09/evil", "/ /evil", "/\x7f", "/" + strings.Repeat("a", 2100)} {
		f.Add(s)
	}
	base, _ := url.Parse("https://central.test/login")
	f.Fuzz(func(t *testing.T, s string) {
		got := SafeReturnTo(s)
		if got == "" {
			return
		}
		if got != s {
			t.Fatalf("SafeReturnTo(%q) = %q: a path is followed as given or not at all", s, got)
		}
		if !strings.HasPrefix(got, "/") || strings.HasPrefix(got, "//") || strings.ContainsAny(got, "\\") || len(got) > 2048 {
			t.Fatalf("SECURITY: SafeReturnTo accepted %q", s)
		}
		for _, r := range got {
			if r < 0x20 || r == 0x7f {
				t.Fatalf("SECURITY: SafeReturnTo accepted a control character in %q", s)
			}
		}
		// Browsers strip tabs and newlines and read a backslash as a slash;
		// none survive above, so the standard resolution is the browser's.
		ref, err := url.Parse(got)
		if err != nil {
			t.Fatalf("SafeReturnTo accepted %q, which does not parse: %v", s, err)
		}
		if u := base.ResolveReference(ref); u.Scheme != "https" || u.Host != "central.test" || u.User != nil {
			t.Fatalf("SECURITY: %q resolves to %s, off App Central", s, u)
		}
	})
}

// Normalised scopes are sorted, unique, from the catalogue, and every edit
// scope brings its read scope; anything else is refused. (Surrounding
// whitespace is forgiven: only the canonical scope is ever stored or checked.)
func FuzzNormalizeScopes(f *testing.F) {
	f.Add("users:edit groups:read")
	f.Add("users:read users:read")
	f.Add("owner apps:read")
	f.Add(" users:edit\x00")
	f.Add("api:edit mcp:tools")
	check := func(t *testing.T, in []string, out []string, err error, known map[string]string) {
		if err != nil {
			bad := false
			for _, s := range in {
				if _, ok := known[strings.TrimSpace(s)]; !ok {
					bad = true
				}
			}
			if !bad {
				t.Fatalf("%q refused, though every scope is known: %v", in, err)
			}
			return
		}
		if !sort.StringsAreSorted(out) {
			t.Fatalf("%q normalised to %q: not sorted", in, out)
		}
		seen := map[string]bool{}
		for _, s := range out {
			read, ok := known[s]
			if !ok {
				t.Fatalf("%q normalised to %q, which holds unknown %q", in, out, s)
			}
			if seen[s] {
				t.Fatalf("%q normalised to %q, which repeats %q", in, out, s)
			}
			seen[s] = true
			if read != "" && !contains(out, read) {
				t.Fatalf("%q normalised to %q: %q without its read scope %q", in, out, s, read)
			}
		}
		for _, s := range in {
			if !seen[strings.TrimSpace(s)] {
				t.Fatalf("%q normalised to %q, which lost %q", in, out, s)
			}
		}
	}
	f.Fuzz(func(t *testing.T, joined string) {
		in := strings.Split(joined, " ")
		out, err := NormalizeScopes(in)
		check(t, in, out, err, grantable)
		out, err = NormalizeClientScopes(in)
		check(t, in, out, err, clientScopes)
	})
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// StorableText always yields storable text within its limit, and leaves text
// that already is both exactly as it was.
func FuzzStorableText(f *testing.F) {
	for _, s := range []string{"", "Mozilla/5.0", "\xff\xfe", "Chrome\x00", strings.Repeat("a", 511) + "é", "😀😀", "\x80"} {
		f.Add(s, uint16(512))
	}
	f.Add("abcé", uint16(4))
	f.Fuzz(func(t *testing.T, s string, max uint16) {
		got := StorableText(s, int(max))
		if !Storable(got) || len(got) > int(max) {
			t.Fatalf("StorableText(%q, %d) = %q: not storable, or past the limit", s, max, got)
		}
		if Storable(s) && len(s) <= int(max) && got != s {
			t.Fatalf("StorableText(%q, %d) = %q: storable text within the limit was changed", s, max, got)
		}
	})
}

// Storable is exactly "UTF-8 without NUL", and the walk BindJSON relies on
// finds a bad string wherever it sits in a decoded body.
func FuzzStorable(f *testing.F) {
	for _, s := range []string{"", "ok", "a\x00b", "\xff", "\xc3\x28", "😀", "‮"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		want := utf8.ValidString(s) && !strings.Contains(s, "\x00")
		if Storable(s) != want {
			t.Fatalf("Storable(%q) = %v, want %v", s, Storable(s), want)
		}
		type inner struct{ Name string }
		type body struct {
			Name   string
			Tags   []string
			Ptr    *string
			Nested []inner
			Extra  map[string]any
		}
		for _, v := range []any{
			&body{Name: s},
			&body{Tags: []string{"ok", s}},
			&body{Ptr: &s},
			&body{Nested: []inner{{Name: "ok"}, {Name: s}}},
			&body{Extra: map[string]any{"k": []any{s}}},
			&body{Extra: map[string]any{s: 1}},
		} {
			if got := storableValue(reflect.ValueOf(v)); got != want {
				t.Fatalf("storableValue(%+v) = %v, want %v", v, got, want)
			}
		}
	})
}
