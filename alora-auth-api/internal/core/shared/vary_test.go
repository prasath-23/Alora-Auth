package shared

import (
	"net/http"
	"slices"
	"testing"
)

func TestAddVaryMergesInsteadOfOverwriting(t *testing.T) {
	cases := []struct {
		name   string
		before []string
		add    string
		want   []string
	}{
		{"first field", nil, "Origin", []string{"Origin"}},
		{"appends to an earlier field", []string{"Origin"}, "Accept-Encoding", []string{"Origin, Accept-Encoding"}},
		{"already listed", []string{"Origin, Accept-Encoding"}, "Accept-Encoding", []string{"Origin, Accept-Encoding"}},
		{"case-insensitive", []string{"origin"}, "Origin", []string{"origin"}},
		{"merges separate lines", []string{"Origin", "Accept-Encoding"}, "Cookie", []string{"Origin, Accept-Encoding, Cookie"}},
		{"star covers everything", []string{"*"}, "Origin", []string{"*"}},
	}
	for _, c := range cases {
		h := http.Header{}
		for _, v := range c.before {
			h.Add("Vary", v)
		}
		AddVary(h, c.add)
		if got := h.Values("Vary"); !slices.Equal(got, c.want) {
			t.Errorf("%s: Vary = %q, want %q", c.name, got, c.want)
		}
	}
}
