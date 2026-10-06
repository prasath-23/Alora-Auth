package main

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/alora/auth/docs"
)

// The OpenAPI document describes exactly the router: every route it serves is
// documented, and every documented operation is served, with the same path
// parameters. A handler added without its annotation, or an annotation left
// behind by a removed route, fails here instead of misleading an integrator.
func TestTheAPIDocumentDescribesExactlyTheRouter(t *testing.T) {
	a := newApp(t)
	var spec struct {
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name string `json:"name"`
				In   string `json:"in"`
			} `json:"parameters"`
		} `json:"paths"`
	}
	if err := json.Unmarshal([]byte(docs.SwaggerInfo.ReadDoc()), &spec); err != nil {
		t.Fatal(err)
	}
	param := regexp.MustCompile(`\{[^}]+\}|:[^/]+`)
	shape := func(method, path string) string {
		return strings.ToUpper(method) + " " + param.ReplaceAllString(path, "{}")
	}

	documented := map[string]bool{}
	for path, ops := range spec.Paths {
		want := param.FindAllString(path, -1)
		for method, op := range ops {
			documented[shape(method, path)] = true
			var got []string
			for _, p := range op.Parameters {
				if p.In == "path" {
					got = append(got, "{"+p.Name+"}")
				}
			}
			if strings.Join(sorted(got), ",") != strings.Join(sorted(want), ",") {
				t.Errorf("%s %s documents path parameters %v, but the path has %v", strings.ToUpper(method), path, got, want)
			}
		}
	}
	served := map[string]bool{}
	for _, r := range a.r.Routes() {
		served[shape(r.Method, r.Path)] = true
	}
	// The Owner console serves the company-management families for any company;
	// the document describes each route once, at its /api/admin path, and says
	// so. A family is mirrored whole.
	mirrored := func(rest string) bool {
		family, _, _ := strings.Cut(rest, "/")
		return mirroredFamilies[family]
	}
	for k := range served {
		method, path, _ := strings.Cut(k, " ")
		if rest, ok := strings.CutPrefix(path, "/api/owner/companies/{}/"); ok && !documented[k] && mirrored(rest) {
			if !documented[method+" /api/admin/"+rest] {
				t.Errorf("served for the Owner, but its /api/admin twin is not documented: %s", k)
			}
			continue
		}
		if !documented[k] && !undocumented[k] {
			t.Errorf("served but not documented: %s", k)
		}
	}
	for k := range documented {
		method, path, _ := strings.Cut(k, " ")
		if rest, ok := strings.CutPrefix(path, "/api/admin/"); ok && mirrored(rest) && !served[method+" /api/owner/companies/{}/"+rest] {
			t.Errorf("the document says the Owner console serves %s for any company, but it does not", k)
		}
	}
	for k := range documented {
		if !served[k] {
			t.Errorf("documented but not served: %s", k)
		}
	}
	for k := range undocumented {
		if !served[k] {
			t.Errorf("listed as served without documentation, but not served: %s", k)
		}
	}
}

// undocumented are the routes served on purpose without an operation in the
// document, each for its reason.
var undocumented = map[string]bool{
	"GET /docs":      true, // the document itself, and Swagger UI reading it
	"GET /docs/*any": true,
}

// mirroredFamilies are the /api/admin families the document says the Owner
// console serves for any company under /api/owner/companies/{cid} (its "owner"
// tag, and the introduction).
var mirroredFamilies = map[string]bool{"users": true, "invitations": true, "groups": true, "api-clients": true}

func sorted(ss []string) []string {
	out := append([]string(nil), ss...)
	sort.Strings(out)
	return out
}
