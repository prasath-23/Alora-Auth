package main

// Architecture guard. It parses every non-test Go file of the module and fails
// when a package imports across a boundary the layering forbids, reaches the
// database around the table services, or lets one kind of model leak into a
// layer that must not see it. The rules are the ones ARCHITECTURE.md §2
// describes; this test is what keeps them true.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/alora/auth/"

type goFile struct {
	path    string // slash-separated, relative to the module root
	dir     string // package directory, relative to the module root
	ast     *ast.File
	imports map[string]string // local name → import path (module-relative when internal)
}

func TestArchitecture(t *testing.T) {
	root := filepath.Join("..", "..")
	files := parseModule(t, root)
	for _, f := range files {
		for _, imp := range f.imports {
			if !strings.HasPrefix(imp, "internal/") {
				continue
			}
			if reason := forbiddenImport(f.dir, imp); reason != "" {
				t.Errorf("%s imports %s: %s", f.path, imp, reason)
			}
		}
		checkRawHandles(t, f)
		checkModelKinds(t, f)
		checkServiceContext(t, f)
		checkTokenSigning(t, f)
		checkOwnerScope(t, f)
		checkTransports(t, f)
	}
	checkFeatureLayout(t, root)
}

// transports are the import paths that belong at the edges: gin, gRPC (with
// its error details), and the code generated from the protos.
var transports = []string{
	"github.com/gin-gonic/gin", "google.golang.org/grpc", "google.golang.org/genproto",
	"github.com/prasath-23/Alora-Auth/alora-auth-go",
}

// checkTransports keeps HTTP and gRPC at the edges — controllers, middlewares
// and cmd/api. A service, the database layer or infrastructure importing one
// would tie a rule to one door, and the two doors of the token endpoint would
// drift apart. shared may carry gin's types (the scope resolver, binding),
// never gRPC's.
func checkTransports(t *testing.T, f goFile) {
	t.Helper()
	parts := strings.Split(f.dir, "/")
	isService := len(parts) == 4 && parts[0] == "internal" && parts[1] == "core" && parts[3] == "service"
	inner := isService || strings.HasPrefix(f.dir, "internal/database") || f.dir == "internal/infrastructure"
	shared := strings.HasPrefix(f.dir, "internal/core/shared")
	if !inner && !shared {
		return
	}
	for _, imp := range f.imports {
		for _, tr := range transports {
			if shared && tr == "github.com/gin-gonic/gin" {
				continue
			}
			if imp == tr || strings.HasPrefix(imp, tr+"/") {
				t.Errorf("%s imports %s: transports stay in controllers, middlewares and cmd/api", f.path, imp)
			}
		}
	}
}

// alora-auth-go is what products and applications build against: its protos,
// generated code, helper and demo. It must never import App Central — that
// would drag App Central's dependencies into every product, and let a product
// reach code only App Central should run.
func TestTheGoModuleStandsAlone(t *testing.T) {
	root := filepath.Join("..", "..", "..", "alora-auth-go")
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("alora-auth-go not found beside alora-auth-api: %v", err)
	}
	fset := token.NewFileSet()
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".bin" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		files++
		for _, spec := range file.Imports {
			p, _ := strconv.Unquote(spec.Path.Value)
			if p == strings.TrimSuffix(modulePath, "/") || strings.HasPrefix(p, modulePath) {
				t.Errorf("%s imports App Central (%s)", filepath.ToSlash(path), p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("alora-auth-go has no Go files")
	}
}

// checkTokenSigning keeps token minting in one place: only the auth service may
// sign, so every claim every token carries is decided by one package that reads
// it from the database. It also refuses a verification that names no audience,
// which would accept a token minted for anyone.
func checkTokenSigning(t *testing.T, f goFile) {
	t.Helper()
	alias := ""
	for name, imp := range f.imports {
		if imp == "internal/core/shared/crypto/jwtkeys" {
			alias = name
		}
	}
	if alias == "" {
		return
	}
	ast.Inspect(f.ast, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); !ok || x.Name != alias {
			return true
		}
		switch sel.Sel.Name {
		case "SignAccess", "SignID":
			if f.dir != "internal/core/auth/service" {
				t.Errorf("%s: only internal/core/auth/service may call jwtkeys.%s", f.path, sel.Sel.Name)
			}
		case "VerifyAccess", "VerifyID":
			if len(call.Args) == 2 {
				if lit, ok := call.Args[1].(*ast.BasicLit); ok && (lit.Value == `""` || lit.Value == "``") {
					t.Errorf("%s: jwtkeys.%s with an empty audience", f.path, sel.Sel.Name)
				}
			}
		}
		return true
	})
}

// checkOwnerScope keeps the only way to act on ANOTHER company in the Owner
// console's controller: nothing else may call OwnerScopeFrom.
func checkOwnerScope(t *testing.T, f goFile) {
	t.Helper()
	if f.dir == "internal/core/owner/controller" {
		return
	}
	ast.Inspect(f.ast, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if x.Sel.Name == "OwnerScopeFrom" {
				t.Errorf("%s: OwnerScopeFrom may be called only from internal/core/owner/controller", f.path)
			}
		case *ast.Ident:
			if x.Name == "OwnerScopeFrom" {
				t.Errorf("%s: OwnerScopeFrom may be called only from internal/core/owner/controller", f.path)
			}
		}
		return true
	})
}

// forbiddenImport returns why dir may not import imp, or "" when it may.
func forbiddenImport(dir, imp string) string {
	if imp == "internal/database/sqlc" && !isDatabaseAccess(dir) {
		return "generated SQL is reachable only through internal/database"
	}
	// allowed accepts exact package paths, and "x/**" for x and everything below it.
	allowed := func(patterns ...string) string {
		for _, p := range patterns {
			if base, subtree := strings.CutSuffix(p, "/**"); subtree {
				if imp == base || strings.HasPrefix(imp, base+"/") {
					return ""
				}
			} else if imp == p {
				return ""
			}
		}
		return "not an allowed dependency of " + dir
	}
	parts := strings.Split(dir, "/")
	switch {
	case dir == "internal/exceptions", dir == "internal/config",
		dir == "internal/database/sqlc", dir == "internal/database/models":
		return "this package must not depend on any other internal package"
	case dir == "internal/database/contexts":
		return allowed("internal/database/sqlc")
	case dir == "internal/database/services":
		return allowed("internal/database/models", "internal/database/sqlc")
	case strings.HasPrefix(dir, "internal/database/services/") && len(parts) == 4:
		return allowed("internal/database/contexts", "internal/database/models",
			"internal/database/sqlc", "internal/database/services")
	case strings.HasPrefix(dir, "internal/database/services/") && len(parts) == 5 && parts[4] == "customs":
		return allowed("internal/database/contexts", "internal/database/models", "internal/database/sqlc",
			"internal/database/services", "internal/database/services/"+parts[3])
	case strings.HasPrefix(dir, "internal/core/shared"):
		return allowed("internal/exceptions")
	case dir == "internal/infrastructure":
		return allowed("internal/config", "internal/database/contexts", "internal/database/services/**")
	case dir == "internal/middlewares":
		return allowed("internal/exceptions", "internal/core/shared", "internal/core/shared/crypto/jwtkeys")
	case strings.HasPrefix(dir, "internal/core/") && len(parts) == 4:
		feature, layer := parts[2], parts[3]
		switch layer {
		case "controller":
			return allowed("internal/exceptions", "internal/middlewares", "internal/core/shared",
				"internal/core/"+feature+"/service", "internal/core/"+feature+"/models")
		case "service":
			if reason := allowed("internal/exceptions", "internal/core/shared/**", "internal/infrastructure",
				"internal/database/contexts", "internal/database/models", "internal/database/services/**",
				"internal/core/"+feature+"/models"); reason == "" {
				return ""
			}
			// Another feature's business logic and DTOs, never its HTTP layer.
			other := strings.Split(imp, "/")
			if len(other) == 4 && other[1] == "core" && other[2] != "shared" &&
				(other[3] == "service" || other[3] == "models") {
				return ""
			}
			return "a feature service may use only its own models, other features' services and models, and the layers below"
		case "models":
			return allowed("internal/core/shared")
		}
		return "unknown layer " + layer
	}
	return ""
}

// isDatabaseAccess reports whether dir is part of the database layer proper.
func isDatabaseAccess(dir string) bool {
	return dir == "internal/database/contexts" || dir == "internal/database/services" ||
		strings.HasPrefix(dir, "internal/database/services/") || dir == "internal/database/sqlc"
}

// checkRawHandles fails on a call to the DbContext's raw handles outside the
// database layer, which would bypass the table services.
func checkRawHandles(t *testing.T, f goFile) {
	t.Helper()
	if strings.HasPrefix(f.dir, "internal/database/") {
		return
	}
	ast.Inspect(f.ast, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && len(call.Args) == 0 {
			switch sel.Sel.Name {
			case "Queries", "DBTX", "Pool":
				t.Errorf("%s: %s() is the database layer's raw handle; go through a table service",
					f.path, sel.Sel.Name)
			}
		}
		return true
	})
}

// checkModelKinds fails when a feature service touches an HTTP model: request and
// response models belong to controllers alone.
func checkModelKinds(t *testing.T, f goFile) {
	t.Helper()
	if !isLayer(f.dir, "service") {
		return
	}
	modelPkgs := map[string]bool{}
	for name, imp := range f.imports {
		if strings.HasPrefix(imp, "internal/core/") && strings.HasSuffix(imp, "/models") {
			modelPkgs[name] = true
		}
	}
	ast.Inspect(f.ast, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if x, ok := sel.X.(*ast.Ident); ok && modelPkgs[x.Name] &&
			(strings.HasSuffix(sel.Sel.Name, "Request") || strings.HasSuffix(sel.Sel.Name, "Response")) {
			t.Errorf("%s: a service must not use the HTTP model %s.%s", f.path, x.Name, sel.Sel.Name)
		}
		return true
	})
}

// checkServiceContext fails when a controller hands its *gin.Context to a
// service as a context.Context. It compiles, but gin recycles that value once
// the handler returns, and it does not carry the request's cancellation.
func checkServiceContext(t *testing.T, f goFile) {
	t.Helper()
	if !isLayer(f.dir, "controller") {
		return
	}
	ast.Inspect(f.ast, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		fn, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		recv, ok := fn.X.(*ast.SelectorExpr)
		if !ok || recv.Sel.Name != "svc" {
			return true
		}
		if arg, ok := call.Args[0].(*ast.Ident); ok && arg.Name == "c" {
			t.Errorf("%s: pass c.Request.Context() to the service, not c", f.path)
		}
		return true
	})
}

// checkFeatureLayout fails when a feature has anything but its three layers.
func checkFeatureLayout(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "internal", "core"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		dir := "internal/core/" + e.Name()
		if !e.IsDir() || e.Name() == "shared" {
			continue
		}
		layers, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range layers {
			switch {
			case !l.IsDir():
				t.Errorf("%s/%s: a feature holds only controller/, service/ and models/", dir, l.Name())
			case l.Name() != "controller" && l.Name() != "service" && l.Name() != "models":
				t.Errorf("%s/%s: unknown layer (want controller, service or models)", dir, l.Name())
			}
		}
	}
}

func isLayer(dir, layer string) bool {
	parts := strings.Split(dir, "/")
	return len(parts) == 4 && parts[0] == "internal" && parts[1] == "core" && parts[2] != "shared" && parts[3] == layer
}

func parseModule(t *testing.T, root string) []goFile {
	t.Helper()
	fset := token.NewFileSet()
	var out []goFile
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			imports := map[string]string{}
			for _, spec := range file.Imports {
				p, _ := strconv.Unquote(spec.Path.Value)
				name := p[strings.LastIndex(p, "/")+1:]
				if spec.Name != nil {
					name = spec.Name.Name
				}
				imports[name] = strings.TrimPrefix(p, modulePath)
			}
			out = append(out, goFile{path: rel, dir: filepath.ToSlash(filepath.Dir(rel)), ast: file, imports: imports})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}
