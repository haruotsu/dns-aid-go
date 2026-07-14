package dnsaid_test

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"strings"
	"testing"
)

// TestPublicAPIDoesNotLeakInternalTypes type-checks the package and walks
// every exported declaration: no exported function signature, struct field,
// variable, or constant may reference a type defined under internal/
// (R-CLI-4). Library consumers outside this module cannot import internal
// packages, so a leaked internal type would make the API unusable.
func TestPublicAPIDoesNotLeakInternalTypes(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("no non-test Go files found")
	}

	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	pkg, err := conf.Check("github.com/haruotsu/dns-aid-go/pkg/dnsaid", fset, files, nil)
	if err != nil {
		t.Fatalf("type-check package: %v", err)
	}

	scope := pkg.Scope()
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		if !obj.Exported() {
			continue
		}
		if leaked := findInternalType(obj.Type(), make(map[types.Type]bool)); leaked != "" {
			t.Errorf("exported %s %s references internal type %s", objKind(obj), name, leaked)
		}
	}
}

// TestExampleFilesDoNotImportInternal parses every test file that declares
// an Example function and rejects imports of internal packages. Examples are
// rendered on godoc/pkg.go.dev as copy-paste templates for consumers outside
// this module, who cannot import internal packages.
func TestExampleFilesDoNotImportInternal(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		hasExample := false
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Example") {
				hasExample = true
				break
			}
		}
		if !hasExample {
			continue
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if isInternalPkgPath(path) {
				t.Errorf("%s declares an Example but imports internal package %s", name, path)
			}
		}
	}
}

// TestIsInternalPkgPath pins the internal-package detection shared by the
// API-surface and Example guards: both bare ".../internal" packages and
// packages nested under ".../internal/" are internal, while names that merely
// start with "internal" are not.
func TestIsInternalPkgPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"github.com/haruotsu/dns-aid-go/internal", true},
		{"github.com/haruotsu/dns-aid-go/internal/discover", true},
		{"github.com/haruotsu/dns-aid-go/internalfoo", false},
		{"github.com/haruotsu/dns-aid-go/pkg/dnsaid", false},
		{"github.com/haruotsu/dns-aid-go/xinternal", false},
	}
	for _, tt := range tests {
		if got := isInternalPkgPath(tt.path); got != tt.want {
			t.Errorf("isInternalPkgPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// isInternalPkgPath reports whether path names a Go internal package: either
// a bare ".../internal" package or one nested under an internal directory.
// Prefix matching alone would wrongly flag names like "internalfoo".
func isInternalPkgPath(path string) bool {
	return strings.Contains(path, "/internal/") || strings.HasSuffix(path, "/internal")
}

func objKind(obj types.Object) string {
	switch obj.(type) {
	case *types.Func:
		return "func"
	case *types.TypeName:
		return "type"
	case *types.Var:
		return "var"
	case *types.Const:
		return "const"
	}
	return "object"
}

// findInternalType walks t and returns the string of the first named type
// found whose defining package is internal (isInternalPkgPath), or "" when
// there is none. seen breaks cycles (e.g. recursive struct types).
func findInternalType(t types.Type, seen map[types.Type]bool) string {
	if t == nil {
		return ""
	}
	// Resolve alias declarations (type A = B); with gotypesalias enabled
	// they are distinct *types.Alias nodes wrapping the actual type.
	t = types.Unalias(t)
	if seen[t] {
		return ""
	}
	seen[t] = true

	switch t := t.(type) {
	case *types.Named:
		if p := t.Obj().Pkg(); p != nil && isInternalPkgPath(p.Path()) {
			return t.String()
		}
		// Type arguments of generic instantiations (e.g. box[internalT])
		// need not appear in the underlying type or method set.
		for arg := range t.TypeArgs().Types() {
			if leaked := findInternalType(arg, seen); leaked != "" {
				return leaked
			}
		}
		// Exported methods are part of the public surface even when the
		// underlying type does not mention their parameter/result types.
		for m := range t.Methods() {
			if !m.Exported() {
				continue
			}
			if leaked := findInternalType(m.Signature(), seen); leaked != "" {
				return leaked
			}
		}
		return findInternalType(t.Underlying(), seen)
	case *types.Pointer:
		return findInternalType(t.Elem(), seen)
	case *types.Slice:
		return findInternalType(t.Elem(), seen)
	case *types.Array:
		return findInternalType(t.Elem(), seen)
	case *types.Map:
		if leaked := findInternalType(t.Key(), seen); leaked != "" {
			return leaked
		}
		return findInternalType(t.Elem(), seen)
	case *types.Chan:
		return findInternalType(t.Elem(), seen)
	case *types.Struct:
		for field := range t.Fields() {
			if leaked := findInternalType(field.Type(), seen); leaked != "" {
				return leaked
			}
		}
	case *types.Signature:
		for param := range t.Params().Variables() {
			if leaked := findInternalType(param.Type(), seen); leaked != "" {
				return leaked
			}
		}
		for result := range t.Results().Variables() {
			if leaked := findInternalType(result.Type(), seen); leaked != "" {
				return leaked
			}
		}
	case *types.Interface:
		for method := range t.Methods() {
			if leaked := findInternalType(method.Type(), seen); leaked != "" {
				return leaked
			}
		}
	}
	return ""
}
