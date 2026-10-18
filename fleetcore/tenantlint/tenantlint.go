// Package tenantlint is a test helper that keeps tenant isolation from depending on every future change remembering it. Tenants share collections, and what keeps them apart is that
// every query is scoped and every document is stamped through the store's own helpers. This checks the source: every call on a MongoDB collection must build its filter with one of those
// helpers (or be marked "// tenant-ok: reason" because the collection is global by design), and every insert must stamp what it writes.
package tenantlint

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// Options names the helpers of a package.
type Options struct {
	// Scopes are the functions and methods that put the tenant into a filter or an _id: scope, pk, key...
	Scopes []string
	// Stamps are those that put the tenant into a document being written.
	Stamps []string
}

var filterArg = map[string]int{
	"Find": 1, "FindOne": 1, "FindOneAndUpdate": 1, "FindOneAndDelete": 1, "FindOneAndReplace": 1,
	"UpdateOne": 1, "UpdateMany": 1, "ReplaceOne": 1, "DeleteOne": 1, "DeleteMany": 1, "CountDocuments": 1, "Distinct": 2, "Aggregate": 1,
}

var writeArg = map[string]int{"InsertOne": 1, "InsertMany": 1}

// Check reports every collection call in the non-test Go files of dir that is neither tenant-scoped nor marked.
func Check(t *testing.T, dir string, o Options) {
	t.Helper()
	checkDir(t, token.NewFileSet(), dir, o)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func checkDir(t *testing.T, fset *token.FileSet, dir string, o Options) {
	t.Helper()
	problems, checked, err := Find(fset, dir, o)
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatalf("tenantlint found no collection calls in %s: the check would prove nothing", dir)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// Find returns the problems in a directory and how many collection calls it looked at.
func Find(fset *token.FileSet, dir string, o Options) (problems []string, checked int, err error) {
	pkgs, err := parser.ParseDir(fset, dir, nil, parser.ParseComments)
	if err != nil {
		return nil, 0, err
	}
	for _, pkg := range pkgs {
		for fname, file := range pkg.Files {
			if strings.HasSuffix(fname, "_test.go") {
				continue
			}
			marked := map[int]bool{}
			for _, cg := range file.Comments {
				for _, c := range cg.List {
					if strings.Contains(c.Text, "tenant-ok:") {
						ln := fset.Position(c.Pos()).Line
						marked[ln], marked[ln+1] = true, true
					}
				}
			}
			for _, d := range file.Decls {
				fn, isFn := d.(*ast.FuncDecl)
				if !isFn || fn.Body == nil {
					continue
				}
				// identifiers assigned from a helper call in this function: a filter built in one statement and used in another
				helped := map[string]bool{}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if as, ok := n.(*ast.AssignStmt); ok {
						for i, rhs := range as.Rhs {
							if usesHelper(rhs, append(append([]string{}, o.Scopes...), o.Stamps...), helped) {
								lhs := as.Lhs[0]
								if i < len(as.Lhs) {
									lhs = as.Lhs[i]
								}
								switch l := lhs.(type) {
								case *ast.Ident:
									helped[l.Name] = true
								case *ast.IndexExpr: // docs[i] = s.stamp(...)
									if id, ok := l.X.(*ast.Ident); ok {
										helped[id.Name] = true
									}
								}
							}
						}
					}
					return true
				})
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, isCall := n.(*ast.CallExpr)
					if !isCall {
						return true
					}
					sel, isSel := call.Fun.(*ast.SelectorExpr)
					if !isSel || !onCollection(sel.X) {
						return true
					}
					op := sel.Sel.Name
					pos := fset.Position(call.Pos())
					if i, ok := filterArg[op]; ok {
						checked++
						if i < len(call.Args) && usesHelper(call.Args[i], o.Scopes, helped) {
							return true
						}
						if marked[pos.Line] {
							return true
						}
						problems = append(problems, pos.String()+": "+op+" in "+fn.Name.Name+" does not scope its filter by tenant")
					}
					if i, ok := writeArg[op]; ok {
						checked++
						if i < len(call.Args) && usesHelper(call.Args[i], o.Stamps, helped) {
							return true
						}
						if marked[pos.Line] {
							return true
						}
						problems = append(problems, pos.String()+": "+op+" in "+fn.Name.Name+" does not stamp its document with the tenant")
					}
					if op == "BulkWrite" {
						checked++
						if i := 1; i < len(call.Args) {
							// the operations carry their own filters: they must use a scoping helper somewhere in the function
							if usesHelperIn(fn.Body, o.Scopes) || marked[pos.Line] {
								return true
							}
						}
						problems = append(problems, pos.String()+": BulkWrite in "+fn.Name.Name+" builds no operation with a tenant helper")
					}
					return true
				})
			}
		}
	}
	sort.Strings(problems)
	return problems, checked, nil
}

// onCollection reports whether expr is a call to .Collection(...) or a field named coll (the receiver of a collection operation).
func onCollection(x ast.Expr) bool {
	switch t := x.(type) {
	case *ast.CallExpr:
		s, ok := t.Fun.(*ast.SelectorExpr)
		return ok && s.Sel.Name == "Collection"
	case *ast.SelectorExpr:
		return t.Sel.Name == "coll" || t.Sel.Name == "c"
	}
	return false
}

// usesHelper reports whether the expression contains a call to one of the helpers, or names a variable that was built with one.
func usesHelper(e ast.Expr, helpers []string, helped map[string]bool) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		switch t := n.(type) {
		case *ast.CallExpr:
			switch f := t.Fun.(type) {
			case *ast.SelectorExpr:
				if contains(helpers, f.Sel.Name) {
					found = true
				}
			case *ast.Ident:
				if contains(helpers, f.Name) {
					found = true
				}
			}
		case *ast.Ident:
			if helped[t.Name] {
				found = true
			}
		}
		return !found
	})
	return found
}

func usesHelperIn(body *ast.BlockStmt, helpers []string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if s, ok := c.Fun.(*ast.SelectorExpr); ok && contains(helpers, s.Sel.Name) {
				found = true
			}
		}
		return !found
	})
	return found
}
