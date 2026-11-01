package gmrtd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const fuzzWorkflowPath = ".github/workflows/fuzz.yml"

// fuzz.yml matrix entries are "- pkg: <dir>" followed by "name: <FuzzXxx>"
var fuzzMatrixEntryRe = regexp.MustCompile(`(?m)^\s*- pkg: (\S+)\s*\n\s*name: (\S+)\s*$`)

// TestFuzzWorkflowMatrixCoversAllFuzzTargets keeps the nightly fuzz workflow's matrix in sync
// with the FuzzXxx functions in the repo, as targets are only fuzzed (rather than run as seeds)
// if they are listed there.
func TestFuzzWorkflowMatrixCoversAllFuzzTargets(t *testing.T) {
	targets := findFuzzTargets(t, ".")
	matrix := readFuzzMatrix(t, fuzzWorkflowPath)

	if len(targets) == 0 || len(matrix) == 0 {
		t.Fatalf("found %d fuzz targets and %d matrix entries, expected both to be non-empty", len(targets), len(matrix))
	}

	inMatrix := map[string]bool{}
	for _, entry := range matrix {
		if inMatrix[entry] {
			t.Errorf("%s lists %q more than once", fuzzWorkflowPath, entry)
		}
		inMatrix[entry] = true
	}

	isTarget := map[string]bool{}
	for _, target := range targets {
		isTarget[target] = true
		if !inMatrix[target] {
			t.Errorf("fuzz target %q is not in the %s matrix", target, fuzzWorkflowPath)
		}
	}

	for _, entry := range matrix {
		if !isTarget[entry] {
			t.Errorf("%s lists %q, but no such fuzz target exists", fuzzWorkflowPath, entry)
		}
	}
}

// findFuzzTargets returns "<pkg> <FuzzXxx>" for each fuzz target under root, with pkg in the
// workflow's "./<dir>" form.
func findFuzzTargets(t *testing.T, root string) []string {
	t.Helper()

	var targets []string
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" || d.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		pkg := "./" + filepath.ToSlash(filepath.Dir(path))
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && isFuzzTarget(fn) {
				targets = append(targets, pkg+" "+fn.Name.Name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanning for fuzz targets: %s", err)
	}

	sort.Strings(targets)
	return targets
}

// isFuzzTarget reports whether fn is a top-level func FuzzXxx(*testing.F), as go test requires.
func isFuzzTarget(fn *ast.FuncDecl) bool {
	if fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Fuzz") || len(fn.Type.Params.List) != 1 {
		return false
	}
	star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "F"
}

func readFuzzMatrix(t *testing.T, path string) []string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %s", path, err)
	}

	var entries []string
	for _, m := range fuzzMatrixEntryRe.FindAllStringSubmatch(string(data), -1) {
		entries = append(entries, m[1]+" "+m[2])
	}
	return entries
}
