//go:build e2e

package e2e

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Spec 002 R7.2 forbids a passphrase living in a widget, a struct field, or a
// closure past the operation that needed it. Extending a session is the agent's
// job, with a bounded lifetime, not something a window does quietly.
//
// A test cannot observe "no secret is retained" by running the window, so this
// reads the source instead: it fails if the GUI's types grow a field that looks
// like somewhere to keep one. That is a blunt instrument and it is meant to be —
// it does not prove the rule holds, it makes the most likely way of breaking it
// impossible to do without noticing.
//
// The zeroing itself is covered by unit tests beside the code, in
// internal/gui/secret_test.go.
func TestGUIKeepsNoSecretFields(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, filepath.Join("..", "..", "internal", "gui"), nil, 0)
	require.NoError(t, err)

	// Names that would be somewhere to keep a secret. "secret" as a local
	// variable is fine and expected — this only looks at struct fields.
	suspect := []string{"passphrase", "secret", "password", "recovery", "unlock"}

	for _, pkg := range pkgs {
		for path, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				st, ok := n.(*ast.StructType)
				if !ok || st.Fields == nil {
					return true
				}
				for _, f := range st.Fields.List {
					for _, name := range f.Names {
						lower := strings.ToLower(name.Name)
						for _, bad := range suspect {
							require.NotContainsf(t, lower, bad,
								"%s declares a struct field %q.\nR7.2 forbids the GUI keeping a "+
									"passphrase past the operation that needed it. If this field "+
									"holds no secret, rename it; if it does, it must not exist.",
								filepath.Base(path), name.Name)
						}
					}
				}
				return true
			})
		}
	}
}
