//go:build e2e

package e2e

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ushineko/angou/internal/cli"
	"github.com/ushineko/angou/internal/gui"
)

// CLI/GUI feature parity (spec 002 R4.3).
//
// angou ships two front ends over one store, and the project rule is that
// neither may hold an operation the other lacks. This is the test behind that
// rule: it enumerates the cobra command tree and the GUI's registered actions
// and fails when they disagree.
//
// This file imports internal packages, which the rest of this suite deliberately
// does not — every other test drives the built binary, because the claims being
// made are claims about the artifact. This one is different: it is a claim about
// the two command sets agreeing, which is a fact about the source, and there is
// no way to ask a binary what buttons a different binary has.
//
// If this fails, the fix is to implement the missing side, not to edit the
// allow-list.

// notInTheGUI are commands with no GUI affordance, each with the reason.
//
// An entry here is a decision someone made and can be argued with, which is the
// difference between an exception and an omission.
var notInTheGUI = map[string]string{
	// cobra generates this one; it has no meaning outside a shell.
	"completion": "generates shell completion scripts, which a window cannot use",
	// cobra's own; not an angou operation.
	"help": "cobra's help command",
}

func TestCLIAndGUIExposeTheSameOperations(t *testing.T) {
	inCLI := map[string]bool{}
	for _, c := range cli.Root().Commands() {
		name := strings.Fields(c.Use)[0]
		if _, skip := notInTheGUI[name]; skip {
			continue
		}
		inCLI[name] = true
	}

	inGUI := map[string]bool{}
	for _, a := range gui.Actions() {
		inGUI[a] = true
	}

	var missingFromGUI, missingFromCLI []string
	for name := range inCLI {
		if !inGUI[name] {
			missingFromGUI = append(missingFromGUI, name)
		}
	}
	for name := range inGUI {
		if !inCLI[name] {
			missingFromCLI = append(missingFromCLI, name)
		}
	}
	sort.Strings(missingFromGUI)
	sort.Strings(missingFromCLI)

	require.Emptyf(t, missingFromGUI,
		"these commands have no GUI affordance: %v\n"+
			"Implement them in internal/gui and add them to gui.Actions(), or declare the "+
			"exception in notInTheGUI with a reason.", missingFromGUI)
	require.Emptyf(t, missingFromCLI,
		"the GUI claims operations the CLI does not have: %v\n"+
			"Either the name is wrong, or a feature landed in the GUI first, which the "+
			"project rule forbids.", missingFromCLI)
}
