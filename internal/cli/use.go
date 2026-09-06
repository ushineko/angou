package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/core"
)

func newUseCmd() *cobra.Command {
	var forget bool

	cmd := &cobra.Command{
		Use:   "use [dir]",
		Short: "Remember which store this machine works with",
		Long: "use records a store directory so later commands do not need --store. init and\n" +
			"bootstrap already record the store they set up, so this is for changing that\n" +
			"choice or for a machine set up before the choice was recorded.\n\n" +
			"The path is written to the same file the desktop GUI reads, so both agree about\n" +
			"which store this machine works with. Only the path is written: no fingerprint,\n" +
			"no passphrase, and nothing out of the store itself.\n\n" +
			"--store on a single command still wins, and $ANGOU_STORE wins over both. A\n" +
			"one-off against another store therefore stays a one-off.\n\n" +
			"With no argument it prints what is remembered and where the answer came from.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if forget {
				if err := core.ForgetStore(); err != nil {
					return err
				}
				fmt.Println("Forgot the remembered store. Later commands need --store or $" + StoreEnv + ".")
				return nil
			}
			if len(args) == 0 {
				return reportStoreChoice()
			}
			dir := core.ExpandPath(args[0])
			// Refused rather than remembered-anyway: the point of remembering is
			// that later commands work without a path, and a remembered path
			// that holds no store just moves the failure to the next command.
			if !core.StoreExists(dir) {
				return fmt.Errorf("%s does not hold a store.\n"+
					"To create one there:   angou init %s\n"+
					"To set this machine up for one that already exists: angou bootstrap --store %s",
					dir, dir, dir)
			}
			if err := core.RememberStore(dir); err != nil {
				return err
			}
			fmt.Printf("Now using %s. Later commands need no --store.\n", dir)
			if !core.HasLocalKey(dir) {
				fmt.Println("This machine has no local key for it, so commands will ask for the " +
					"recovery passphrase until you run: angou bootstrap")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&forget, "forget", false,
		"remove the remembered store, leaving --store and $"+StoreEnv+" as the only sources")
	return cmd
}

// reportStoreChoice explains which store would be used and why. The precedence
// is worth printing rather than documenting alone: a set $ANGOU_STORE silently
// overriding a remembered choice is exactly the confusion this command exists to
// clear up.
func reportStoreChoice() error {
	remembered := core.RememberedStore()
	if remembered == "" {
		fmt.Println("No store is remembered on this machine.")
	} else {
		fmt.Println("Remembered store: " + remembered)
	}
	if global.storeDir != "" && global.storeDir != remembered {
		fmt.Println("In use right now:  " + global.storeDir +
			" (from --store or $" + StoreEnv + ", which wins)")
	}
	if remembered != "" && !core.StoreExists(remembered) {
		fmt.Println("It does not hold a store any more. Point this somewhere else with: angou use <dir>")
	}
	return nil
}
