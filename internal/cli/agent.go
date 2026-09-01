package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/agent"
	"github.com/ushineko/angou/internal/core"
)

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Hold the store unlocked for a short time so commands do not re-derive a key",
		Long: "There is no gpg-agent here, so without this every command unlocks the store from\n" +
			"scratch. `angou agent start` keeps the unlocked key in memory behind a socket in\n" +
			"your runtime directory for a bounded time.\n\n" +
			"You probably do not need it on a machine you have bootstrapped. The keyring\n" +
			"already opens the store there in about five milliseconds, and the agent saves two\n" +
			"more — while giving up something real, because the keyring's copy stops being\n" +
			"available when your wallet locks and the agent's does not. The agent is for\n" +
			"machines with no keyring, where the alternative is typing the recovery passphrase\n" +
			"and waiting a quarter of a second on every command.\n\n" +
			"Be clear about what this protects you from. The socket is readable only by you,\n" +
			"which keeps out other users on the machine. It does not keep out anything else\n" +
			"running as you: while the agent is up, any process under your account can ask it\n" +
			"for the key and get it. Checking peer credentials and wiping buffers does not\n" +
			"change that, and neither does locking memory. If something is already running as\n" +
			"you, this tool cannot defend against it, and the short lifetime is the real\n" +
			"mitigation rather than any of the machinery.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return c.Help() },
	}
	cmd.AddCommand(newAgentStartCmd(), newAgentStopCmd(), newAgentStatusCmd())
	return cmd
}

func newAgentStartCmd() *cobra.Command {
	var ttlText string

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Unlock the store and hold it for --ttl",
		Long: "start unlocks the store and holds the key until --ttl runs out.\n\n" +
			"The lifetime is the point. While the agent is up, anything running under your\n" +
			"account can ask it for the key, so how long it runs is how long that is true.\n" +
			"A long lifetime is your decision to make, but it is a decision rather than a\n" +
			"detail.\n\n" +
			"--ttl takes a number of seconds, or a number with a unit: 30s, 10m, 2h, 1d, 2w.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ttl, err := parseDuration(ttlText)
			if err != nil {
				return err
			}
			dir, err := storeDir()
			if err != nil {
				return err
			}
			socket, err := core.AgentSocket(dir)
			if err != nil {
				return err
			}
			if st, err := core.AgentState(dir); err == nil && st.Running && !st.Expired {
				return fmt.Errorf("an agent is already holding this store for another %s.\n"+
					"Stop it first with `angou agent stop`", st.Remaining.Round(time.Second))
			}

			s, err := unlock()
			if err != nil {
				return err
			}

			fmt.Printf("Holding %s for %s.\n", dir, describeTTL(ttl))
			fmt.Printf("Socket: %s\n", socket)
			fmt.Fprintln(os.Stderr, "Anything running as you can ask this agent for the key while it is up.")
			if ttl > longTTL {
				// Not a refusal — it is your machine — but the short lifetime is
				// the only thing actually limiting the exposure above, so a long
				// one should be a decision rather than a side effect.
				fmt.Fprintf(os.Stderr, "Note: %s is long enough that the lifetime stops being much of a\n"+
					"limit. `angou agent stop` ends it whenever you are done.\n", describeTTL(ttl))
			}
			return core.StartAgent(s, socket, ttl, events())
		},
	}
	cmd.Flags().StringVar(&ttlText, "ttl", agent.DefaultTTL.String(),
		"how long to hold the key: seconds, or a number with a unit (30s, 10m, 2h, 1d, 2w)")
	return cmd
}

// longTTL is where holding the key stops being a convenience and starts being
// the state the machine is normally in.
const longTTL = 8 * time.Hour

func newAgentStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop",
		Short: "Release the cached key material now, before the TTL expires",
		Long: "stop terminates the agent for this store. Use it when you are done, and as part\n" +
			"of responding to a machine you no longer trust: it releases the key, the naming\n" +
			"key, and the decrypted index without waiting for the lifetime to run out.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			dir, err := storeDir()
			if err != nil {
				return err
			}
			stopped, err := core.StopAgent(dir)
			if err != nil {
				return err
			}
			if !stopped {
				fmt.Printf("No agent is running for %s.\n", dir)
				return nil
			}
			fmt.Printf("Stopped the agent for %s.\n", dir)
			return nil
		},
	}
}

func newAgentStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report whether an agent is holding this store, and for how much longer",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			dir, err := storeDir()
			if err != nil {
				return err
			}
			st, err := core.AgentState(dir)
			if err != nil {
				return err
			}
			switch {
			case !st.Running:
				fmt.Printf("No agent is running for %s.\n", dir)
			case st.Expired:
				fmt.Printf("The agent for %s has expired and is shutting down.\n", dir)
			default:
				fmt.Printf("Holding %s (identity %s) for another %s.\n",
					dir, st.Fingerprint, st.Remaining.Round(time.Second))
				fmt.Printf("Socket: %s\n", st.Socket)
			}
			return nil
		},
	}
}
