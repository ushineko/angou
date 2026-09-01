package cli

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/agent"
	"github.com/ushineko/angou/internal/prompt"
)

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Hold the store unlocked for a short time so commands do not re-derive a key",
		Long: "There is no gpg-agent here, so without this every command unlocks the store from\n" +
			"scratch. `angou agent start` keeps the unlocked key in memory behind a socket in\n" +
			"your runtime directory for a bounded time.\n\n" +
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
	var ttl time.Duration

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Unlock the store and hold it for --ttl",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			dir, err := storeDir()
			if err != nil {
				return err
			}
			socket, err := agent.SocketPath(dir)
			if err != nil {
				return err
			}
			if client, err := agent.Dial(dir); err == nil {
				if remaining, _, err := client.Status(); err == nil {
					return fmt.Errorf("an agent is already holding this store for another %s.\n"+
						"Stop it first with `angou agent stop`", remaining.Round(time.Second))
				}
			}

			s, err := unlock()
			if err != nil {
				return err
			}
			identity, err := s.ExportLocalIdentity()
			if err != nil {
				return err
			}
			defer prompt.Zero(identity)

			// NewServer takes its own copy, so this one is wiped straight away
			// rather than at return: the agent then runs for the whole TTL with
			// one copy of the key in memory instead of two.
			server := agent.NewServer(socket, s.Fingerprint(), identity, ttl)
			prompt.Zero(identity)
			if err := server.Listen(); err != nil {
				return err
			}
			// Best-effort, and reported as such. Failing to lock memory is not a
			// reason to refuse to run, and claiming success would be worse than
			// saying it did not happen.
			if err := agent.LockMemory(); err != nil {
				logf("could not lock memory (%v); key material may reach swap", err)
			}

			fmt.Printf("Holding %s for %s.\n", dir, ttl)
			fmt.Printf("Socket: %s\n", socket)
			fmt.Fprintln(os.Stderr, "Anything running as you can ask this agent for the key while it is up.")
			return server.Serve()
		},
	}
	cmd.Flags().DurationVar(&ttl, "ttl", agent.DefaultTTL,
		"how long to hold the key before releasing it")
	return cmd
}

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
			client, err := agent.Dial(dir)
			if err != nil {
				if errors.Is(err, agent.ErrNoAgent) {
					fmt.Printf("No agent is running for %s.\n", dir)
					return nil
				}
				return err
			}
			if err := client.Stop(); err != nil {
				return err
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
			client, err := agent.Dial(dir)
			if err != nil {
				if errors.Is(err, agent.ErrNoAgent) {
					fmt.Printf("No agent is running for %s.\n", dir)
					return nil
				}
				return err
			}
			remaining, fingerprint, err := client.Status()
			if err != nil {
				if errors.Is(err, agent.ErrExpired) {
					fmt.Printf("The agent for %s has expired and is shutting down.\n", dir)
					return nil
				}
				return err
			}
			fmt.Printf("Holding %s (identity %s) for another %s.\n",
				dir, fingerprint, remaining.Round(time.Second))
			fmt.Printf("Socket: %s\n", client.Socket())
			return nil
		},
	}
}
