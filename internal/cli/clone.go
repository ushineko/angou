package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/ushineko/angou/internal/release"
	"github.com/ushineko/angou/internal/store"
)

func newCloneCmd() *cobra.Command {
	var (
		to         string
		noBinaries bool
	)

	cmd := &cobra.Command{
		Use:   "clone",
		Short: "Copy a store to another directory",
		Long: "clone copies a store verbatim, so the copy opens with the same recovery\n" +
			"passphrase and holds the same secrets. Treat it exactly as you treat the\n" +
			"original.\n\n" +
			"--no-binaries omits the platform binaries, which are usually most of the size. A\n" +
			"store copied that way still holds every secret and still opens; it just cannot\n" +
			"bootstrap a bare machine on its own.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if to == "" {
				return fmt.Errorf("clone needs --to")
			}
			from, err := storeDir()
			if err != nil {
				return err
			}
			if _, err := os.Stat(filepath.Join(from, store.MetaName)); err != nil {
				return fmt.Errorf("%w: %s", store.ErrNotAStore, from)
			}
			if _, err := os.Stat(to); err == nil {
				return fmt.Errorf("%s already exists; clone will not write into it", to)
			}
			n, err := copyStore(from, to, noBinaries)
			if err != nil {
				return err
			}
			fmt.Printf("Cloned %s to %s (%d files).\n", from, to, n)
			if noBinaries {
				fmt.Fprintln(os.Stderr, "The platform binaries were omitted. This copy cannot bootstrap a bare\n"+
					"machine; it still holds every secret the original does.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "destination directory, which must not already exist")
	cmd.Flags().BoolVar(&noBinaries, "no-binaries", false,
		"omit the platform binaries from the copy (R5.10)")
	return cmd
}

func copyStore(from, to string, noBinaries bool) (int, error) {
	count := 0
	err := filepath.Walk(from, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return fmt.Errorf("resolve %s relative to %s: %w", path, from, err)
		}
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(to, rel), 0o700)
		}
		if noBinaries && isReleaseBinary(rel) {
			return nil
		}
		if err := copyFile(path, filepath.Join(to, rel), info.Mode()); err != nil {
			return err
		}
		count++
		return nil
	})
	if err != nil {
		return count, fmt.Errorf("copy store: %w", err)
	}
	return count, nil
}

// isReleaseBinary reports whether a store-relative path is a stashed binary or
// one of its companions.
func isReleaseBinary(rel string) bool {
	dir, name := filepath.Split(filepath.ToSlash(rel))
	if strings.TrimSuffix(dir, "/") != store.BootstrapDir {
		return false
	}
	base := strings.TrimSuffix(strings.TrimSuffix(name, release.SignatureSuffix), release.MetadataSuffix)
	_, _, _, ok := release.ParseBinaryName(base)
	return ok
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer func() { _ = in.Close() }()

	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(dst), err)
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode.Perm())
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("write %s: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", dst, err)
	}
	return nil
}
