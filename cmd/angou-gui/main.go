// Command angou-gui is the desktop front end (spec 002).
//
// It is a separate binary from cmd/angou on purpose. This one needs CGO,
// OpenGL, and a display server; the CLI needs none of those and must not, since
// spec 001's bootstrap and bare-machine recovery claims rest on it being a
// static, dependency-free artifact (spec 002 R1.3, R2.2).
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ushineko/angou/internal/buildinfo"
	"github.com/ushineko/angou/internal/gui"
)

func main() {
	// The two flags exist for tools/screenshot.sh. Deep-linking into a section
	// is what makes the README captures reproducible: without it, refreshing
	// them means clicking through the window against a timer, and a set that is
	// tedious to refresh goes stale.
	section := flag.String("section", "",
		"open on this section: "+strings.Join(gui.SectionNames(), ", "))
	scheme := flag.String("scheme", "",
		"use this colour scheme for this run without saving it: "+strings.Join(gui.SchemeNames(), ", "))
	scan := flag.String("scan", "",
		"scan this directory on startup, for documentation captures")
	version := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *version {
		fmt.Printf("angou-gui %s (%s)\n", buildinfo.Version, buildinfo.Commit)
		os.Exit(0)
	}

	gui.Run(gui.Options{Version: buildinfo.Version, Section: *section, Scheme: *scheme, Scan: *scan})
}
