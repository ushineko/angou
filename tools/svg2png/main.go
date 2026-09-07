// Command svg2png rasterises an SVG to a square PNG at a given pixel size,
// scaling the viewBox to fill the canvas.
//
// It exists for tools/make-icns.sh. qlmanage, the built-in that script reached
// for first, produces a Quick Look *thumbnail*: it drew the logo at roughly its
// native 64px in a mostly empty 1024px canvas, so the app icon came out tiny.
// This renders the vector to fill the target instead, using the same
// oksvg/rasterx stack fyne uses to draw the in-app icon — so the bundle's icon
// matches the window's — and needs no ImageMagick or librsvg, only the Go
// toolchain the build already requires.
package main

import (
	"fmt"
	"image"
	"image/png"
	"os"
	"strconv"

	"github.com/srwiley/oksvg"
	"github.com/srwiley/rasterx"
)

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "svg2png:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 4 {
		return fmt.Errorf("usage: svg2png <in.svg> <out.png> <size>")
	}
	size, err := strconv.Atoi(args[3])
	if err != nil || size <= 0 {
		return fmt.Errorf("bad size %q", args[3])
	}

	// The paths are Makefile arguments, not untrusted input; this is a build
	// tool, so the file-open lints do not apply.
	in, err := os.Open(args[1]) //nolint:gosec // build tool; path is a Makefile argument
	if err != nil {
		return fmt.Errorf("open %s: %w", args[1], err)
	}
	defer func() { _ = in.Close() }()

	icon, err := oksvg.ReadIconStream(in)
	if err != nil {
		return fmt.Errorf("parse %s: %w", args[1], err)
	}
	// Scale the viewBox to fill the square target. The SVG carries its own
	// padding, so the logo sits inside the canvas with a margin rather than
	// bleeding to the edges.
	icon.SetTarget(0, 0, float64(size), float64(size))

	rgba := image.NewRGBA(image.Rect(0, 0, size, size))
	scanner := rasterx.NewScannerGV(size, size, rgba, rgba.Bounds())
	raster := rasterx.NewDasher(size, size, scanner)
	icon.Draw(raster, 1.0)

	out, err := os.Create(args[2]) //nolint:gosec // build tool; path is a Makefile argument
	if err != nil {
		return fmt.Errorf("create %s: %w", args[2], err)
	}
	if err := png.Encode(out, rgba); err != nil {
		_ = out.Close()
		return fmt.Errorf("encode: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", args[2], err)
	}
	return nil
}
