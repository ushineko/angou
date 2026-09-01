package gui

import (
	_ "embed"

	"fyne.io/fyne/v2"
)

// The window and taskbar icon. It is embedded rather than loaded from disk so
// the GUI keeps the CLI's property of needing nothing installed alongside it to
// run — one binary, no asset directory to lose.
//
// packaging/angou.svg is the same file, installed for the .desktop entry.
//
//go:embed assets/angou.svg
var iconSVG []byte

func appIcon() fyne.Resource { return fyne.NewStaticResource("angou.svg", iconSVG) }
