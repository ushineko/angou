package gui

import (
	"fyne.io/fyne/v2"

	"github.com/ushineko/angou/internal/core"
)

// The window and taskbar icon.
//
// The bytes live in internal/core, which is also what writes them into the
// bootstrap installer, so a machine that installs the GUI from a store gets the
// same icon this window uses. packaging/angou.svg is the same drawing again, on
// disk for install.sh to place into the icon theme.
func appIcon() fyne.Resource { return fyne.NewStaticResource("angou.svg", core.IconSVG()) }
