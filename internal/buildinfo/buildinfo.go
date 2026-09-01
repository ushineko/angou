// Package buildinfo carries what this binary was built from.
//
// It is a package of its own because the values are program metadata rather
// than part of any format. They previously sat in the container package, which
// made the format's package the place you went to ask what version the program
// was — a coupling that existed only because that is where the -ldflags path
// happened to point.
package buildinfo

// Version and Commit are injected at build time via -ldflags.
var (
	Version = "dev"
	Commit  = "unknown"
)
