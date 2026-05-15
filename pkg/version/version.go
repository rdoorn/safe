// Package version exposes the SAFE build version, overridden at link time
// by -ldflags "-X github.com/rdoorn/safe/pkg/version.Version=<value>".
package version

// Version is the current build's version string. It is set by the build
// system; the source default of "dev" indicates an unstamped local build.
var Version = "dev"
