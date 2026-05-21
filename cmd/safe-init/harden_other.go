//go:build !linux

package main

// hardenAgentSubtree is a no-op on non-Linux because safe-init only
// runs on Linux (it refuses to run elsewhere in main()). The stub
// exists so the package compiles on macOS for developer ergonomics.
func hardenAgentSubtree() error {
	return nil
}
