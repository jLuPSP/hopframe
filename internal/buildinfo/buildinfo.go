// Package buildinfo holds build metadata threaded through every cmd/*
// binary. The values are set at link time by goreleaser via
// `-X main.{version,commit,date}`; each main package declares the
// vars and passes them to MaybePrint at the top of main().
//
// At `go build ./...` time the values stay at their dev defaults;
// only goreleaser-built binaries carry real version strings.
package buildinfo

import (
	"fmt"
	"io"
	"os"
)

// Print writes "<binary> <version> (commit <commit>, built <date>)"
// to w. Used by --version output and by structured-log boot lines.
func Print(w io.Writer, binary, version, commit, date string) {
	fmt.Fprintf(w, "%s %s (commit %s, built %s)\n", binary, version, commit, date)
}

// MaybePrint inspects os.Args for --version / -v / version as the
// first arg. Prints and exits 0 on match. Designed to run at the
// very top of main(), before flag.Parse(), so unknown-flag errors
// don't pre-empt the version request.
func MaybePrint(binary, version, commit, date string) {
	if len(os.Args) < 2 {
		return
	}
	switch os.Args[1] {
	case "--version", "-v", "version":
		Print(os.Stdout, binary, version, commit, date)
		os.Exit(0)
	}
}
