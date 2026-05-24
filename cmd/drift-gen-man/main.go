// drift-gen-man generates man pages for every drift command via Cobra.
// Usage: drift-gen-man <out-dir>
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra/doc"

	"github.com/sufforest/drift/internal/cli"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: drift-gen-man <out-dir>")
		os.Exit(2)
	}
	outDir := os.Args[1]
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	root := cli.Root()
	root.DisableAutoGenTag = true
	header := &doc.GenManHeader{
		Title:   "DRIFT",
		Section: "1",
		Source:  "drift",
		Manual:  "drift manual",
		Date:    timePtr(),
	}
	if err := doc.GenManTree(root, header, outDir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func timePtr() *time.Time {
	t := time.Now().UTC()
	return &t
}
