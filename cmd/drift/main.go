// Command drift is the Drift CLI entrypoint.
//
// See docs/rfc/rfc-v01-drift-workspace.md for the design and
// docs/design/dd3-implementation-plan.md for the phased plan.
package main

import (
	"fmt"
	"os"

	"github.com/sufforest/drift/internal/cli"
)

func main() {
	if err := cli.Root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "drift:", err)
		os.Exit(1)
	}
}
