// Package version exposes build-time metadata injected via -ldflags.
package version

import "fmt"

// Set at build time:
//
//	go build -ldflags "-X .../version.Version=v1.0.0 -X .../version.Commit=abc1234 ..."
var (
	Version   = "dev"
	Commit    = "none"
	BuildDate = "unknown"
)

// Info returns a human-readable one-liner.
func Info() string {
	return fmt.Sprintf("mcpguard %s (commit=%s built=%s)", Version, Commit, BuildDate)
}

// Short returns just the semver string.
func Short() string { return Version }
