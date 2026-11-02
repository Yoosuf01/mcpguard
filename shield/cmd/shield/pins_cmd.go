package main

import (
	"fmt"
	"os"
	"time"

	"github.com/Yoosuf01/mcpguard/shield/internal/pins"
)

func handlePinsCommand(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: mcpguard pins [list|diff|approve] ...")
		os.Exit(1)
	}
	pinsFile := "configs/pins.json"
	store, err := pins.NewFileStore(pinsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading pins: %v\n", err)
		os.Exit(1)
	}

	switch args[0] {
	case "list":
		records := store.List()
		if len(records) == 0 {
			fmt.Println("No pins recorded yet.")
			return
		}
		fmt.Printf("%-20s %-20s %-32s %s\n", "SERVER", "TOOL", "DIGEST", "UPDATED")
		for _, r := range records {
			digestDisplay := r.Digest
			if len(digestDisplay) > 24 {
				digestDisplay = digestDisplay[:24] + "..."
			}
			fmt.Printf("%-20s %-20s %-32s %s\n", r.Server, r.Tool, digestDisplay, r.UpdatedAt.Format(time.RFC3339))
		}
	case "diff":
		if len(args) < 4 {
			fmt.Println("Usage: mcpguard pins diff <server> <tool> <new_digest>")
			os.Exit(1)
		}
		server, tool, newDigest := args[1], args[2], args[3]
		oldDigest, _ := store.Get(fmt.Sprintf("tool|%s|%s", server, tool))
		fmt.Print(pins.Diff(server, tool, oldDigest, newDigest))
	case "approve":
		if len(args) < 4 {
			fmt.Println("Usage: mcpguard pins approve <server> <tool> <new_digest>")
			os.Exit(1)
		}
		server, tool, newDigest := args[1], args[2], args[3]
		if err := store.Approve(server, tool, newDigest); err != nil {
			fmt.Fprintf(os.Stderr, "failed to approve pin: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Approved tool %s/%s with digest %s\n", server, tool, newDigest)
	default:
		fmt.Fprintf(os.Stderr, "unknown pins subcommand: %s\n", args[0])
		os.Exit(1)
	}
}
