package pins

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestFileStore_PersistAndList(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "pins.json")

	store1, err := NewFileStore(tmpFile)
	if err != nil {
		t.Fatalf("failed to create FileStore: %v", err)
	}

	key := "tool|postgres|query"
	digest := "sha256:1111222233334444"
	store1.Set(key, digest)

	// Verify in store1
	val, ok := store1.Get(key)
	if !ok || val != digest {
		t.Fatalf("expected digest in store1, got %s (ok=%v)", val, ok)
	}

	// Verify persistence in store2 created from the same file (simulating process restart)
	store2, err := NewFileStore(tmpFile)
	if err != nil {
		t.Fatalf("failed to reload FileStore: %v", err)
	}
	val2, ok2 := store2.Get(key)
	if !ok2 || val2 != digest {
		t.Fatalf("expected persisted digest in store2, got %s (ok=%v)", val2, ok2)
	}

	list := store2.List()
	if len(list) != 1 || list[0].Server != "postgres" || list[0].Tool != "query" {
		t.Errorf("unexpected list output: %+v", list)
	}
}

func TestFileStore_ApproveAndDiff(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "pins.json")
	store, _ := NewFileStore(tmpFile)

	server := "weather"
	tool := "forecast"
	oldDigest := "sha256:aaaa"
	newDigest := "sha256:bbbb"

	store.Set("tool|weather|forecast", oldDigest)

	diffText := Diff(server, tool, oldDigest, newDigest)
	if !strings.Contains(diffText, "DRIFT DETECTED") {
		t.Errorf("expected DRIFT DETECTED in diff, got: %s", diffText)
	}

	// Re-approve tool
	if err := store.Approve(server, tool, newDigest); err != nil {
		t.Fatalf("Approve failed: %v", err)
	}

	val, ok := store.Get("tool|weather|forecast")
	if !ok || val != newDigest {
		t.Fatalf("expected re-approved digest %s, got %s", newDigest, val)
	}
}
