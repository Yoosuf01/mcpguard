package ratelimit_test

import (
	"testing"
	"time"

	"github.com/Yoosuf01/mcpguard/shield/internal/ratelimit"
)

func TestBasicAllow(t *testing.T) {
	l := ratelimit.New(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !l.Allow("alice") {
			t.Fatalf("call %d should be allowed", i+1)
		}
	}
	if l.Allow("alice") {
		t.Fatal("4th call should be denied")
	}
}

func TestSlidingWindow(t *testing.T) {
	l := ratelimit.New(2, 80*time.Millisecond)
	l.Allow("bob")
	l.Allow("bob")
	if l.Allow("bob") {
		t.Fatal("should be rate-limited")
	}
	time.Sleep(90 * time.Millisecond)
	if !l.Allow("bob") {
		t.Fatal("window slid; call should be allowed")
	}
}

func TestIsolatedKeys(t *testing.T) {
	l := ratelimit.New(1, time.Minute)
	if !l.Allow("alice") {
		t.Fatal("alice 1st")
	}
	if !l.Allow("bob") {
		t.Fatal("bob 1st – independent window")
	}
	if l.Allow("alice") {
		t.Fatal("alice 2nd should be denied")
	}
}

func TestRemaining(t *testing.T) {
	l := ratelimit.New(5, time.Minute)
	l.Allow("carol")
	l.Allow("carol")
	if got := l.Remaining("carol"); got != 3 {
		t.Fatalf("want 3 remaining, got %d", got)
	}
}

func TestReset(t *testing.T) {
	l := ratelimit.New(1, time.Minute)
	l.Allow("dave")
	l.Reset("dave")
	if !l.Allow("dave") {
		t.Fatal("after reset should be allowed")
	}
}
