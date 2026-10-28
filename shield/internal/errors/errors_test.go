package errors_test

import (
	"testing"

	mcperr "github.com/Yoosuf01/mcpguard/shield/internal/errors"
)

func TestErrorFormatting(t *testing.T) {
	e := mcperr.New(mcperr.CodeForbidden, "tool not allowed")
	if e.Error() != "[FORBIDDEN] tool not allowed" {
		t.Fatalf("unexpected: %s", e.Error())
	}
}

func TestWrapUnwrap(t *testing.T) {
	cause := mcperr.New(mcperr.CodeUpstream, "upstream down")
	wrapped := mcperr.Wrap(mcperr.CodeUnavailable, "gateway unavailable", cause)
	if wrapped.Unwrap() != cause {
		t.Fatal("Unwrap should return cause")
	}
}

func TestIs(t *testing.T) {
	e := mcperr.New(mcperr.CodeRateLimit, "too many requests")
	if !mcperr.Is(e, mcperr.CodeRateLimit) {
		t.Fatal("Is should match code")
	}
	if mcperr.Is(e, mcperr.CodeForbidden) {
		t.Fatal("Is should not match different code")
	}
}

func TestRetryable(t *testing.T) {
	e := mcperr.RetryableError(mcperr.CodeUnavailable, "retry me", nil)
	if !e.Retryable {
		t.Fatal("expected Retryable=true")
	}
}
