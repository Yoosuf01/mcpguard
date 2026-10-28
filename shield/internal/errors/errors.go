// Package errors defines MCPGuard's typed, structured error hierarchy.
// All public surfaces return *Error so callers can inspect Code and Retryable
// without string-matching.
package errors

import "fmt"

// Code is a machine-readable error classification.
type Code string

const (
	CodeUnauthorized    Code = "UNAUTHORIZED"
	CodeForbidden       Code = "FORBIDDEN"
	CodeInvalidInput    Code = "INVALID_INPUT"
	CodeUpstream        Code = "UPSTREAM_ERROR"
	CodePolicyViolation Code = "POLICY_VIOLATION"
	CodeRateLimit       Code = "RATE_LIMIT"
	CodeInternal        Code = "INTERNAL"
	CodeUnavailable     Code = "UNAVAILABLE"
	CodeTimeout         Code = "TIMEOUT"
)

// Error is the canonical MCPGuard error type.
type Error struct {
	Code      Code
	Message   string
	Retryable bool
	Cause     error
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Cause }

// New constructs a non-retryable Error.
func New(code Code, msg string) *Error { return &Error{Code: code, Message: msg} }

// Wrap wraps an underlying error.
func Wrap(code Code, msg string, cause error) *Error {
	return &Error{Code: code, Message: msg, Cause: cause}
}

// RetryableError constructs a retryable Error (e.g. upstream temporarily down).
func RetryableError(code Code, msg string, cause error) *Error {
	return &Error{Code: code, Message: msg, Cause: cause, Retryable: true}
}

// Is satisfies errors.Is for code-based matching.
func Is(err error, code Code) bool {
	var e *Error
	if As(err, &e) {
		return e.Code == code
	}
	return false
}

// As is a convenience wrapper around the stdlib errors.As.
func As(err error, target **Error) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(*Error); ok {
		*target = e
		return true
	}
	return false
}
