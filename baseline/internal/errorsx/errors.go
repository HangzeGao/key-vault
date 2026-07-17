package errorsx

import (
	stderrors "errors"
	"fmt"
)

// Code is a stable error code string.
type Code string

const (
	CodeAuthFailed             Code = "AUTH_FAILED"
	CodePermissionDenied       Code = "PERMISSION_DENIED"
	CodeKeyNotFound            Code = "KEY_NOT_FOUND"
	CodeKeyDisabled            Code = "KEY_DISABLED"
	CodeKeyDestroyed           Code = "KEY_DESTROYED"
	CodePolicyDenied           Code = "POLICY_DENIED"
	CodeAADMismatch            Code = "AAD_MISMATCH"
	CodeEnvelopeInvalid        Code = "ENVELOPE_INVALID"
	CodeNonceExhausted         Code = "NONCE_EXHAUSTED"
	CodeTPMUnavailable         Code = "TPM_UNAVAILABLE"
	CodeDBConflict             Code = "DB_CONFLICT"
	CodeIdempotencyKeyReused   Code = "IDEMPOTENCY_KEY_REUSED"
	CodeAuditUnavailable       Code = "AUDIT_UNAVAILABLE"
	CodeRateLimited            Code = "RATE_LIMITED"
	CodeBadRequest             Code = "BAD_REQUEST"
	CodeInternal               Code = "INTERNAL"
	CodeNodeNotReady           Code = "NODE_NOT_READY"
	CodeNodeFrozen             Code = "NODE_FROZEN"
	CodeBaselineCheckFailed    Code = "BASELINE_CHECK_FAILED"
	CodeInvalidArgument        Code = "INVALID_ARGUMENT"
)

// Error is the structured error type returned by all layers.
type Error struct {
	Code      Code
	Message   string
	Cause     error
	Retryable bool
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Cause }

// New creates a new Error.
func New(code Code, msg string, retryable bool) *Error {
	return &Error{Code: code, Message: msg, Retryable: retryable}
}

// Wrap creates a new Error wrapping a cause.
func Wrap(code Code, msg string, retryable bool, cause error) *Error {
	return &Error{Code: code, Message: msg, Cause: cause, Retryable: retryable}
}

// AsCode extracts the Code from an error if it is *Error; otherwise CodeInternal.
func AsCode(err error) Code {
	if err == nil {
		return ""
	}
	var e *Error
	if stderrors.As(err, &e) {
		return e.Code
	}
	return CodeInternal
}

// AsRetryable extracts the Retryable flag.
func AsRetryable(err error) bool {
	if err == nil {
		return false
	}
	var e *Error
	if stderrors.As(err, &e) {
		return e.Retryable
	}
	return false
}

// AsMessage extracts the Message from an error if it is *Error; otherwise falls back to err.Error().
func AsMessage(err error) string {
	if err == nil {
		return ""
	}
	var e *Error
	if stderrors.As(err, &e) {
		return e.Message
	}
	return err.Error()
}

// HTTPStatus maps a Code to an HTTP status code per design §18.1.
func HTTPStatus(code Code) int {
	switch code {
	case CodeAuthFailed:
		return 401
	case CodePermissionDenied, CodeKeyNotFound, CodeKeyDestroyed:
		return 403 // cross-tenant 404/403 unified per HA-11
	case CodeKeyDisabled, CodeDBConflict, CodeIdempotencyKeyReused:
		return 409
	case CodeBadRequest, CodePolicyDenied, CodeAADMismatch, CodeEnvelopeInvalid, CodeInvalidArgument:
		return 400
	case CodeNonceExhausted, CodeRateLimited:
		return 429
	case CodeTPMUnavailable, CodeAuditUnavailable:
		return 503
	case CodeNodeNotReady, CodeNodeFrozen, CodeBaselineCheckFailed:
		return 409
	default:
		return 500
	}
}

// Sentinel errors.
var (
	ErrEnvelopeInvalid = New(CodeEnvelopeInvalid, "envelope invalid", false)
	ErrAADMismatch     = New(CodeAADMismatch, "aad mismatch", false)
)
