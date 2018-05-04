package openidvalidator

import "github.com/pkg/errors"

var (
	// ErrForbidden will be returned if user scopes does not satisfy required scopes
	ErrForbidden = errors.New("access is forbidden")
)
