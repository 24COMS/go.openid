package access

import (
	"crypto/rsa"

	"github.com/SermoDigital/jose/jwt"
)

//go:generate charlatan -output ./mock/mock.go -package validatorMock Validator

// Validator describes common interface for all permission validators
type Validator interface {
	UpdateKeys() error
	GetRSAPubKeys() []*rsa.PublicKey
	ValidateApplicationToken(accessToken string, requiredScopes ...string) (bool, error)
	GetAndValidateToken(accessToken string, requiredScopes ...string) (jwt.JWT, error)
	ValidateUserToken(accessToken string, requiredScopes ...string) (uint64, uint64, bool, error)
	GetOpenIDConfig() OpenIDConfig
}
