package access

import "crypto/rsa"

// Validator describes common interface for all permission validators
type Validator interface {
	CheckRSAExpiration() error
	GetRSAPubKeys() []*rsa.PublicKey
	ValidateApplicationToken(accessToken string) (bool, error)
	ValidateUserToken(accessToken string) (uint64, uint64, bool, error)
}
