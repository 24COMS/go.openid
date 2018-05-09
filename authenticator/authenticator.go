package authenticator

//go:generate charlatan -output ./mock/mock.go -package authenticatorMock Authenticator

// Authenticator describes authenticators methods
type Authenticator interface {
	// GetToken try to get cached access token if it is still valid, or generate a new one
	GetToken(scope string) (token string, err error)
}
