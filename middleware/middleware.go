package middleware

import (
	"net/http"

	"context"

	"crypto/rsa"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// ContextKey defines the type that the middleware will use to set / get http.Request context values
type ContextKey string

const (
	// ContextKeyToken is used to get / set the bearer token in the http.Request context
	ContextKeyToken ContextKey = "token"
)

// Middleware contains all the middleware dependencies
type Middleware struct {
	requiredScopes []string
	logger         logrus.FieldLogger
	rsaPublicKey   []*rsa.PublicKey
}

// New creates a new openid Middleware object and sets all dependencies
func New(logger logrus.FieldLogger, requiredScopes []string, key ...*rsa.PublicKey) (*Middleware, error) {
	m := &Middleware{
		logger:         logger,
		rsaPublicKey:   key,
		requiredScopes: requiredScopes,
	}

	return m, nil
}

// SetRSAPublicKey will configure the new RSA keys to check the bearer access token signature
func (m *Middleware) SetRSAPublicKey(rsaPublicKey []*rsa.PublicKey) {
	m.rsaPublicKey = rsaPublicKey
}

func (m *Middleware) checkRequiredScopes(scopes []string) bool {
	// Check the scope and requiredScopes for matches
	count := 0
	for _, sc := range scopes {
		for _, requiredScope := range m.requiredScopes {
			if requiredScope == sc {
				count++
			}
		}
	}

	// If all the required scope are in the scope of the token, the scope are valid
	return count == len(m.requiredScopes)
}

// Wrap adds the middleware to the given handler
func (m *Middleware) Wrap(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		validToken := false
		var token *jwt.Token
		for _, key := range m.rsaPublicKey {
			t, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor, func(token *jwt.Token) (interface{}, error) {
				return key, nil
			})

			// Check if no errors
			if err == nil {
				token = t
				validToken = true
				break
			}
		}

		if !validToken {
			if m.logger != nil {
				m.logger.WithField("err", errors.New("token invalid")).Infof("Error validating token in OpenID middleware")
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Check if the required audience is present
		claims := token.Claims.(jwt.MapClaims)
		actualScopes := claims["scope"].([]interface{})
		var scopes []string
		for _, aud := range actualScopes {
			scopes = append(scopes, aud.(string))
		}

		if !m.checkRequiredScopes(scopes) {
			if m.logger != nil {
				m.logger.WithField("requiredScopes", m.requiredScopes).WithField("scopes", scopes).Infof("Error validating token in OpenID middleware, required scopes not available")
			}
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Execute the next handler
		handler(w, r.WithContext(context.WithValue(r.Context(), ContextKeyToken, token)))
	}
}
