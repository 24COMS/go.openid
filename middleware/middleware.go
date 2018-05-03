package middleware

import (
	"net/http"

	"context"

	"github.com/24COMS/go.openid/validator"
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
	validator      access.Validator
}

// New creates a new openid Middleware object and sets all dependencies
func New(logger logrus.FieldLogger, requiredScopes []string, validator access.Validator) (*Middleware, error) {
	m := &Middleware{
		logger:         logger,
		validator:      validator,
		requiredScopes: requiredScopes,
	}

	return m, nil
}

func (m *Middleware) checkRequiredScopes(scopes []string) bool {
	// First checking if user has enough number of scopes
	if len(scopes) < len(m.requiredScopes) {
		return false
	}

	// Create set of unique user scopes
	userScopes := make(map[string]struct{}, len(scopes))
	for _, sc := range scopes {
		userScopes[sc] = struct{}{}
	}

	// Iterating over slice of required scopes. Return false on first absent scope
	for _, reqScope := range m.requiredScopes {
		if _, ok := userScopes[reqScope]; !ok {
			return false
		}
	}
	return true
}

// Wrap adds the middleware to the given handler
func (m *Middleware) Wrap(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var token *jwt.Token
		for _, key := range m.validator.GetRSAPubKeys() {
			t, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor, func(_ *jwt.Token) (interface{}, error) {
				return key, nil
			})
			if err != nil {
				m.logger.Info(errors.Wrap(err, "failed to parse JWT from request"))
				continue
			}

			token = t
			break
		}

		if token == nil {
			m.logger.WithField("err", errors.New("token invalid")).Info("Error validating token in OpenID middleware")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Check if the required audience is present
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			m.logger.Error("failed to assert type (jwt.MapClaims) from token.Claims")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		actualScopes, ok := claims["scope"].([]interface{})
		if !ok {
			m.logger.Error(`failed to assert type ([]interface{}) from claims["scope"]`)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var scopes []string
		for _, aud := range actualScopes {
			if scope, ok := aud.(string); ok {
				scopes = append(scopes, scope)
			}
		}

		if !m.checkRequiredScopes(scopes) {
			m.logger.WithField("requiredScopes", m.requiredScopes).WithField("scopes", scopes).Info("Error validating token in OpenID middleware, required scopes not available")
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Execute the next handler
		handler(w, r.WithContext(context.WithValue(r.Context(), ContextKeyToken, token)))
	}
}
