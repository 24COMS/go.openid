package middleware

import (
	"net/http"

	"context"

	"github.com/24COMS/go.openid/validator"
	"github.com/24COMS/go.openid/validator/openID"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/urfave/negroni"
)

// ContextKey defines the type that the middleware will use to set / get http.Request context values
type ContextKey string

const (
	// ContextKeyToken is used to get / set the bearer token in the http.Request context
	ContextKeyToken ContextKey = "token"
)

var _ negroni.Handler = (*middleware)(nil)

// middleware contains all the middleware dependencies
type middleware struct {
	requiredScopes []string
	logger         logrus.FieldLogger
	validator      access.Validator
}

// New creates a new openid middleware object and sets all dependencies
func New(logger logrus.FieldLogger, requiredScopes []string, validator access.Validator) (negroni.Handler, error) {
	m := &middleware{
		logger:         logger,
		validator:      validator,
		requiredScopes: requiredScopes,
	}

	return m, nil
}

// ServeHTTP implements negroni.Handler interface
func (m *middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	tokenStr, err := request.AuthorizationHeaderExtractor.ExtractToken(r)
	if err != nil {
		m.logger.Info(errors.Wrap(err, "failed to extract token"))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	token, err := m.validator.GetAndValidateToken(tokenStr, m.requiredScopes...)
	if err != nil {
		m.logger.Info(errors.Wrap(err, "failed to validate token"))
		if err == openidvalidator.ErrForbidden {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	next(w, r.WithContext(context.WithValue(r.Context(), ContextKeyToken, token)))
}
