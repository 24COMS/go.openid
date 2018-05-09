/* This package contains functions to validate OpenId access tokens.
*  The tokens are checked for expiration, valid format, valid signing (with public key from OpenId discovery) and subject/issuer (if applicable).
 */

package openidvalidator

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/24COMS/go.openid/validator"
	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// validator struct implements openID validator
type validator struct {
	lastConfig            access.OpenIDConfig
	discoveryURI          string
	RSAPubKey             *rsa.PublicKey
	expiresAt             time.Time
	evaluationInterval    time.Duration
	defaultRequiredScopes []string

	logger logrus.FieldLogger
	mu     *sync.RWMutex
}

const openIDCfgPath = "/.well-known/openid-configuration"

// Config for new openID validator
type Config struct {
	Logger                logrus.FieldLogger
	Domain                string
	EvaluationInterval    time.Duration
	DefaultRequiredScopes []string
}

// New creates validator which implements access.Validator interface
// discoveryURI is the uri to the openid discovery document.
// evaluationInterval is the interval (in minutest) after which the RSAPublicKey
// will be automatically re-acquired from the discovery source.
// DefaultRequiredScopes is self-explanatory. Will be used in case if requiredScopes were not specified on method call.
func New(ctx context.Context, wg *sync.WaitGroup, cfg Config) (access.Validator, error) {
	v := validator{
		mu:                    &sync.RWMutex{},
		logger:                cfg.Logger,
		evaluationInterval:    cfg.EvaluationInterval,
		defaultRequiredScopes: cfg.DefaultRequiredScopes,
	}

	if !strings.HasSuffix(cfg.Domain, openIDCfgPath) {
		cfg.Domain += openIDCfgPath
	}

	v.discoveryURI = cfg.Domain

	// With empty v.expiresAt it will get new key and set v.expiresAt
	err := v.CheckRSAExpiration()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get public key")
	}

	//Print everything, for debugging
	v.logger.Debugf(
		"Uri:%s\nPubKey:%T\nexpiresAt:%s\nevaluationInterval:%d\n",
		v.discoveryURI, v.RSAPubKey,
		v.expiresAt.UTC().Format(time.UnixDate),
		v.evaluationInterval,
	)

	//Start the refresh cycle
	err = v.autoRefreshPublicKey(ctx, wg)

	//If everything went fine, returns nil. Otherwise it returns the error
	return &v, err
}

//Refreshes the public key after the interval has passed. If it has already been refreshed in the mean-time, don't refresh it.
func (v validator) autoRefreshPublicKey(ctx context.Context, wg *sync.WaitGroup) error {
	wg.Add(1)
	go func() {
		// -1 minute to be sure that token was re-acquired before expiration
		ticker := time.NewTicker(v.evaluationInterval - time.Minute)
		defer func() {
			ticker.Stop()
			wg.Done()
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Check if key should be refreshed
				err := v.CheckRSAExpiration()
				if err != nil {
					v.logger.Error(errors.Wrap(err, "failed to refresh public key"))
				}
			}
		}
	}()
	return nil
}

// Validates the user token by verifying the signing with the discovery endpoints public key. Then checks the subject. Then checks if the issuer is the same domain as the discovery endpoint.
// If requiredScopes is not specified, defaultRequiredScopes which was defined on init will be used.
// Then checks present scopes against the list of defaultRequiredScopes. If all tests pass, the token is valid and the userID, userType, validFlag and err are returned.
func (v validator) ValidateUserToken(accessToken string, requiredScopes ...string) (uint64, uint64, bool, error) {
	token, err := v.GetAndValidateToken(accessToken, requiredScopes...)
	if err != nil {
		return 0, 0, false, err
	}

	// Also get the subject & userType
	// TODO: proper name for the userType
	subString, _ := token.Claims().Subject()
	sub, err := strconv.ParseUint(subString, 10, 64)
	if err != nil {
		return 0, 0, false, errors.Wrap(err, "failed to parse subject to uint64")
	}

	userType, ok := token.Claims().Get("type").(uint64)
	if !ok {
		// Not found, so no userType. Set to 0
		userType = 0
	}

	// Success
	return sub, userType, true, nil
}

// Validates the application token by verifying the signing with the discovery endpoints public key. Then checks if the issuer is the same domain as the discovery endpoint.
// If requiredScopes is not specified, defaultRequiredScopes which was defined on init will be used.
// Then checks present scopes against the list of defaultRequiredScopes. If all tests pass, the token is valid and the userID, userType, validFlag and err are returned.
func (v validator) ValidateApplicationToken(accessToken string, requiredScopes ...string) (bool, error) {
	_, err := v.GetAndValidateToken(accessToken, requiredScopes...)
	if err != nil {
		return false, err
	}

	// Success
	return true, nil
}

// GetAndValidateToken validates the application token by verifying the signing with the discovery endpoints public key. Then checks if the issuer is the same domain as the discovery endpoint.
// Then checks present scopes against the list of defaultRequiredScopes. If all tests pass, the token is valid and the JWT and err are returned.
func (v validator) GetAndValidateToken(accessToken string, requiredScopes ...string) (jwt.JWT, error) {
	token, scopes, err := v.getJWTAndScopes(accessToken)
	if err != nil {
		return nil, err
	}

	// Check if the issuer is from the same domain as the discovery document
	if issuer, _ := token.Claims().Issuer(); !strings.Contains(v.discoveryURI, issuer) {
		// Issuer does not match discoveryURI -> Forbidden
		return nil, errors.New("issuer does not match discoveryURI")
	}

	if len(requiredScopes) == 0 {
		requiredScopes = v.defaultRequiredScopes
	}

	// Check all the requiredScope(s) against the present ones
	if !checkScope(scopes, requiredScopes) {
		// Required scopes are not all present -> Forbidden
		return nil, ErrForbidden
	}

	audience, _ := token.Claims().Audience()
	if !checkAudience(audience, requiredScopes) {
		// audience was not present -> Forbidden
		return nil, errors.New("audience was not present")
	}

	// Success
	return token, nil
}

func (v validator) getJWTAndScopes(accessToken string) (jwt.JWT, []string, error) {
	// Parse the accesstoken as JWT token
	parsedJWT, err := jws.ParseJWT([]byte(accessToken))
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to Parse JWT token")
	}

	// Validate token
	if err = parsedJWT.Validate(v.RSAPubKey, crypto.SigningMethodRS256); err != nil {
		// The signing of the token was not valid -> Unauthorized
		return nil, nil, errors.Wrap(err, "failed to Validate JWT")
	}

	// Check for claims, audience and issuer
	scopes := parsedJWT.Claims().Get("scope").([]interface{})

	// convert the scope interfaces to a string slice
	scopeStrings := make([]string, len(scopes))
	for i, v := range scopes {
		if scope, ok := v.(string); ok {
			scopeStrings[i] = scope
		}
	}

	return parsedJWT, scopeStrings, nil
}

func checkScope(scopes []string, requiredScopes []string) bool {
	// First checking if user has enough number of scopes
	if len(scopes) < len(requiredScopes) {
		return false
	}

	// Create set of unique user scopes
	userScopes := make(map[string]struct{}, len(scopes))
	for _, sc := range scopes {
		userScopes[sc] = struct{}{}
	}

	// Iterating over slice of required scopes. Return false on first absent scope
	for _, reqScope := range requiredScopes {
		if _, ok := userScopes[reqScope]; !ok {
			return false
		}
	}
	return true
}

func checkAudience(audiences []string, wantedAudiences []string) bool {
	// Create set of unique user audiences
	currentAudiences := make(map[string]struct{}, len(audiences))
	for _, aud := range audiences {
		currentAudiences[aud] = struct{}{}
	}

	// Iterating over slice of required audiences. Return true on first found value
	for _, req := range wantedAudiences {
		if _, ok := currentAudiences[req]; ok {
			return true
		}
	}
	return false
}

func (v *validator) CheckRSAExpiration() error {
	// Check if the expiresAt is in the past
	if time.Now().After(v.expiresAt) {
		v.mu.Lock()
		defer v.mu.Unlock()

		v.logger.Info("getting a new RSAPublicKey")

		err := v.updateOpenIDConfig()
		if err != nil {
			return errors.Wrap(err, "failed to update openID configuration")
		}
		//first get the pemBytes from the discovery endpoint
		data, err := v.getPublicKeyCertificate()
		if err != nil {
			v.logger.Info("Failed getPublicKeyCertificate()")
			return err
		}

		// From those data, parse the public key
		v.RSAPubKey, err = crypto.ParseRSAPublicKeyFromPEM(data)
		if err != nil {
			return errors.Wrap(err, "failed to Parse RSA public key")
		}
		v.logger.Info("New PublicKey retrieved from discovery endpoint.")

		// Now reset the expiresAt (expiration) timestamp
		v.expiresAt = time.Now().Add(v.evaluationInterval)

	}
	return nil
}

func (v *validator) updateOpenIDConfig() error {
	// First get the openidconfiguration from the .well-known endpoint
	req, err := http.NewRequest("GET", v.discoveryURI, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		err = resp.Body.Close()
		if err != nil {
			v.logger.Warn(errors.Wrap(err, "failed to close body after call "+v.discoveryURI))
		}
	}()

	// Fill the record with the data from the JSON
	// Note: JSON returned is always an array, even when its a single object
	var openIDConfig access.OpenIDConfig

	// Use json.Decode for reading streams of JSON data
	err = json.NewDecoder(resp.Body).Decode(&openIDConfig)
	if err != nil {
		return err
	}

	v.lastConfig = openIDConfig
	return nil
}

func (v *validator) GetRSAPubKeys() []*rsa.PublicKey {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return []*rsa.PublicKey{v.RSAPubKey}
}

func (v *validator) GetOpenIDConfig() access.OpenIDConfig {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return v.lastConfig
}

// Get the OpenIdconfiguration based on the baseUri, then get the publickey from jwks. Return []byte containing the PEM-bytes
func (v *validator) getPublicKeyCertificate() ([]byte, error) {
	// Then use the JwksUri to get the JWKS values
	req, err := http.NewRequest("GET", v.lastConfig.JwksURI, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = resp.Body.Close()
		if err != nil {
			v.logger.Warn(errors.Wrap(err, "failed to close body after call for JWKS"))
		}
	}()

	// Fill the record with the data from the JSON
	// Note: JSON returned is always an array, even when its a single object
	var jwksValues access.JWKS

	// Use json.Decode for reading streams of JSON data
	err = json.NewDecoder(resp.Body).Decode(&jwksValues)
	if err != nil {
		return nil, err
	}

	// Return the X5C (certificate) of the key first Key
	// TODO: Make it select proper key depending on x5t and kid
	//Change DER to PEM formatted
	b := bytes.Buffer{}
	b.WriteString("-----BEGIN CERTIFICATE-----\n")
	b.WriteString(jwksValues.Keys[0].X5C[0])
	b.WriteString("\n-----END CERTIFICATE-----\n")
	return b.Bytes(), nil
}
