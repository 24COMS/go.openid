/* This package contains functions to validate OpenId access tokens.
*  The tokens are checked for expiration, valid format, valid signing (with public key from OpenId discovery) and subject/issuer (if applicable).
 */

package openidvalidator

import (
	"24coms-dialog/validator"
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// validator struct implements openID validator
type validator struct {
	discoveryURI       string
	RSAPubKey          *rsa.PublicKey
	expiresAt          time.Time
	evaluationInterval time.Duration
	requiredScopes     []string
	logger             logrus.FieldLogger
}

const openIDCfgPath = "/.well-known/openid-configuration"

// New creates validator which implements access.Validator interface
// discoveryURI is the uri to the openid discovery document.
// evaluationInterval is the interval (in minutest) after which the RSAPublicKey
// will be automatically re-acquired from the discovery source. RequiredScopes is self-explanatory.
func New(ctx context.Context, wg *sync.WaitGroup, logger logrus.FieldLogger, domain string, evaluationInterval time.Duration, requiredScopes []string) (access.Validator, error) {
	v := validator{
		logger:             logger,
		expiresAt:          time.Now().Add(evaluationInterval),
		evaluationInterval: evaluationInterval,
		requiredScopes:     requiredScopes,
	}

	if !strings.HasSuffix(domain, openIDCfgPath) {
		domain += openIDCfgPath
	}

	v.discoveryURI = domain

	//first get the pemBytes from the discovery endpoint
	data, err := v.getPublicKeyCertificate(v.discoveryURI)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get Public Key Certificate")
	}

	// From those data, parse the public key
	v.RSAPubKey, err = crypto.ParseRSAPublicKeyFromPEM(data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to Parse RSA public key")
	}

	//Print everything, for debugging
	logger.Debugf("Uri:%s\nPubKey:%T\nexpiresAt:%s\nevaluationInterval:%d\n", v.discoveryURI, v.RSAPubKey, v.expiresAt.UTC().Format(time.UnixDate), evaluationInterval)

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
		ticker := time.NewTicker(v.evaluationInterval - 1)
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
// Then checks present scopes against the list of requiredScopes. If all tests pass, the token is valid and the userID, userType, validFlag and err are returned.
func (v validator) ValidateUserToken(accessToken string) (uint64, uint64, bool, error) {
	token, scopes, err := v.getJWTAndScopes(accessToken)
	if err != nil {
		return 0, 0, false, err
	}

	audience, _ := token.Claims().Audience()

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

	// Check if the issuer is from the same domain as the discovery document
	if issuer, _ := token.Claims().Issuer(); !strings.Contains(v.discoveryURI, issuer) {
		// Issuer does not match discoveryURI -> Forbidden
		return sub, userType, false, nil
	}

	// Check all the requiredScope(s) against the present ones
	if !checkScope(scopes, v.requiredScopes) {
		// Required scopes are not all present -> Forbidden
		return sub, userType, false, nil
	}
	if !checkAudience(audience, v.requiredScopes) {
		// audience was not present -> Forbidden
		return sub, userType, false, nil
	}

	// Success
	return sub, userType, true, nil
}

// Validates the application token by verifying the signing with the discovery endpoints public key. Then checks if the issuer is the same domain as the discovery endpoint.
// Then checks present scopes against the list of requiredScopes. If all tests pass, the token is valid and the userID, userType, validFlag and err are returned.
func (v validator) ValidateApplicationToken(accessToken string) (bool, error) {
	token, scopes, err := v.getJWTAndScopes(accessToken)
	if err != nil {
		return false, err
	}

	audience, _ := token.Claims().Audience()

	// Check if the issuer is from the same domain as the discovery document
	if issuer, _ := token.Claims().Issuer(); !strings.Contains(v.discoveryURI, issuer) {
		// Issuer does not match discoveryURI -> Forbidden
		return false, nil
	}

	// Check all the requiredScope(s) against the present ones
	if !checkScope(scopes, v.requiredScopes) {
		// Required scopes are not all present -> Forbidden
		return false, nil
	}
	if !checkAudience(audience, v.requiredScopes) {
		// audience was not present -> Forbidden
		return false, nil
	}

	// Success
	return true, nil
}

func (v validator) getJWTAndScopes(accessToken string) (jwt.JWT, []string, error) {
	//Check if the current RSAPubKey is still valid and has not expired.
	err := v.CheckRSAExpiration()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to checkRSAExpiration")
	}

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
	scope := parsedJWT.Claims().Get("scope").([]interface{})

	// convert the scope interfaces to a string slice
	scopeStrings := make([]string, len(scope))
	for _, v := range scope {
		scopeStrings = append(scopeStrings, v.(string))
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
	// Recursively check the scope and requiredScopes for matches
	count := 0
	for _, aud := range audiences {
		for _, wtaud := range wantedAudiences {
			if wtaud == aud {
				count++
			}
		}
	}
	// At least one match was found, so the audience is valid
	return count > 0
}

func (v *validator) CheckRSAExpiration() error {
	// Check if the expiresAt is in the past
	if time.Now().After(v.expiresAt) {
		v.logger.Info("RSAPublicKey is expired, get a new one from the discoveryURI")

		//first get the pemBytes from the discovery endpoint
		data, err := v.getPublicKeyCertificate(v.discoveryURI)
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

func (v validator) GetRSAPubKeys() []*rsa.PublicKey {
	return []*rsa.PublicKey{v.RSAPubKey}
}

// Get the OpenIdconfiguration based on the baseUri, then get the publickey from jwks. Return []byte containing the PEM-bytes
func (v validator) getPublicKeyCertificate(discoveryURI string) ([]byte, error) {
	// First get the openidconfiguration from the .well-known endpoint
	req, err := http.NewRequest("GET", discoveryURI, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = resp.Body.Close()
		if err != nil {
			v.logger.Warn(errors.Wrap(err, "failed to close body after call "+discoveryURI))
		}
	}()

	// Fill the record with the data from the JSON
	// Note: JSON returned is always an array, even when its a single object
	var openIDConfig OpenIDConfig

	// Use json.Decode for reading streams of JSON data
	err = json.NewDecoder(resp.Body).Decode(&openIDConfig)
	if err != nil {
		return nil, err
	}

	// Then use the JwksUri to get the JWKS values
	req, err = http.NewRequest("GET", openIDConfig.JwksURI, nil)
	if err != nil {
		return nil, err
	}

	resp, err = client.Do(req)
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
	var jwksValues JWKS

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