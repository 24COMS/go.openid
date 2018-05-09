package auth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/24COMS/go.isempty"
	"github.com/24COMS/go.openid/authenticator"
	"github.com/24COMS/go.openid/validator"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Config is used to provide dependencies to New() and create Authenticator instance
type Config struct {
	Logger    logrus.FieldLogger
	Validator access.Validator
	GrantType grantType

	// Other fields could be added for different grant types
	ClientID     string
	ClientSecret string
}

type grantType string

var (
	// ClientCredentials is for "client_credentials"
	ClientCredentials grantType = "client_credentials"
)

// New will create instance of authenticator using provided Config
func New(cfg Config) (authenticator.Authenticator, error) {
	if isEmpty.Values(cfg.ClientSecret, cfg.ClientID, cfg.Logger, cfg.Validator) {
		return nil, errors.New("some configs are empty")
	}
	if cfg.GrantType != ClientCredentials {
		return nil, errors.New("grant type is not supported")
	}

	a := &auth{
		grantType:    string(cfg.GrantType),
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,

		validator: cfg.Validator,
		logger:    cfg.Logger,
		cache:     make(map[string]cachedToken),
	}
	return a, nil
}

type auth struct {
	grantType    string
	clientID     string
	clientSecret string

	validator access.Validator
	logger    logrus.FieldLogger
	cache     map[string]cachedToken
}

const contentType = "application/x-www-form-urlencoded"

func (a *auth) GetToken(scope string) (string, error) {
	// First trying to get cached token
	var token string
	if cached, ok := a.cache[scope]; ok {
		if time.Now().Add(time.Minute).Before(cached.ExpiresAt) {
			token = cached.AccessToken
		} else {
			delete(a.cache, scope)
		}
	}
	if token != "" {
		return token, nil
	}

	// If cached token was not found or it was expired
	endpoint := a.validator.GetOpenIDConfig().TokenEndpoint
	if endpoint == "" {
		return "", errors.New("failed to get token endpoint")
	}

	data := url.Values{
		"grant_type":    []string{a.grantType},
		"client_id":     []string{a.clientID},
		"client_secret": []string{a.clientSecret},
		"scope":         []string{scope},
	}

	resp, err := http.Post(endpoint, contentType, strings.NewReader(data.Encode()))
	if err != nil {
		return "", errors.Wrap(err, "failed to execute post request")
	}
	defer func() {
		err = resp.Body.Close()
		if err != nil {
			a.logger.Warn(errors.Wrap(err, "failed to close response body"))
		}
	}()

	var r authResp
	err = json.NewDecoder(resp.Body).Decode(&r)
	if err != nil {
		return "", errors.Wrap(err, "failed to decode response")
	}

	a.cache[scope] = cachedToken{
		AccessToken: r.AccessToken,
		ExpiresAt:   time.Now().Add(time.Second * time.Duration(r.ExpiresIn)),
	}

	return r.AccessToken, nil
}

type authResp struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type cachedToken struct {
	AccessToken string
	ExpiresAt   time.Time
}
