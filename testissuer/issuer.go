/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
adapted from https://github.com/chainguard-dev/go-oidctest
*/

package testissuer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// UserLoginCookie specifies the user you want to login with that you dont have
// to specify the user manually in a test. Also see the Issuer.Login method.
const UserLoginCookie = "oprox_test_issuer_user"

type Server struct {
	*Issuer
	*httptest.Server
}

// NewServer starts a httptest.Server and configures an issuer accordingly.
// When running NewServer you don't have to supply an IssuerURL in the config
// becuase it gets set based on the random URL where the httptest.Server
// started.
func NewServer(config *Config) (*Server, error) {
	if config == nil {
		config = NewDefaultConfig()
	}

	server := httptest.NewUnstartedServer(nil)

	config.IssuerURL = "http://" + server.Listener.Addr().String()

	issuer, err := New(config)
	if err != nil {
		server.Close()
		return nil, err
	}

	server.Config.Handler = issuer
	server.Start()

	return &Server{
		Server: server,
		Issuer: issuer,
	}, nil
}

// Config for the Issuer
type Config struct {
	Logger *slog.Logger

	IssuerURL string

	TokenLifetime    time.Duration
	GetUserClaims    UserClaimFunc
	AccessTokenIsJWT bool
}

func NewDefaultConfig() *Config {
	return &Config{
		Logger:        slog.Default(),
		IssuerURL:     "http://localhost:4444",
		TokenLifetime: time.Minute * 30,
		GetUserClaims: DefaultUserClaims(),
	}
}

// Issuer is a test implementation for an OIDC/OAuth2 IDP.
type Issuer struct {
	*Config

	// key and signing
	privateKey crypto.Signer
	jsonWebKey jose.JSONWebKey
	Signer     jose.Signer

	ServeMux *http.ServeMux
}

// New creates a new test issuer
func New(config *Config) (*Issuer, error) {
	var err error

	if config == nil {
		config = NewDefaultConfig()
	}

	issuer := &Issuer{
		Config: config,
	}

	issuer.privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("cannot generate RSA key: %w", err)
	}

	issuer.jsonWebKey = jose.JSONWebKey{
		Algorithm: string(jose.RS256),
		Key:       issuer.privateKey,
	}

	issuer.Signer, err = jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       issuer.jsonWebKey.Key,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("jose.NewSigner(): %w", err)
	}

	issuer.ServeMux = http.NewServeMux()
	issuer.ServeMux.HandleFunc("/.well-known/openid-configuration", issuer.OpenIDDiscovery)
	issuer.ServeMux.HandleFunc("/keys", issuer.JWKS)
	issuer.ServeMux.HandleFunc("/authz", issuer.Authz)
	issuer.ServeMux.HandleFunc("/token", issuer.Token)
	return issuer, nil
}

func (i *Issuer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	i.ServeMux.ServeHTTP(w, r)
}

func (i *Issuer) MustGetToken(authInfo *AuthTokenInfo) string {
	token, err := i.GetToken(authInfo)
	if err != nil {
		panic("failed to create token: " + err.Error())
	}
	return token
}

func (i *Issuer) GetToken(authInfo *AuthTokenInfo) (string, error) {
	standardClaims := struct {
		jwt.Claims `json:",inline"` // nolint:revive // unknown option 'inline' in JSON tag

		Nonce string `json:"nonce,omitempty"`
	}{
		Claims: jwt.Claims{
			Issuer:   i.IssuerURL,
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Expiry:   jwt.NewNumericDate(time.Now().Add(i.TokenLifetime)),
			Subject:  authInfo.User,
			Audience: jwt.Audience{authInfo.ClientID},
		},
		Nonce: authInfo.Nonce,
	}

	jwtBuilder := jwt.Signed(i.Signer).Claims(standardClaims)

	extraUserClaims := i.GetUserClaims(authInfo.User)

	if extraUserClaims != nil {
		jwtBuilder = jwtBuilder.Claims(extraUserClaims)
	}

	if authInfo.Claims != nil {
		jwtBuilder = jwtBuilder.Claims(authInfo.Claims)
	}

	return jwtBuilder.CompactSerialize()
}

func (i *Issuer) Token(w http.ResponseWriter, r *http.Request) {
	i.Logger.InfoContext(r.Context(), "Handling request for token.")

	grantType := r.FormValue("grant_type")
	if grantType != "authorization_code" {
		http.Error(w, "grant_type "+grantType+" not supported", http.StatusInternalServerError)
		return
	}

	authCode := r.FormValue("code")
	if authCode == "" {
		http.Error(w, "code missing", http.StatusInternalServerError)
		return
	}
	authInfo := &AuthTokenInfo{}
	err := decode(authCode, authInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	tokenResponse := struct {
		TokenType    string `json:"token_type"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token,omitempty"`
		IdToken      string `json:"id_token,omitempty"`
		ExpiresIn    int    `json:"expires_in,omitempty"`
	}{
		TokenType: "Bearer",
		ExpiresIn: int(i.TokenLifetime.Truncate(time.Second).Seconds()),
	}

	idToken, err := i.GetToken(authInfo)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// add access token
	if i.AccessTokenIsJWT {
		tokenResponse.AccessToken = idToken
	} else {
		accessTokenInfo := *authInfo
		accessTokenInfo.Type = TypeAccessToken

		accessToken, err := encode(accessTokenInfo) //nolint:govet
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		tokenResponse.AccessToken = accessToken
	}

	// add id_token
	if slices.Contains(authInfo.Scope, "openid") {
		tokenResponse.IdToken = idToken
	}

	// add refresh_token
	if slices.Contains(authInfo.Scope, "offline_access") {
		refreshTokenInfo := *authInfo
		refreshTokenInfo.Type = TypeRefreshToken

		accessToken, err := encode(refreshTokenInfo) //nolint:govet
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		tokenResponse.RefreshToken = accessToken
	}

	out, err := json.Marshal(&tokenResponse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	_, _ = w.Write(out)
}

const (
	TypeCode         = "code"
	TypeAccessToken  = "access_token"
	TypeRefreshToken = "refresh_token"
)

// AuthTokenInfo is used to keep state between calls
type AuthTokenInfo struct {
	Type     string   `json:"type"`
	ClientID string   `json:"client_id"`
	Nonce    string   `json:"nonce"`
	Scope    []string `json:"scope"`
	User     string   `json:"user"`

	// Claims add additional claims or overwrite existing claims. This
	// has to be of type map[string]any or struct.
	Claims any `json:"extra"`
}

func encode(t any) (string, error) {
	out, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(out), nil
}

func decode(token string, t any) error {
	data, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, t)
	if err != nil {
		return err
	}
	return nil
}

func (i *Issuer) Authz(w http.ResponseWriter, r *http.Request) {
	i.Logger.InfoContext(r.Context(), "Handling request for authz.")
	redirectURL, err := url.Parse(r.URL.Query().Get("redirect_uri"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// get the user either from query parameter or cookie
	var user string
	if queryUser := r.URL.Query().Get("user"); queryUser != "" {
		user = queryUser
	} else {
		cookie, err := r.Cookie(UserLoginCookie) //nolint:govet
		if err == nil {
			user = cookie.Value
		}
	}

	// if not user is supplied show form to login manually
	if user == "" {
		// user selection
		fmt.Fprintf(w, `<html>
				<body>
				</body>
				<h1>Test Issuer Login Form</h1>
				<form>
					<input type="text" name="user" value="username" />
					<input type="submit" action="%s" />
				</form>
			</html>
			`, r.RequestURI)
		return
	}

	if claims := i.GetUserClaims(user); claims == nil {
		http.Error(w, fmt.Sprintf("user '%s' does not exist", user), http.StatusUnauthorized)
		return
	}

	// Rely on `code` as a mechanism to encode information required by the token
	// endpoint.
	code, err := encode(AuthTokenInfo{
		Type:     TypeCode,
		ClientID: r.URL.Query().Get("client_id"),
		Nonce:    r.URL.Query().Get("nonce"),
		User:     user,
		Scope:    strings.Split(r.URL.Query().Get("scope"), " "),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	v := url.Values{
		"state": {r.URL.Query().Get("state")},
		"code":  {code},
	}
	redirectURL.RawQuery = v.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (i *Issuer) OpenIDDiscovery(w http.ResponseWriter, r *http.Request) {
	i.Logger.InfoContext(r.Context(), "Handling request for openid-configuration.")
	if err := json.NewEncoder(w).Encode(struct {
		Issuer        string `json:"issuer"`
		JWKSURI       string `json:"jwks_uri"`
		AuthzEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint string `json:"token_endpoint"`
	}{
		Issuer:        i.IssuerURL,
		JWKSURI:       i.IssuerURL + "/keys",
		AuthzEndpoint: i.IssuerURL + "/authz",
		TokenEndpoint: i.IssuerURL + "/token",
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (i *Issuer) JWKS(w http.ResponseWriter, r *http.Request) {
	i.Logger.InfoContext(r.Context(), "Handling request for jwks.")
	w.Header().Add("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			i.jsonWebKey.Public(),
		},
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (i *Issuer) Login(user string, c *http.Client) error {
	var err error
	if c.Jar == nil {
		c.Jar, err = cookiejar.New(nil)
		if err != nil {
			return err
		}
	}

	cookie := &http.Cookie{
		Name:     UserLoginCookie,
		Value:    user,
		Path:     "/",
		Secure:   false,
		HttpOnly: false,
	}

	u, err := url.Parse(i.IssuerURL)
	if err != nil {
		return err
	}
	c.Jar.SetCookies(u, []*http.Cookie{cookie})
	return nil
}
