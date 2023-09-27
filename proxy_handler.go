package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/dvob/oidc-proxy/cookie"
	"golang.org/x/oauth2"
)

type Provider struct {
	Name                   string     `json:"name"`
	IssuerURL              string     `json:"issuer_url"`
	ClientID               string     `json:"client_id"`
	ClientSecret           string     `json:"client_secret"`
	Scopes                 []string   `json:"scopes"`
	AuthorizationParameter url.Values `json:"authorization_parameters"`
	TokenParameters        url.Values `json:"token_parameters"`
	Endpoints
}

type Endpoints struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
}

// Merge sets e to e2 if e is not set
func (e *Endpoints) Merge(e2 *Endpoints) {
	if e.AuthorizationEndpoint == "" {
		e.AuthorizationEndpoint = e2.AuthorizationEndpoint
	}
	if e.TokenEndpoint == "" {
		e.TokenEndpoint = e2.TokenEndpoint
	}
	if e.IntrospectionEndpoint == "" {
		e.IntrospectionEndpoint = e2.IntrospectionEndpoint
	}
	if e.UserinfoEndpoint == "" {
		e.UserinfoEndpoint = e2.UserinfoEndpoint
	}
	if e.EndSessionEndpoint == "" {
		e.EndSessionEndpoint = e2.EndSessionEndpoint
	}
	if e.RevocationEndpoint == "" {
		e.RevocationEndpoint = e2.RevocationEndpoint
	}
}

type OIDCProxyConfig struct {
	// OAuth2 / OIDC
	Providers map[string]Provider

	CallbackURL string

	// handler pathes
	LoginPath  string
	LogoutPath string

	// secure cookie
	HashKey    []byte
	EncryptKey []byte
}

func NewOIDCProxyHandler(config *OIDCProxyConfig, next http.Handler) (*OIDCProxyHandler, error) {
	callbackURL, err := url.Parse(config.CallbackURL)
	if err != nil {
		return nil, err
	}

	// Setup Cookiehandler
	hashKey := config.HashKey
	encKey := config.EncryptKey

	if len(hashKey) == 0 {
		slog.Warn("no cookie hash key configuerd. sessions will not be persistent accross restarts.")
		hashKey, err = generateKey(32)
		if err != nil {
			return nil, err
		}
	}
	if len(encKey) == 0 {
		encKey = nil
	}

	if !(len(hashKey) == 32 || len(hashKey) == 64) {
		return nil, fmt.Errorf("hash key has invalid key length. a length of 32 or 64 is required")
	}
	if !(len(encKey) == 0 || len(encKey) == 32 || len(encKey) == 64) {
		return nil, fmt.Errorf("hash key has invalid key length. a length of 32 or 64 is required")
	}

	cookieHandler := cookie.NewCookieHandler(hashKey, encKey)

	providers := map[string]provider{}
	// Perform OIDC dicovery
	// TODO: do not fail on startup
	for name, providerConfig := range config.Providers {
		provider := provider{
			config: providerConfig,
			oauth2Config: &oauth2.Config{
				ClientID:     providerConfig.ClientID,
				ClientSecret: providerConfig.ClientSecret,
				Scopes:       providerConfig.Scopes,
				RedirectURL:  config.CallbackURL,
			},
		}
		if providerConfig.IssuerURL != "" {
			provider.oidcProvider, err = oidc.NewProvider(context.Background(), providerConfig.IssuerURL)
			if err != nil {
				return nil, err
			}
			endpoints := &Endpoints{}
			err := provider.oidcProvider.Claims(endpoints)
			if err != nil {
				return nil, err
			}
			// apply explicitly set settings
			provider.config.Endpoints.Merge(endpoints)
		}

		if provider.config.AuthorizationEndpoint == "" {
			return nil, fmt.Errorf("authorization endpoint not set")
		}
		if provider.config.TokenEndpoint == "" {
			return nil, fmt.Errorf("token endpoint not set")
		}

		provider.oauth2Config.Endpoint = oauth2.Endpoint{
			AuthURL:  provider.config.AuthorizationEndpoint,
			TokenURL: provider.config.TokenEndpoint,
		}

		providers[name] = provider
	}

	return &OIDCProxyHandler{
		config:            config,
		loginPath:         config.LoginPath,
		callbackPath:      callbackURL.Path,
		cookieHandler:     cookieHandler,
		providers:         providers,
		sessionCookieName: "oprox",
		next:              next,
	}, nil
}

type provider struct {
	config       Provider
	oidcProvider *oidc.Provider
	oauth2Config *oauth2.Config
}

type OIDCProxyHandler struct {
	providers         map[string]provider
	config            *OIDCProxyConfig
	loginPath         string
	callbackPath      string
	cookieHandler     *cookie.CookieHandler
	sessionCookieName string
	next              http.Handler
}

type Session struct {
	Provider     string
	OAuth2Tokens *oauth2.Token
	IDToken      string
}

func (op *OIDCProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == op.config.LogoutPath {
		op.LogoutHandler(w, r)
		return
	}
	// handle login
	if r.URL.Path == op.loginPath {
		op.LoginHandler(w, r)
		return
	}

	// handle callback
	if r.URL.Path == op.callbackPath {
		op.CallbackHandler(w, r)
		return
	}

	// ----------- //
	// handle auth //
	// ----------- //
	s := op.getSession(r)
	if s == nil {
		slog.Debug("no session")
		op.RedirectToLogin(w, r)
		//op.LoginHandler(w, r)
		return
	}

	// Temporary test
	if r.URL.Path == "/refresh" {
		newSession, err := op.refreshToken(r.Context(), s)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		slog.Info("token refreshed", "access_token", newSession.OAuth2Tokens.AccessToken != "", "refresh_token", newSession.OAuth2Tokens.RefreshToken != "")
		err = op.cookieHandler.Set(w, r, op.sessionCookieName, s)
		if err != nil {
			// TODO: log in cookie handler
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		s = newSession
	}

	// invalid token try refresh otherwise run login handler
	if !s.OAuth2Tokens.Valid() {
		newSession, err := op.refreshToken(r.Context(), s)
		if err != nil {
			slog.Info("token refresh failed", "err", err)
			op.RedirectToLogin(w, r)
			return
		}
		slog.Info("token refreshed", "access_token", newSession.OAuth2Tokens.AccessToken != "", "refresh_token", newSession.OAuth2Tokens.RefreshToken != "")
		err = op.cookieHandler.Set(w, r, op.sessionCookieName, s)
		if err != nil {
			// TODO: log in cookie handler
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	token := s.OAuth2Tokens.Type() + " " + s.OAuth2Tokens.AccessToken
	r.Header.Add("Authorization", token)

	op.next.ServeHTTP(w, r.WithContext(ContextWithSession(r.Context(), s)))
}

type contextKey int

const sessionContextKey contextKey = 0

func SessionFromContext(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionContextKey).(*Session)
	return s
}

func ContextWithSession(parent context.Context, s *Session) context.Context {
	return context.WithValue(parent, sessionContextKey, s)
}

func (op *OIDCProxyHandler) getSession(r *http.Request) *Session {
	s := &Session{}
	ok, err := op.cookieHandler.Get(r, op.sessionCookieName, s)
	if !ok {
		return nil
	}
	if err != nil {
		slog.Debug("failed to obtain session", "err", err)
		return nil
	}
	return s
}

type loginState struct {
	State    string
	URI      string
	Provider string
}

func (op *OIDCProxyHandler) RedirectToLogin(w http.ResponseWriter, r *http.Request) {
	// TODO: where do we really want to handle this
	if !(r.Method == "GET" || r.Method == "HEAD") {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	originURI := r.URL.RequestURI()
	http.Redirect(w, r, op.loginPath+"?origin_uri="+originURI, 303)
}

func (op *OIDCProxyHandler) refreshToken(ctx context.Context, s *Session) (*Session, error) {
	if s.OAuth2Tokens == nil || s.OAuth2Tokens.RefreshToken == "" {
		return nil, fmt.Errorf("token expired or missing and no refresh token available")
	}
	provider, ok := op.providers[s.Provider]
	if !ok {
		return nil, fmt.Errorf("unknown provider %s", s.Provider)
	}
	newToken, err := provider.oauth2Config.TokenSource(ctx, s.OAuth2Tokens).Token()
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	newIDToken, ok := newToken.Extra("id_token").(string)
	if !ok {
		slog.Info("token refresh did not return new id_token")
		newIDToken = s.IDToken
	}

	return &Session{
		Provider:     s.Provider,
		OAuth2Tokens: newToken,
		IDToken:      newIDToken,
	}, nil
}

func (op *OIDCProxyHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}
	providerName := r.Form.Get("provider")
	if providerName == "" {
		w.Header().Add("Content-Type", "text/html")
		w.Header().Add("Cache-Control", "no-cache")
		fmt.Fprintln(w, "<h1>select login provider</h1>")
		for name, provider := range op.providers {
			fullName := provider.config.Name
			if fullName == "" {
				fullName = name
			}
			fmt.Fprintf(w, `<div><a href="%s">%s</a></div>`, r.URL.RequestURI()+"&provider="+name, fullName)
		}
		return
	}

	provider, ok := op.providers[providerName]
	if !ok {
		http.Error(w, "unknown provider", http.StatusBadRequest)
		return
	}

	const STATE_LENGTH = 20
	state, err := randString(STATE_LENGTH)
	if err != nil {
		panic(err)
	}
	loginState := loginState{
		Provider: providerName,
		State:    state,
		URI:      r.Form.Get("origin_uri"),
	}
	slog.Debug("set state cookie", "state", loginState.State, "uri", loginState.URI)
	err = op.cookieHandler.Set(w, r, "state", loginState)
	if err != nil {
		slog.Debug("failed to set cookie", "err", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	redirectURL := provider.oauth2Config.AuthCodeURL(loginState.State, urlValuesIntoOpts(provider.config.AuthorizationParameter)...)
	slog.Debug("redirect for authentication", "url", redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func urlValuesIntoOpts(urlValues url.Values) []oauth2.AuthCodeOption {
	opts := []oauth2.AuthCodeOption{}
	for parameter, values := range urlValues {
		for _, value := range values {
			opts = append(opts, oauth2.SetAuthURLParam(parameter, value))
		}
	}
	return opts
}

func (op *OIDCProxyHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	op.cookieHandler.Delete(w, op.sessionCookieName)

	s := op.getSession(r)
	if s == nil {
		fmt.Fprintln(w, "logged out")
		return
	}

	provider, ok := op.providers[s.Provider]
	if !ok {
		fmt.Fprintln(w, "logged out")
		return
	}
	revocationURL := provider.config.RevocationEndpoint
	slog.Debug("revoke token", "url", revocationURL)
	if revocationURL != "" {
		token := s.OAuth2Tokens.RefreshToken
		if token == "" {
			token = s.OAuth2Tokens.AccessToken
		}
		body := url.Values{}
		body.Add("token", token)
		body.Add("client_id", provider.config.ClientID)
		body.Add("client_secret", provider.config.ClientSecret)
		req, err := http.NewRequestWithContext(r.Context(), "POST", revocationURL, bytes.NewBufferString(body.Encode()))
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		if err != nil {
			slog.Info("failed to call revocation url", "err", err)
			// I know I know, spaghetti...
			goto NEXT
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			slog.Info("failed to call revocation url", "err", err)
			// I know I know, spaghetti...
			goto NEXT
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 399 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1000))
			slog.Info("failed to call revocation url", "status_code", resp.StatusCode, "body", string(body))
		}
		slog.Debug("revoked token")
	}
NEXT:

	endSessionURL := provider.config.EndSessionEndpoint

	if endSessionURL != "" {
		q := url.Values{}
		if s.IDToken != "" {
			q.Add("id_token_hint", s.IDToken)
		}
		http.Redirect(w, r, endSessionURL+"?"+q.Encode(), 303)
		return
	}
	fmt.Fprintln(w, "logged out")
}

func (op *OIDCProxyHandler) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	var loginState loginState
	ok, err := op.cookieHandler.Get(r, "state", &loginState)
	if !ok {
		http.Error(w, "state cookie missing", http.StatusBadRequest)
		return
	}
	if err != nil {
		slog.Info("invalid state cookie", "err", err)
		op.cookieHandler.Delete(w, "state")
		http.Error(w, "invalid state cookie", http.StatusBadRequest)
		return
	}
	op.cookieHandler.Delete(w, "state")

	state := r.FormValue("state")

	if state != loginState.State {
		http.Error(w, "state missmatch", http.StatusInternalServerError)
		return
	}

	params := r.URL.Query()
	if params.Get("error") != "" {
		slog.Info("login failed", "error", params.Get("error"), "error_description", params.Get("error_description"))
		http.Error(w, fmt.Sprintf("error=%s, error_description=%s", params.Get("error"), params.Get("error_description")), http.StatusInternalServerError)
		return
	}

	provider, ok := op.providers[loginState.Provider]
	if !ok {
		http.Error(w, "invalid state unknown provider", http.StatusBadRequest)
		return
	}
	start := time.Now()
	oauth2Token, err := provider.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"), urlValuesIntoOpts(provider.config.TokenParameters)...)
	if err != nil {
		http.Error(w, fmt.Sprintf("token exchange failed: %s", err.Error()), http.StatusInternalServerError)
		return
	}
	slog.Info("token issued", "duration", time.Now().Sub(start))

	session := &Session{
		Provider:     loginState.Provider,
		OAuth2Tokens: oauth2Token,
	}

	// for pure OAuth2 flows we don't have an oidcProvider and no id_tokens
	if provider.oidcProvider != nil {
		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "missing id_token", http.StatusInternalServerError)
			return
		}

		// Parse and verify ID Token payload.
		_, err = provider.oidcProvider.Verifier(&oidc.Config{ClientID: provider.config.ClientID}).Verify(r.Context(), rawIDToken)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to validate id_token: %s", err.Error()), http.StatusInternalServerError)
			return
		}
		session.IDToken = rawIDToken
	}

	err = op.cookieHandler.Set(w, r, op.sessionCookieName, session)
	if err != nil {
		slog.Info("failed to set cookie", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	slog.Info("token successfuly issued", "refresh_token", oauth2Token.RefreshToken != "")

	originURI := loginState.URI
	if originURI == "" {
		originURI = "/"
	}
	http.Redirect(w, r, loginState.URI, http.StatusSeeOther)
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randString(n int) (string, error) {
	r := make([]byte, n)
	_, err := rand.Read(r)
	if err != nil {
		return "", err
	}

	b := make([]byte, n)
	for i := range b {
		// TODO: does this work?
		b[i] = letterBytes[int(r[i])%(len(letterBytes)-1)]
	}
	return string(b), nil
}

func generateKey(length int) ([]byte, error) {
	k := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, k)
	if err != nil {
		return nil, err
	}
	return k, nil
}
