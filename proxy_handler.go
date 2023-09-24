package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/dvob/oidc-proxy/cookie"
	"golang.org/x/oauth2"
)

type OIDCProxyConfig struct {
	// OAuth2 / OIDC
	IssuerURL    string
	ClientID     string
	ClientSecret string
	Scopes       []string
	CallbackURL  string

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

	// Perform OIDC dicovery
	// TODO: do not fail on startup
	provider, err := oidc.NewProvider(context.Background(), config.IssuerURL)
	if err != nil {
		return nil, err
	}

	oauth2Config := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  config.CallbackURL,
		Scopes:       config.Scopes,
	}

	return &OIDCProxyHandler{
		config:            config,
		loginPath:         config.LoginPath,
		callbackPath:      callbackURL.Path,
		cookieHandler:     cookieHandler,
		provider:          provider,
		oauth2Config:      oauth2Config,
		sessionCookieName: "oprox",
		next:              next,
	}, nil
}

type OIDCProxyHandler struct {
	config            *OIDCProxyConfig
	loginPath         string
	callbackPath      string
	cookieHandler     *cookie.CookieHandler
	provider          *oidc.Provider
	oauth2Config      *oauth2.Config
	sessionCookieName string
	next              http.Handler
}

type Session struct {
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

	// handle auth
	s := op.getSession(r)
	if s == nil {
		slog.Debug("no session")
		op.LoginHandler(w, r)
		return
	}

	// invalid token try refresh otherwise run login handler
	if !s.OAuth2Tokens.Valid() {
		if s.OAuth2Tokens == nil || s.OAuth2Tokens.RefreshToken == "" {
			slog.Debug("token expired or missing and no refresh token available")
			op.LoginHandler(w, r)
			return
		}
		newToken, err := op.oauth2Config.TokenSource(r.Context(), s.OAuth2Tokens).Token()
		if err != nil {
			slog.Info("token refresh failed. initiate login.", "err", err)
			op.LoginHandler(w, r)
			return
		}

		s.OAuth2Tokens = newToken
		newIDToken, ok := newToken.Extra("id_token").(string)
		if ok {
			s.IDToken = newIDToken
		}
		slog.Info("token refreshed", "access_token", newToken.AccessToken != "", "refresh_token", newToken.AccessToken != "", "id_token", newIDToken != "")
		err = op.cookieHandler.Set(w, r, op.sessionCookieName, s)
		if err != nil {
			// TODO: log in cookie handler
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	token := s.OAuth2Tokens.Type() + " " + s.OAuth2Tokens.AccessToken
	r.Header.Add("Authorization", token)

	op.next.ServeHTTP(w, r)
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
	session := SessionFromContext(r.Context())
	if session != nil {
		return session
	}
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
	State string
	URI   string
}

func (op *OIDCProxyHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	const STATE_LENGTH = 20
	state, err := randString(STATE_LENGTH)
	if err != nil {
		panic(err)
	}
	loginState := loginState{
		State: state,
		URI:   r.URL.RequestURI(),
	}
	slog.Debug("set state cookie", "state", loginState.State, "uri", loginState.URI)
	err = op.cookieHandler.Set(w, r, "state", loginState)
	if err != nil {
		slog.Debug("failed to set cookie", "err", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	redirectURL := op.oauth2Config.AuthCodeURL(loginState.State)
	slog.Debug("redirect for authentication", "url", redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (op *OIDCProxyHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	op.cookieHandler.Delete(w, op.sessionCookieName)
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

	oauth2Token, err := op.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, fmt.Sprintf("token exchange failed: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "missing id_token", http.StatusInternalServerError)
		return
	}

	// Parse and verify ID Token payload.
	_, err = op.provider.Verifier(&oidc.Config{ClientID: op.config.ClientID}).Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to validate id_token: %s", err.Error()), http.StatusInternalServerError)
		return
	}

	session := &Session{
		OAuth2Tokens: oauth2Token,
		IDToken:      rawIDToken,
	}
	err = op.cookieHandler.Set(w, r, op.sessionCookieName, session)
	if err != nil {
		slog.Info("failed to set cookie", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	slog.Info("token successfuly issued", "refresh_token", oauth2Token.RefreshToken != "")
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
