package oidcproxy

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/dvob/oidc-proxy/cookie"
)

type Config struct {
	// OAuth2 / OIDC
	// TODO: do not use map otherwise we have to configure name twice
	Providers []ProviderConfig

	CallbackURL string

	// LoginPath initiates the login flow
	LoginPath string

	// LogoutPath deletes cookie, revokes token and redirect to IDPs logout
	// URL if available
	LogoutPath string

	// DebugPath shows info about the current session
	DebugPath string

	// RefreshPath performs an explicit refresh
	RefreshPath string

	// secure cookie
	HashKey    []byte
	EncryptKey []byte
}

func NewAuthenticator(ctx context.Context, config *Config) (*authenticator, error) {
	if config.CallbackURL == "" {
		return nil, fmt.Errorf("callback url not set")
	}
	callbackURL, err := url.Parse(config.CallbackURL)
	if err != nil {
		return nil, err
	}

	// Setup Cookiehandler
	hashKey := config.HashKey
	encKey := config.EncryptKey

	if !(len(hashKey) == 32 || len(hashKey) == 64) {
		return nil, fmt.Errorf("hash key is missing or has invalid key length. a length of 32 or 64 is required")
	}
	if !(len(encKey) == 0 || len(encKey) == 32 || len(encKey) == 64) {
		return nil, fmt.Errorf("encryption kes is missing or has invalid key length. a length of 32 or 64 is required")
	}

	cookieHandler := cookie.NewCookieHandler(hashKey, encKey)

	// Setup providers
	providers := map[string]provider{}
	for _, providerConfig := range config.Providers {
		if providerConfig.CallbackURL == "" {
			providerConfig.CallbackURL = config.CallbackURL
		}

		provider, err := newProvider(ctx, providerConfig)
		if err != nil {
			return nil, err
		}

		if existing, ok := providers[provider.config.Identifier]; ok {
			return nil, fmt.Errorf("duplicate provider %s (%s) and %s (%s)", existing.config.Name, existing.config.IssuerURL, provider.config.Name, provider.config.IssuerURL)
		}

		providers[provider.config.Identifier] = *provider
	}

	return &authenticator{
		config: config,

		loginPath:    config.LoginPath,
		callbackPath: callbackURL.Path,
		debugPath:    config.DebugPath,
		refreshPath:  config.RefreshPath,

		cookieHandler:        cookieHandler,
		sessionCookieName:    "oprox",
		loginStateCookieName: "state",

		providers: providers,
	}, nil
}

type authenticator struct {
	config *Config

	loginPath    string
	callbackPath string
	debugPath    string
	refreshPath  string

	cookieHandler        *cookie.CookieHandler
	sessionCookieName    string
	loginStateCookieName string

	providers map[string]provider
}

type Session struct {
	ProviderIdentifier string
	Tokens
}

func (s *Session) Valid() bool {
	if s == nil {
		return false
	}
	return s.Tokens.Valid()
}

func (op *authenticator) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if op.debugPath != "" && r.URL.Path == op.debugPath {
			op.DebugHandler(w, r)
			return
		}

		// handle logout
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

		// handle refresh
		if r.URL.Path == op.refreshPath {
			op.HandleRefresh(w, r)
			return
		}

		// check session
		currentSession, provider := op.getSession(w, r)
		if currentSession == nil {
			slog.Debug("no session available: initiate login")
			op.RedirectToLogin(w, r)
			return
		}

		// run silent refresh or redirect to login if session expired
		if !currentSession.Valid() {
			if currentSession.RefreshToken == "" {
				slog.Debug("no refresh token available: initiate login")
				op.RedirectToLogin(w, r)
			}

			newTokens, err := provider.refresh(r.Context(), &currentSession.Tokens)
			if err != nil {
				slog.Info("token refresh failed", "err", err)
				op.RedirectToLogin(w, r)
				return
			}

			newSession := &Session{
				ProviderIdentifier: currentSession.ProviderIdentifier,
				Tokens:             *newTokens,
			}

			slog.Info("token refreshed", "access_token", newSession.AccessToken != "", "refresh_token", newSession.RefreshToken != "", "id_token", newSession.IDToken != "")

			err = op.setSession(w, r, newSession)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			currentSession = newSession
		}

		r = r.WithContext(ContextWithSession(r.Context(), currentSession))
		next.ServeHTTP(w, r)
	})
}

// HandleRefresh handles exlicit refresh which prints the outcome to the
// response writer.
func (op *authenticator) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	currentSession, provider := op.getSession(w, r)
	if currentSession == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}

	newTokens, err := provider.refresh(r.Context(), &currentSession.Tokens)
	if err != nil {
		slog.Info("token refresh failed", "err", err)
		http.Error(w, "refresh failed", http.StatusInternalServerError)
		return
	}
	newSession := &Session{
		ProviderIdentifier: currentSession.ProviderIdentifier,
		Tokens:             *newTokens,
	}

	slog.Info("token refreshed", "access_token", newSession.AccessToken != "", "refresh_token", newSession.RefreshToken != "", "id_token", newSession.IDToken != "")

	err = op.setSession(w, r, newSession)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "token refresh successful")
	return
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

func (op *authenticator) getSession(w http.ResponseWriter, r *http.Request) (*Session, *provider) {
	s := &Session{}
	ok, err := op.cookieHandler.Get(r, op.sessionCookieName, s)
	if !ok {
		return nil, nil
	}
	if err != nil {
		slog.Info("failed to decode session", "err", err)
		op.deleteSession(w)
		return nil, nil
	}
	provider, ok := op.providers[s.ProviderIdentifier]
	if !ok {
		slog.Info("session with unknown provider", "identifier", s.ProviderIdentifier)
		op.deleteSession(w)
		return nil, nil
	}
	return s, &provider
}

func (op *authenticator) setSession(w http.ResponseWriter, r *http.Request, s *Session) error {
	if s == nil {
		return fmt.Errorf("no session to set")
	}
	if s.Tokens.AccessToken == "" {
		return fmt.Errorf("no access token")
	}

	err := op.cookieHandler.Set(w, r, op.sessionCookieName, s)
	if err != nil {
		slog.Error("failed to encode session state")
	}
	return err
}

func (op *authenticator) deleteSession(w http.ResponseWriter) {
	op.cookieHandler.Delete(w, op.sessionCookieName)
}

func (op *authenticator) getLoginState(w http.ResponseWriter, r *http.Request) *LoginState {
	loginState := &LoginState{}
	ok, err := op.cookieHandler.Get(r, op.loginStateCookieName, loginState)
	if !ok {
		return nil
	}
	if err != nil {
		slog.Info("failed to decode login state", "err", err)
		op.deleteLoginState(w)
		return nil
	}
	return loginState
}

func (op *authenticator) setLoginState(w http.ResponseWriter, r *http.Request, l *LoginState) error {
	err := op.cookieHandler.Set(w, r, op.loginStateCookieName, l)
	if err != nil {
		slog.Error("failed to encode login state", "err", err)
	}
	return err
}

func (op *authenticator) deleteLoginState(w http.ResponseWriter) {
	op.cookieHandler.Delete(w, op.loginStateCookieName)
}

type LoginState struct {
	State              string
	URI                string
	ProviderIdentifier string
}

// RedirectToLogin remembers the current uri to redirect you back there after
// the login flow and redirects you to the login handler.
func (op *authenticator) RedirectToLogin(w http.ResponseWriter, r *http.Request) {
	if !(r.Method == "GET" || r.Method == "HEAD") {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	originURI := r.URL.RequestURI()
	op.setLoginState(w, r, &LoginState{URI: originURI})
	http.Redirect(w, r, op.loginPath, http.StatusSeeOther)
}

// LoginHandler initiates the state and redirects the request to the providers
// authorization URL.
func (op *authenticator) LoginHandler(w http.ResponseWriter, r *http.Request) {
	providerIdentifier := r.URL.Query().Get("provider")

	// if provider is not set and there is only one configured we use that one
	if len(op.providers) == 1 && providerIdentifier == "" {
		// this will only loop once.
		for name := range op.providers {
			providerIdentifier = name
		}
	}

	if providerIdentifier == "" {
		w.Header().Add("Content-Type", "text/html")
		w.Header().Add("Cache-Control", "no-cache")
		fmt.Fprintln(w, "<h1>select login provider</h1>")
		for _, provider := range op.providers {
			fullName := provider.config.Name
			if fullName == "" {
				fullName = provider.config.IssuerURL
			}
			fmt.Fprintf(w, `<div><a href="%s">%s (%s)</a></div>`, op.loginPath+"?provider="+provider.config.Identifier, fullName, provider.config.Identifier)
		}
		return
	}

	provider, ok := op.providers[providerIdentifier]
	if !ok {
		http.Error(w, "unknown provider", http.StatusBadRequest)
		return
	}

	const STATE_LENGTH = 10
	stateStr, err := randString(STATE_LENGTH)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		slog.Error("faild to generate random state", "err", err)
		return
	}

	state := op.getLoginState(w, r)
	if state == nil {
		state = &LoginState{
			ProviderIdentifier: providerIdentifier,
			State:              stateStr,
		}
	} else {
		state.ProviderIdentifier = providerIdentifier
		state.State = stateStr
	}

	err = op.setLoginState(w, r, state)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	redirectURL := provider.authCodeURL(r.Context(), state.State)
	slog.Debug("redirect for authentication", "url", redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// LogoutHandler deletes the session cookies, revokes the token (if supportd by
// the provider) and redirects to the end_session_uri of the provider (if
// supported by the provider).
//
// TODO: generalize logged out view
func (op *authenticator) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, provider := op.getSession(w, r)
	if session == nil {
		fmt.Fprintln(w, "logged out")
		return
	}

	// delete cookie
	op.deleteSession(w)

	// revoke
	revocationURL := provider.config.RevocationEndpoint
	if revocationURL != "" {
		err := provider.revoke(r.Context(), session.RefreshToken)
		if err != nil {
			slog.Warn("failed to revoke token", "err", err)
		}
	}

	// logut
	endSessionURL := provider.config.EndSessionEndpoint
	if endSessionURL != "" {
		logoutURL := provider.rpInitiatedLogoutURL(r.Context(), &session.Tokens)
		http.Redirect(w, r, logoutURL, http.StatusSeeOther)
		return
	}
	fmt.Fprintln(w, "logged out")
}

// CallbackHandler handles the callback from the provider. It does the following things:
//   - checks the state
//   - gets the tokens from the provider using the authorization code grant
//   - initiates the sessoin (set cookies)
//   - redirect back to the uri you came from if set
func (op *authenticator) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	loginState := op.getLoginState(w, r)
	if loginState == nil {
		http.Error(w, "state cookie missing", http.StatusBadRequest)
		return
	}

	op.deleteLoginState(w)

	state := r.URL.Query().Get("state")
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

	provider, ok := op.providers[loginState.ProviderIdentifier]
	if !ok {
		http.Error(w, "invalid state unknown provider", http.StatusBadRequest)
		return
	}
	tokens, err := provider.exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		slog.Info("token exchange failed", "err", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}

	session := &Session{
		ProviderIdentifier: loginState.ProviderIdentifier,
		Tokens:             *tokens,
	}

	err = op.setSession(w, r, session)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	slog.Info("token successfuly issued", "refresh_token", tokens.RefreshToken != "")

	originURI := loginState.URI
	if originURI == "" {
		// TODO: redirect to session info or make configurable
		//originURI = "/"
		fmt.Fprintln(w, "successfully logged in")
		return
	}
	http.Redirect(w, r, loginState.URI, http.StatusSeeOther)
}

func randString(randomBytesLen int) (string, error) {
	randomBytes := make([]byte, randomBytesLen)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func generateKey(length int) ([]byte, error) {
	k := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, k)
	if err != nil {
		return nil, err
	}
	return k, nil
}
