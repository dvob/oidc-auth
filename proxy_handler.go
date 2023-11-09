package oidcproxy

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

type Config struct {
	// OAuth2 / OIDC
	Providers []ProviderConfig

	// CallbackURL is the url under which the callback path is reachable
	CallbackURL string

	// PostLogoutRedirectURI is the URL where you get redirected after an
	// RP initiated logut
	PostLogoutRediretURI string

	// LoginPath initiates the login flow
	LoginPath string

	// CallbackPath handle the oauth2 callback. It defaults to the path of
	// the CallbackURL if not specified.
	CallbackPath string

	// SessionInfoPath
	SessionInfoPath string

	// RefreshPath performs an explicit refresh
	RefreshPath string

	// LogoutPath deletes cookie, revokes token and redirect to IDPs logout
	// URL if available
	LogoutPath string

	// DebugPath shows info about the current session
	DebugPath string

	// secure cookie
	HashKey    []byte
	EncryptKey []byte

	// Used in templates
	AppName string
}

//go:embed templates/*
var templateFS embed.FS

func NewAuthenticator(ctx context.Context, config *Config) (*Authenticator, error) {
	var (
		devMode   = false
		templates map[string]*template.Template
	)

	if devMode {
		var err error
		templateDirFS := os.DirFS("templates")
		templates, err = parsePageTemplates(templateDirFS)
		if err != nil {
			return nil, err
		}
	} else {
		templateDirFS, err := fs.Sub(templateFS, "templates")
		if err != nil {
			return nil, err
		}
		templates, err = parsePageTemplates(templateDirFS)
		if err != nil {
			return nil, err
		}
	}

	// validate and prepare config
	if config.CallbackURL == "" {
		// TODO: default to current host /callback path
		return nil, fmt.Errorf("callback url not set")
	}
	callbackURL, err := url.Parse(config.CallbackURL)
	if err != nil {
		return nil, err
	}

	// derive callbackPath from callbackURL if not explicitly set
	callbackPath := config.CallbackPath
	if callbackPath == "" {
		callbackPath = callbackURL.Path
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

	// Setup providerMap
	providerList := []*Provider{}

	for _, providerConfig := range config.Providers {
		if providerConfig.CallbackURL == "" {
			providerConfig.CallbackURL = config.CallbackURL
		}

		if providerConfig.PostLogoutRedirectURI == "" {
			providerConfig.PostLogoutRedirectURI = config.PostLogoutRediretURI
		}

		provider, err := NewProvider(ctx, providerConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize provider '%s': %w", providerConfig.IssuerURL, err)
		}

		providerList = append(providerList, provider)
	}

	providers, err := newProviderSet(providerList...)

	return &Authenticator{
		appName:         config.AppName,
		loginPath:       config.LoginPath,
		callbackPath:    callbackPath,
		sessionInfoPath: config.SessionInfoPath,
		refreshPath:     config.RefreshPath,
		logoutPath:      config.LogoutPath,
		debugPath:       config.DebugPath,

		sessionManager: newSessionManager(hashKey, encKey, providers),

		devMode:   devMode,
		mu:        &sync.Mutex{},
		templates: templates,
	}, nil
}

type Authenticator struct {
	// used in templates if available
	appName string

	loginPath       string
	callbackPath    string
	sessionInfoPath string
	refreshPath     string
	logoutPath      string
	debugPath       string

	sessionManager *sessionManager

	devMode   bool
	mu        *sync.Mutex
	templates map[string]*template.Template
}

func (op *Authenticator) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == op.sessionInfoPath {
			op.SessionInfoHandler(w, r)
			return
		}

		if op.debugPath != "" && r.URL.Path == op.debugPath {
			op.DebugHandler(w, r)
			return
		}

		// handle logout
		if r.URL.Path == op.logoutPath {
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
			op.RefreshHandler(w, r)
			return
		}

		// check session
		currentSessionCtx, _ := op.sessionManager.GetSession(w, r)
		if currentSessionCtx == nil {
			slog.Debug("no session available: initiate login")
			op.RedirectToLogin(w, r)
			return
		}

		provider := currentSessionCtx.Provider
		currentSession := currentSessionCtx.Session

		// run silent refresh or redirect to login if session expired
		if !currentSession.Valid() {
			if !currentSession.HasRefreshToken() {
				slog.Debug("no refresh token available: initiate login")
				op.RedirectToLogin(w, r)
			}

			newSession, err := provider.Refresh(r.Context(), currentSession)
			if err != nil {
				slog.Info("token refresh failed. initiate login", "err", err)
				op.RedirectToLogin(w, r)
				return
			}

			slog.Info("token refreshed", "access_token", newSession.HasAccessToken(), "refresh_token", newSession.HasRefreshToken(), "id_token", newSession.HasIDToken())

			err = op.sessionManager.SetSession(w, r, newSession)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			currentSession = newSession
		}

		r = r.WithContext(ContextWithSession(r.Context(), &SessionContext{
			Session:  currentSession,
			Provider: provider,
		}))
		next.ServeHTTP(w, r)
	})
}

func (op *Authenticator) LoadSessionHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		currentSessionCtx, _ := op.sessionManager.GetSession(w, r)
		r = r.WithContext(ContextWithSession(r.Context(), currentSessionCtx))
		next.ServeHTTP(w, r)
	})
}

func (op *Authenticator) RemoveSession(w http.ResponseWriter, r *http.Request) {
	op.sessionManager.RemoveSession(w, r)
	return
}

func (op *Authenticator) RemoveCookie(r *http.Request) {
	op.sessionManager.RemoveCookie(r)
}

func (op *Authenticator) SessionInfoHandler(w http.ResponseWriter, r *http.Request) {
	currentSessionCtx, _ := op.sessionManager.GetSession(w, r)
	var (
		currentSession *Session
		provider       *Provider
	)

	if currentSessionCtx != nil {
		currentSession = currentSessionCtx.Session
		provider = currentSessionCtx.Provider
	}

	// TODO: rework
	type sessionInfo struct {
		// ? just return 401 instead of 200 with logged_in=false
		LoggedIn bool `json:"logged_in"`

		// ? only return expiry and let theses infos for the debug endpoint only
		AccessTokenAvailable  bool      `json:"access_token_available"`
		RefreshTokenAvailable bool      `json:"refresh_token_available"`
		IDTokenAvailable      bool      `json:"id_token_available"`
		User                  *User     `json:"user"`
		Expiry                time.Time `json:"expiry,omitempty"`
		Provider              string    `json:"provider"`
	}

	info := &sessionInfo{
		LoggedIn: currentSession.Valid(),
	}

	if currentSession != nil && provider != nil {
		info.User = currentSession.User
		info.AccessTokenAvailable = currentSession.HasAccessToken()
		info.RefreshTokenAvailable = currentSession.HasRefreshToken()
		info.IDTokenAvailable = currentSession.HasIDToken()
		info.Expiry = currentSession.Expiry
		info.Provider = provider.String()
	}

	w.Header().Add("Cache-Control", "no-cache")
	contentType := r.Header.Get("Accept")
	if contentType == "application/json" {
		if currentSession == nil {
			http.Error(w, "no session", http.StatusUnauthorized)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		out, err := json.Marshal(info)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			slog.Error("failed to marshal session info", "err", err)
			return
		}
		w.Write(out)
		return
	}

	op.servePage(w, "session_info", info)
}

// RefreshHandler handles exlicit refresh which prints the outcome to the
// response writer.
func (op *Authenticator) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: return proper json response on accept json
	// TODO: on HTML set flash message
	currentSessionCtx, _ := op.sessionManager.GetSession(w, r)
	if currentSessionCtx == nil {
		http.Error(w, "no session", http.StatusUnauthorized)
		return
	}
	currentSession := currentSessionCtx.Session
	provider := currentSessionCtx.Provider

	newSession, err := provider.Refresh(r.Context(), currentSession)
	if err != nil {
		slog.Info("session initialization after token refresh failed", "err", err)

		message := "token refresh failed"
		if userError, ok := err.(UserError); ok {
			message += ": " + userError.UserError()
		}
		http.Error(w, message, http.StatusInternalServerError)
		return
	}

	slog.Info("token refreshed", "access_token", newSession.HasAccessToken(), "refresh_token", newSession.HasRefreshToken(), "id_token", newSession.HasIDToken())

	err = op.sessionManager.SetSession(w, r, newSession)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, op.sessionInfoPath, http.StatusSeeOther)
}

type contextKey int

const sessionContextKey contextKey = 0

func SessionFromContext(ctx context.Context) *SessionContext {
	s, _ := ctx.Value(sessionContextKey).(*SessionContext)
	return s
}

func ContextWithSession(parent context.Context, s *SessionContext) context.Context {
	return context.WithValue(parent, sessionContextKey, s)
}

// RedirectToLogin remembers the current uri to redirect you back there after
// the login flow and redirects you to the login handler.
func (op *Authenticator) RedirectToLogin(w http.ResponseWriter, r *http.Request) {
	if !(r.Method == "GET" || r.Method == "HEAD") {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	originURI := r.URL.RequestURI()
	op.sessionManager.SetLoginState(w, r, &LoginState{URI: originURI})
	http.Redirect(w, r, op.loginPath, http.StatusSeeOther)
}

func (op *Authenticator) renderLoginProviderSelection(w http.ResponseWriter) {
	w.Header().Add("Cache-Control", "no-cache")

	type LoginProviderData struct {
		Name string
		Href string
	}

	loginProviderData := struct {
		Name      string
		Providers []LoginProviderData
	}{
		Name: op.appName,
	}

	for _, provider := range op.sessionManager.providerSet.List() {

		href := &url.URL{
			Path: op.loginPath,
		}

		parameters := url.Values{}
		parameters.Add("provider", provider.ID())
		href.RawQuery = parameters.Encode()

		loginProviderData.Providers = append(loginProviderData.Providers, LoginProviderData{
			Name: provider.config.Name,
			Href: href.RequestURI(),
		})
	}

	op.servePage(w, "login_provider_selection", loginProviderData)
}

// LoginHandler initiates the state and redirects the request to the providers
// authorization URL.
func (op *Authenticator) LoginHandler(w http.ResponseWriter, r *http.Request) {
	providerID := r.URL.Query().Get("provider")

	// if provider is not set and there is only one configured we use that one
	providers := op.sessionManager.providerSet.List()
	if len(providers) == 1 && providerID == "" {
		providerID = providers[0].ID()
	}

	if providerID == "" {
		op.renderLoginProviderSelection(w)
		return
	}

	provider, err := op.sessionManager.providerSet.GetByID(providerID)
	if err != nil {
		slog.Error("invalid provider", "err", err)
		http.Error(w, "invalid provider", http.StatusBadRequest)
		return
	}

	const STATE_LENGTH = 10
	stateStr, err := randString(STATE_LENGTH)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		slog.Error("faild to generate random state", "err", err)
		return
	}

	state := op.sessionManager.GetLoginState(w, r)
	if state == nil {
		state = &LoginState{
			ProviderID: providerID,
			State:      stateStr,
		}
	} else {
		state.ProviderID = providerID
		state.State = stateStr
	}

	err = op.sessionManager.SetLoginState(w, r, state)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	redirectURL, err := provider.AuthorizationEndpoint(r.Context(), state.State)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	slog.Debug("redirect for authentication", "url", redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// LogoutHandler deletes the session cookies, revokes the token (if supportd by
// the provider) and redirects to the end_session_uri of the provider (if
// supported by the provider).
//
// TODO: generalize logged out view
func (op *Authenticator) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	sessionCtx, _ := op.sessionManager.GetSession(w, r)
	if sessionCtx == nil {
		fmt.Fprintln(w, "logged out")
		return
	}
	session := sessionCtx.Session
	provider := sessionCtx.Provider

	// delete cookie
	op.sessionManager.RemoveSession(w, r)

	// revoke
	if session.HasRefreshToken() {
		err := provider.Revoke(r.Context(), session.RefreshToken())
		if err != nil && err != ErrNotSupported {
			slog.Warn("failed to revoke token", "err", err)
		}
	}

	// logut
	endSessionURL, err := provider.EndSessionEndpoint(r.Context(), session)
	if err != nil && err != ErrNotSupported {
		slog.Warn("failed to obtain end session endpoint", "err", err)
	}

	if err == nil {
		http.Redirect(w, r, endSessionURL, http.StatusSeeOther)
		return
	}

	fmt.Fprintln(w, "logged out")
}

// CallbackHandler handles the callback from the provider. It does the following things:
//   - checks the state
//   - gets the tokens from the provider using the authorization code grant
//   - initiates the sessoin (set cookies)
//   - redirect back to the uri you came from if set
func (op *Authenticator) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	loginState := op.sessionManager.GetLoginState(w, r)
	if loginState == nil {
		http.Error(w, "state cookie missing", http.StatusBadRequest)
		return
	}

	op.sessionManager.DeleteLoginState(w, r)

	state := r.URL.Query().Get("state")
	if state != loginState.State {
		http.Error(w, "state missmatch", http.StatusInternalServerError)
		return
	}

	params := r.URL.Query()
	if params.Get("error") != "" {
		slog.Info("login failed", "error", params.Get("error"), "error_description", params.Get("error_description"))
		op.renderLoginResult(w, nil, fmt.Sprintf("error=%s, error_description=%s", params.Get("error"), params.Get("error_description")))
		return
	}

	if !params.Has("code") {
		slog.Info("login failed", "error", "code missing")
		op.renderLoginResult(w, nil, "code missing")
		return

	}
	code := params.Get("code")

	provider, err := op.sessionManager.providerSet.GetByID(loginState.ProviderID)
	if err != nil {
		slog.Error("invalid provider", "err", err)
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	newSession, err := provider.Exchange(r.Context(), code)
	if err != nil {
		slog.Info("session initialization failed", "err", err)

		message := "Login verification failed."
		if userError, ok := err.(UserError); ok {
			message += ": " + userError.UserError()
		}
		op.renderLoginResult(w, newSession, message)
		return
	}

	err = op.sessionManager.SetSession(w, r, newSession)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	slog.Info("session initiated", "refresh_token", newSession.HasRefreshToken())

	originURI := loginState.URI
	if originURI == "" {
		op.renderLoginResult(w, newSession, "")
		return
	}
	http.Redirect(w, r, loginState.URI, http.StatusSeeOther)
}

func (op *Authenticator) renderLoginResult(w http.ResponseWriter, session *Session, errorMessage string) {
	w.Header().Add("Cache-Control", "no-cache")

	type LoginResultData struct {
		Error string
		User  *User
	}

	data := LoginResultData{
		Error: errorMessage,
	}

	if session != nil {
		data.User = session.User
	}

	if errorMessage != "" {
		// TODO: could also be 401
		w.WriteHeader(http.StatusInternalServerError)
	}
	op.servePage(w, "login_result", data)
}

func randString(randomBytesLen int) (string, error) {
	randomBytes := make([]byte, randomBytesLen)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}
