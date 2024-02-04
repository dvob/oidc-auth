package oidcauth

import (
	"context"
	"log/slog"
	"net/http"
)

// Authenticator combines privdes handlers and middlewares for the
// authentication using OIDC/OAuth2
type Authenticator struct {
	Config          *Config
	TemplateManager *templateManager
	SessionManager  *sessionManager
	Providers       []*Provider
	ErrorHandler    ErrorHandler
}

// NewAuthenticator validates the configuration and creates a new
// authenticator.
func NewAuthenticator(ctx context.Context, c *Config) (*Authenticator, error) {
	err := c.PrepareAndValidate()
	if err != nil {
		return nil, err
	}

	tm, err := NewTemplateManager(c.TemplateDir, c.TemplateDevMode)
	if err != nil {
		return nil, err
	}

	providers, err := NewProviderSet(ctx, c.Providers, func(pc *ProviderConfig) {
		if pc.CallbackURL == "" {
			pc.CallbackURL = c.CallbackURL
		}

		if pc.PostLogoutRedirectURI == "" {
			pc.PostLogoutRedirectURI = c.PostLogoutRediretURI
		}
	})
	if err != nil {
		return nil, err
	}

	providerSet, err := newProviderSet(providers...)
	if err != nil {
		return nil, err
	}

	sm, err := NewSessionManager(c.HashKey, c.EncryptionKey, providerSet, c.CookieConfig)
	if err != nil {
		return nil, err
	}

	return &Authenticator{
		Config:          c,
		TemplateManager: tm,
		SessionManager:  sm,
		Providers:       providers,
		ErrorHandler:    DefaultErrorHandler(c.GetRequestID, slog.Default()),
	}, nil
}

// FullMiddleware authenticates each request using the authenticator. With the
// default configuration it shadows the following pathes:
//   - /auth/login
//   - /auth/callback
//   - /auth/info
//   - /auth/refresh
//   - /auth/logout
//
// All other pathes are passed to the next handler.
func (a *Authenticator) FullMiddleware(next http.Handler) *http.ServeMux {
	mux := http.NewServeMux()

	// /login
	mux.Handle(a.Config.LoginPath, a.LoginHandler())

	// /callback
	mux.Handle(a.Config.CallbackPath, a.CallbackHandler())

	// /info
	mux.Handle(a.Config.SessionInfoPath, a.SessionInfoHandler())

	// /refresh
	mux.Handle(a.Config.RefreshPath, a.RefreshHandler())

	// logout
	mux.Handle(a.Config.LogoutPath, a.LogoutHandler())

	// for the rest make sure we have a valid session and pass it to the
	// next handler
	mux.Handle("/", a.AuthenticateHandler(next))

	return mux
}

func (a *Authenticator) LoginHandler() http.Handler {
	return LoginHandler(
		a.SessionManager,
		ProviderSelectionHandler(
			a.Config.AppName,
			a.Providers,
			a.TemplateManager,
		),
		a.ErrorHandler,
	)
}

func (a *Authenticator) CallbackHandler() http.Handler {
	return CallbackHandler(
		a.SessionManager,
		defaultPostCallbackHandler(a.SessionManager, DefaultErrorHandler(nil, slog.Default()), a.Config.ExternalSessionInfoPath),
		a.ErrorHandler,
	)
}

func (a *Authenticator) SessionInfoHandler() http.Handler {
	return NewDefaultSessionInfoHandler(
		a.SessionManager,
		a.TemplateManager,
		PathSet{
			Login:   a.Config.ExternalLoginPath,
			Logout:  a.Config.ExternalLogoutPath,
			Refresh: a.Config.ExternalRefreshPath,
		},
		a.ErrorHandler,
	)
}

func (a *Authenticator) RefreshHandler() http.Handler {
	return RefreshHandler(a.SessionManager, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, a.Config.ExternalSessionInfoPath, http.StatusSeeOther)
	}), a.ErrorHandler)
}

func (a *Authenticator) LogoutHandler() http.Handler {
	return LogoutHandler(a.SessionManager, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, a.Config.ExternalSessionInfoPath, http.StatusSeeOther)
	}))
}

// AuthenticateHandler checks if there is an existing valid session (not expired).
func (a *Authenticator) AuthenticateHandler(next http.Handler) http.Handler {
	return AuthenticateHandler(a.SessionManager, a.Config.ExternalLoginPath, next)
}
