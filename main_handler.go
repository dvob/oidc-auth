package oidcproxy

import (
	"context"
	"net/http"
)

func NewMainHandler(config *Config, next http.Handler) (http.Handler, error) {
	a, err := NewApp(config)
	if err != nil {
		return nil, err
	}
	return a.NewAuthHandler(next), nil
}

type App struct {
	Config          *Config
	TemplateManager *templateManager
	SessionManager  *sessionManager
	Providers       []*Provider
}

func NewApp(c *Config) (*App, error) {
	err := c.PrepareAndValidate()
	if err != nil {
		return nil, err
	}

	tm, err := NewTemplateManager(c.TemplateDir, c.TemplateDevMode)
	if err != nil {
		return nil, err
	}

	// TODO: not nice
	providers, err := NewProviderSet(context.TODO(), c.Providers, func(pc *ProviderConfig) {
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

	sm, err := NewSessionManager(c.HashKey, c.EncryptKey, providerSet)
	if err != nil {
		return nil, err
	}

	return &App{
		Config:          c,
		TemplateManager: tm,
		SessionManager:  sm,
		Providers:       providers,
	}, nil
}

func (a *App) NewAuthHandler(next http.Handler) http.Handler {
	mux := http.NewServeMux()

	// login
	mux.Handle(a.Config.LoginPath, LoginHandler(
		a.SessionManager,
		ProviderSelectionHandler(
			a.Config.AppName,
			a.Providers,
			a.TemplateManager,
		),
	))

	// callback
	mux.Handle(a.Config.CallbackPath, CallbackHandler(
		a.SessionManager,
		defaultPostCallbackHandler(a.SessionManager, defaultErrorHandler, a.Config.ExternalSessionInfoPath),
		defaultErrorHandler,
	))

	// info
	mux.Handle(a.Config.SessionInfoPath, NewDefaultSessionInfoHandler(
		a.SessionManager,
		a.TemplateManager,
		PathSet{
			Login:   a.Config.ExternalLoginPath,
			Logout:  a.Config.ExternalLogoutPath,
			Refresh: a.Config.ExternalRefreshPath,
		},
	))

	mux.Handle(a.Config.RefreshPath, RefreshHandler(a.SessionManager, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, a.Config.ExternalSessionInfoPath, http.StatusSeeOther)
	}), defaultErrorHandler))

	// logout
	mux.Handle(a.Config.LogoutPath, LogoutHandler(a.SessionManager, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, a.Config.ExternalSessionInfoPath, http.StatusSeeOther)
	})))

	// root
	mux.Handle("/", AuthenticateHandler(a.SessionManager, a.Config.ExternalLoginPath, next))

	// TODO: remove
	mux.Handle("/debug", DebugHandler(a.SessionManager, a.Providers))
	return mux
}
